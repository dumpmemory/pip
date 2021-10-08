//
//  pip_tcp.cpp
//
//  Created by Plumk on 2021/3/11.
//

#include "pip_tcp.hpp"
#include "pip_opt.hpp"
#include "pip_checksum.hpp"
#include "pip_netif.hpp"
#include <map>
#include <unistd.h>
#include <arpa/inet.h>
#include <mutex>


/// 判断seq2 > seq1
int before_seq(pip_uint32 seq1, pip_uint32 seq2) {
    return (pip_int32)(seq1 - seq2) <= 0;
}

pip_uint32 increase_seq(pip_uint32 seq, pip_uint8 flags, pip_uint32 datalen) {
    if (flags & TH_SYN || flags & TH_FIN || flags & TH_PUSH || datalen > 0) {
        return seq + (datalen > 0 ? datalen : 1);
    }
    return seq;
}

/// FIN连接状态最近一次检查时间
static time_t fin_recent_check_time = 0;

/// 当前连接
static std::map<pip_uint32, pip_tcp *> tcp_connections;

pip_tcp::pip_tcp() {
    this->status = pip_tcp_status_closed;
    this->seq = pip_netif::shared()->get_isn();
    
    this->receive_wind = PIP_TCP_WIND;
    this->receive_mss = PIP_TCP_MSS;
    
    this->_last_ack = 0;
    this->_is_wait_push_ack = false;
    
    this->connected_callback = NULL;
    this->closed_callback = NULL;
    this->received_callback = NULL;
    this->written_callback = NULL;
    
    this->dest_ip_str = NULL;
    this->src_ip_str = NULL;
    
    this->arg = NULL;
    
    this->_packet_queue = new pip_queue<pip_tcp_packet *>();
    this->_fin_time = 0;
}

pip_tcp::~pip_tcp() {
    
}

void pip_tcp::release() {
    if (this->status == pip_tcp_status_released) {
        return;
    }

    tcp_connections.erase(this->_iden);
    this->status = pip_tcp_status_released;
    this->_fin_time = 0;
    
    if (this->_packet_queue != NULL) {
        
        auto queue = this->_packet_queue;
        this->_packet_queue = NULL;
        
        while (!queue->empty()) {
            delete queue->front();
            queue->pop();
        }
        delete queue;
    }
    
    if (this->connected_callback != NULL) {
        this->connected_callback = NULL;
    }
    
    if (this->received_callback != NULL) {
        this->received_callback = NULL;
    }
    
    if (this->written_callback != NULL) {
        this->written_callback = NULL;
    }
    
    if (this->src_ip_str != NULL) {
        free(this->src_ip_str);
        this->src_ip_str = NULL;
    }
    
    if (this->dest_ip_str != NULL) {
        free(this->dest_ip_str);
        this->dest_ip_str = NULL;
    }
    
    void * arg = this->arg;
    this->arg = NULL;
    
    if (this->closed_callback != NULL) {
        this->closed_callback(this, arg);
        this->closed_callback = NULL;
    }
    
    
}

void pip_tcp::timer_tick() {
    
    if (fin_recent_check_time <= 0) {
        fin_recent_check_time = time(NULL);
        return;
    }
    
    time_t cur_time = time(NULL);
    if (cur_time - fin_recent_check_time >= 20) {
        fin_recent_check_time = cur_time;
        
        std::map<pip_uint32, pip_tcp *>::iterator iter;
        for (iter = tcp_connections.begin(); iter != tcp_connections.end();) {
            
            pip_tcp * tcp = NULL;
            if ((iter->second->status == pip_tcp_status_fin_wait_1 || iter->second->status == pip_tcp_status_fin_wait_2) &&
                cur_time - iter->second->_fin_time >= 20) {
                tcp = iter->second;
            }
            
            iter ++;
            if (tcp != NULL) {
                tcp->release();
                delete tcp;
            }
        }
    }
}

// MARK: - -
pip_uint32 pip_tcp::current_connections() {
    return (pip_uint32)tcp_connections.size();
}

void pip_tcp::connected(const void *bytes) {
    if (this->status != pip_tcp_status_wait_establishing) {
        return;
    }
    
    if (bytes == NULL) {
        this->handle_syn(NULL, 0);
        return;
    }
    
    struct tcphdr *hdr = (struct tcphdr *)bytes;
    
    // 判断是否有选项 无选项头部为4 * 5 = 20个字节
    if (hdr->th_off > 5) {
        this->handle_syn((pip_uint8 *)hdr + sizeof(struct tcphdr), ((hdr->th_off - 5) * 4));
    } else {
        this->handle_syn(NULL, 0);
    }
}

void pip_tcp::close() {
    
    switch (this->status) {
        case pip_tcp_status_closed: {
            this->release();
            delete this;
            break;
        }
            
        case pip_tcp_status_wait_establishing:
        case pip_tcp_status_establishing: {
            this->reset();
            break;
        }
            
        case pip_tcp_status_established: {
            this->status = pip_tcp_status_fin_wait_1;
            this->_fin_time = time(NULL);

            pip_tcp_packet *packet = new pip_tcp_packet(this, TH_FIN | TH_ACK, NULL, NULL);
            this->_packet_queue->push(packet);
            this->send_packet(packet);
            break;
        }
            
        default:
            break;
    }
}

void pip_tcp::reset() {
    
    switch (this->status) {
        case pip_tcp_status_wait_establishing:
        case pip_tcp_status_establishing:
        case pip_tcp_status_established: {
            pip_tcp_packet *packet = new pip_tcp_packet(this, TH_RST | TH_ACK, NULL, NULL);
            this->send_packet(packet);
            delete packet;
        }
            break;
            
        default:
            break;
    }
    
    if (this->status == pip_tcp_status_released) {
        return;
    }

    this->release();
    delete this;
}

void pip_tcp::write(const void *bytes, pip_uint32 len) {
    if (this->status != pip_tcp_status_established || !this->can_write()) {
        return;
    }
    
    pip_uint32 offset = 0;
    while (offset < len) {
        
        pip_uint16 write_len = this->send_mss;
        if (offset + write_len > len) {
            write_len = len - offset;
        }
        
        pip_buf * payload_buf = new pip_buf((pip_uint8 *)bytes + offset, write_len, 0);
        
        pip_tcp_packet * packet;
        if (offset + write_len >= len) {
            packet = new pip_tcp_packet(this, TH_PUSH | TH_ACK, NULL, payload_buf);
            this->_is_wait_push_ack = true;
            
        } else {
            packet = new pip_tcp_packet(this, TH_ACK, NULL, payload_buf);
        }
        this->_packet_queue->push(packet);
        this->send_packet(packet);
        
        offset += write_len;
    }
}

void pip_tcp::received(pip_uint16 len) {
    if (this->status != pip_tcp_status_established) {
        return;
    }
    
    this->receive_wind = PIP_MIN(this->receive_wind + len, PIP_TCP_WIND);
    if (this->receive_wind - len <= 0 && this->ack == this->_last_ack) {
        // 无等待发送的包 直接发送ack 更新窗口
        this->send_ack();
    }
}

void pip_tcp::debug_status() {
    printf("source %s port %d\n", this->src_ip_str, this->src_port);
    printf("destination %s port %d\n", this->dest_ip_str, this->dest_port);
    printf("wind %hu \n", this->receive_wind);
    printf("wait ack pkts %d \n", this->_packet_queue->size());
    
    printf("current tcp connections %lu \n", tcp_connections.size());
    printf("\n\n");
}

pip_uint32 pip_tcp::get_iden() {
    return this->_iden;
}

bool pip_tcp::can_write() {
    return this->_is_wait_push_ack == false;
}

// MARK: - Send
void pip_tcp::send_packet(pip_tcp_packet *packet) {
    tcphdr * hdr = packet->get_hdr();
    pip_uint16 datalen = packet->payload_len;
    pip_netif::shared()->output(packet->head_buf, IPPROTO_TCP, this->dest_ip, this->src_ip);
    
    this->_last_ack = ntohl(hdr->th_ack);
    this->seq = increase_seq(this->seq, hdr->th_flags, datalen);
    
#if PIP_DEBUG
    printf("[send]: \n");
    printf("destination %s port %d\n", inet_ntoa({ htonl(this->src_ip) }), this->src_port);
    printf("flags: ");
    if (hdr->th_flags & TH_FIN) {
        printf("FIN ");
    }
    
    if (hdr->th_flags & TH_SYN) {
        printf("SYN ");
    }
    
    if (hdr->th_flags & TH_RST) {
        printf("RST ");
    }
    
    if (hdr->th_flags & TH_PUSH) {
        printf("PUSH ");
    }
    
    if (hdr->th_flags & TH_ACK) {
        printf("ACK ");
    }
    
    if (hdr->th_flags & TH_URG) {
        printf("URG ");
    }
    
    if (hdr->th_flags & TH_ECE) {
        printf("ECE ");
    }
    
    if (hdr->th_flags & TH_CWR) {
        printf("CWR ");
    }
    printf("\ndatalen: %d\n", datalen);
    printf("seq: %d\n", this->seq);
    printf("\n\n");
#endif
}

void pip_tcp::send_ack() {
    pip_tcp_packet * packet = new pip_tcp_packet(this, TH_ACK, NULL, NULL);
    this->send_packet(packet);
    delete packet;
}

// MARK: - Handle
void pip_tcp::handle_ack(pip_uint32 ack) {
    
#if PIP_DEBUG
    printf("[handle_ack]:\n");
#endif
    
    
    bool has_syn = false;
    bool has_fin = false;
    pip_uint32 written_length = 0;
    
    while (this->_packet_queue->size() > 0) {
        pip_tcp_packet * pkt = this->_packet_queue->front();
        struct tcphdr * hdr = pkt->get_hdr();
        if (hdr && !before_seq(ntohl(hdr->th_seq), ack)) {
#if PIP_DEBUG
            printf("break seq: %d ack: %d\n", ntohl(hdr->th_seq), ack);
#endif
            break;
        }
        this->_packet_queue->pop();
        
        if (hdr->th_flags & TH_SYN) {
            this->status = pip_tcp_status_established;
            has_syn = true;
        }
        
        if (pkt->payload_len > 0) {
            if (hdr->th_flags & TH_PUSH) {
                this->_is_wait_push_ack = false;
            }
            
            written_length += pkt->payload_len;
        }
        
        if (hdr->th_flags & TH_FIN) {
            has_fin = true;
        }
        
        
        delete pkt;
    }
    
#if PIP_DEBUG
    printf("remain packet num: %d\n", this->_packet_queue->size());
    printf("\n\n");
#endif
    
    if (has_syn) {
        if (this->connected_callback) {
            this->connected_callback(this);
        }
    }
    
    if (written_length > 0) {
        if (this->written_callback) {
            this->written_callback(this, written_length);
        }
    }
    
    if (has_fin) {
        if (this->status == pip_tcp_status_fin_wait_1) {
            /// 主动关闭 改变状态
            this->status = pip_tcp_status_fin_wait_2;
            this->_fin_time = time(NULL);
            
        } else if (this->status == pip_tcp_status_close_wait) {
            /// 被动关闭 清理资源
            this->release();
            delete this;
        }
    }
}

void pip_tcp::handle_syn(void * options, pip_uint16 optionlen) {
    this->status = pip_tcp_status_establishing;
    
#if PIP_DEBUG
    printf("parse option:\n");
    printf("option len: %d\n", optionlen);
    
#endif
    if (optionlen > 0) {
        pip_uint8 * bytes = (pip_uint8 *)options;
        pip_uint16 offset = 0;
        pip_uint16 pre_offset = -1;
        /// pre_offset != offset 防止碰到无法解析的出现死循环
        while (offset < optionlen && pre_offset != offset) {
            
            pre_offset = offset;
            pip_uint8 kind = bytes[offset];
            
            if (kind == 0) {
                break;
            }
            
            switch (kind) {
                case 1: {
                    offset += 1;
                    break;
                }
                    
                case 2: {
                    // mss
                    pip_uint8 len = bytes[offset + 1];
                    pip_uint16 mss = 0;
                    memcpy(&mss, bytes + offset + 2, len - offset - 2);
                    this->send_mss = ntohs(mss);
#if PIP_DEBUG
                    printf("mss: %d", ntohs(mss));
#endif
                    
                    offset += len;
                    break;
                }
                    
                default: {
                    pip_uint8 len = bytes[offset + 1];
                    offset += len;
                    break;
                }
            }
        }
    }
    
#if PIP_DEBUG
    printf("\n\n");
#endif
    pip_buf * option_buf = new pip_buf(4);
    pip_uint8 * optionBuffer = (pip_uint8 *)option_buf->payload;
    memset(optionBuffer, 0, 4);
    if (true) {
        // mss
        pip_uint8 kind = 2;
        pip_uint8 len = 4;
        pip_uint16 value = htons(this->receive_mss);
        
        memcpy(optionBuffer, &kind, 1);
        memcpy(optionBuffer + 1, &len, 1);
        memcpy(optionBuffer + 2, &value, 2);
    }
    
    pip_tcp_packet * packet = new pip_tcp_packet(this, TH_SYN | TH_ACK, option_buf, NULL);
    this->_packet_queue->push(packet);
    this->send_packet(packet);
}

void pip_tcp::handle_fin() {
    if (this->status == pip_tcp_status_fin_wait_2) {
        /// 主动关闭 回复ack 清理资源
        
        pip_tcp_packet * packet = new pip_tcp_packet(this, TH_ACK, NULL, NULL);
        this->send_packet(packet);
        this->release();
        delete this;
        delete packet;
        
    } else {
        /// 被动关闭回复
        if (this->status != pip_tcp_status_established) {
            return;
        }
        
        this->status = pip_tcp_status_close_wait;
        
        pip_tcp_packet * packet = new pip_tcp_packet(this, TH_ACK, NULL, NULL);
        this->send_packet(packet);
        delete packet;
        
        packet = new pip_tcp_packet(this, TH_FIN | TH_ACK, NULL, NULL);
        this->_packet_queue->push(packet);
        this->send_packet(packet);
    }
}

void pip_tcp::handle_push(void *data, pip_uint16 datalen) {
    this->handle_receive(data, datalen);
    
}

void pip_tcp::handle_receive(void *data, pip_uint16 datalen) {

    
#if PIP_DEBUG
    printf("[handle_receive]:\n");
    printf("receive data: %d\n", datalen);
#endif
    this->receive_wind -= datalen;
    if (this->received_callback) {
        this->received_callback(this, data, datalen);
    }
    
    if (datalen > 0) {
        this->send_ack();
    }
}

// MARK: - Input
void pip_tcp::input(const void * bytes, struct ip *ip) {
    struct tcphdr *hdr = (struct tcphdr *)bytes;
    
    pip_uint16 datalen = htons(ip->ip_len) - (ip->ip_hl * 4 + hdr->th_off * 4);
    pip_uint16 dport = ntohs(hdr->th_dport);
    if (!(dport >= 1 && dport <= 65535)) {
        return;
    }
    
    pip_uint32 iden = ip->ip_src.s_addr + ip->ip_dst.s_addr + dport + ntohs(hdr->th_sport);
    pip_tcp * tcp = NULL;
    

    if (tcp_connections.find(iden) != tcp_connections.end()) {
        tcp = tcp_connections[iden];
    } else if (hdr->th_flags & TH_SYN && tcp_connections.size() < PIP_TCP_MAX_CONNS) {
        tcp = new pip_tcp;
        tcp->_iden = iden;
        
        tcp->src_ip = ntohl(ip->ip_src.s_addr);
        tcp->dest_ip = ntohl(ip->ip_dst.s_addr);
        
        tcp->src_ip_str = (char *)calloc(15, sizeof(char));
        strcpy(tcp->src_ip_str, inet_ntoa(ip->ip_src));
        
        tcp->dest_ip_str = (char *)calloc(15, sizeof(char));
        strcpy(tcp->dest_ip_str, inet_ntoa(ip->ip_dst));
        
        tcp->src_port = ntohs(hdr->th_sport);
        tcp->dest_port = dport;
        
        tcp_connections[iden] = tcp;
    }
    
    
    
    if (tcp == NULL) {
#if PIP_DEBUG
        printf("未获取到TCP连接\n");
#endif
        return;
    }
    
#if PIP_DEBUG
    printf("[input]: \n");
    printf("source %s port %d\n", tcp->src_ip_str, ntohs(hdr->th_sport));
    printf("flags: ");
    if (hdr->th_flags & TH_FIN) {
        printf("FIN ");
    }
    
    if (hdr->th_flags & TH_SYN) {
        printf("SYN ");
    }
    
    if (hdr->th_flags & TH_RST) {
        printf("RST ");
    }
    
    if (hdr->th_flags & TH_PUSH) {
        printf("PUSH ");
    }
    
    if (hdr->th_flags & TH_ACK) {
        printf("ACK ");
    }
    
    if (hdr->th_flags & TH_URG) {
        printf("URG ");
    }
    
    if (hdr->th_flags & TH_ECE) {
        printf("ECE ");
    }
    
    if (hdr->th_flags & TH_CWR) {
        printf("CWR ");
    }
    printf("\ndata length: %d\n", datalen);
    printf("wind: %d\n", ntohs(hdr->th_win));
    printf("ack: %d\n", ntohl(hdr->th_ack));
    printf("seq: %d\n", ntohl(hdr->th_seq));
    printf("\n\n");
    
#endif
    
    if (hdr->th_flags == TH_ACK && ntohl(hdr->th_seq) == tcp->_last_ack - 1) {
        // keep-alive 回复
        tcp->send_ack();
        return;
    }
    
    tcp->ack = increase_seq(ntohl(hdr->th_seq), hdr->th_flags, datalen);
    tcp->send_wind = ntohs(hdr->th_win);
    
    
    if (hdr->th_flags & TH_RST) {
        tcp->release();
        delete tcp;
        return;
    }
    
    if (hdr->th_flags & TH_ACK) {
        tcp->handle_ack(ntohl(hdr->th_ack));
    }
    
    if (hdr->th_flags & TH_SYN) {
        tcp->status = pip_tcp_status_wait_establishing;
        if (pip_netif::shared()->new_tcp_connect_callback) {
            pip_netif::shared()->new_tcp_connect_callback(pip_netif::shared(), tcp, bytes, hdr->th_off * 4);
        }
    }
    
    if (hdr->th_flags & TH_FIN) {
        tcp->handle_fin();
    }
    
    if (hdr->th_flags & TH_PUSH) {
        tcp->handle_push((pip_uint8 *)bytes + hdr->th_off * 4, datalen);
    } else if (datalen > 0) {
        tcp->handle_receive((pip_uint8 *)bytes + hdr->th_off * 4, datalen);
    }
    
}


// MARK: - pip_tcp_packet
pip_tcp_packet::
pip_tcp_packet(pip_tcp *tcp, pip_uint8 flags, pip_buf * option_buf, pip_buf * payload_buf) {
    
    
    pip_uint8 * buffer = (pip_uint8 *)calloc(1, sizeof(struct tcphdr));
    this->buffer = buffer;
    
    // -- 赋值BUF
    pip_buf * head_buf = new pip_buf(buffer, sizeof(struct tcphdr), 0);
    if (option_buf != NULL) {
        option_buf->set_next(payload_buf);
        head_buf->set_next(option_buf);
    } else if (payload_buf != NULL) {
        head_buf->set_next(payload_buf);
    }
    
    
    this->head_buf = head_buf;


    if (payload_buf) {
        this->payload_len = payload_buf->total_len;
    } else {
        this->payload_len = 0;
    }
    
    // - 填充头部
    int offset = 0;
    if (true) {
        // 源端口
        int len = sizeof(pip_uint16);
        pip_uint16 port = htons(tcp->dest_port);
        memcpy(buffer + offset, &port, len);
        
        offset += len;
    }
    
    if (true) {
        // 目标端口
        int len = sizeof(pip_uint16);
        pip_uint16 port = htons(tcp->src_port);
        memcpy(buffer + offset, &port, len);
        
        offset += len;
    }
    
    if (true) {
        // 序号
        int len = sizeof(pip_uint32);
        pip_uint32 seq = htonl(tcp->seq);
        memcpy(buffer + offset, &seq, len);
        
        offset += len;
    }
    
    if (true) {
        // 确认号
        int len = sizeof(pip_uint32);
        pip_uint32 ack = htonl(tcp->ack);
        memcpy(buffer + offset, &ack, len);
        
        offset += len;
    }
    
    
    if (true) {
        // 头部长度 保留 标识
        int len = sizeof(pip_uint16);
        pip_uint16 h_flags = 0;
        
        pip_uint16 headlen = head_buf->payload_len;
        if (option_buf != NULL) {
            headlen += option_buf->payload_len;
        }
        
        h_flags = (headlen / 4) << 12;
        h_flags = h_flags | flags;
        h_flags = htons(h_flags);
        memcpy(buffer + offset, &h_flags, len);
        
        offset += len;
    }
    
    
    if (true) {
        // 窗口大小
        int len = sizeof(pip_uint16);
        pip_uint16 wind = htons(tcp->receive_wind);
        memcpy(buffer + offset, &wind, len);
        
        offset += len;
    }
    
    // 校验和偏移
    int checksum_offset = offset;
    offset += sizeof(pip_uint16);
    
    // 紧急指针
    offset += sizeof(pip_uint16);
    
    
    if (true) {
        // 计算校验和
        pip_uint16 checksum = pip_inet_checksum_buf(head_buf, IPPROTO_TCP, tcp->dest_ip, tcp->src_ip);
        checksum = htons(checksum);
        memcpy(buffer + checksum_offset, &checksum, sizeof(pip_uint16));
    }
    
    
}

pip_tcp_packet::
~pip_tcp_packet() {
    if (this->buffer) {
        free(this->buffer);
        this->buffer = NULL;
    }
}


struct tcphdr *
pip_tcp_packet::get_hdr() {
    if (this->buffer) {
        return (struct tcphdr *)this->buffer;
    }
    return NULL;
}
