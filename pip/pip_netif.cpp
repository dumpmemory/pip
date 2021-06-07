//
//  pip_netif.cpp
//
//  Created by Plumk on 2021/3/11.
//

#include "pip_netif.hpp"
#include "pip_tcp.hpp"
#include "pip_checksum.hpp"
#include <iostream>
#include <mutex>
#include "pip_opt.hpp"

using namespace std;

mutex _lock;
static pip_netif * netif = NULL;

pip_netif::pip_netif() {
    this->_identifer = 0;
    this->_isn = 1;
    
    this->output_callback = NULL;
    this->output_tcp_callback = NULL;
    this->output_udp_callback = NULL;
    
}

pip_netif * pip_netif::shared() {
    
    if (netif == NULL) {
        _lock.lock();
        if (netif == NULL) {
            netif = new pip_netif();
        }
        _lock.unlock();
    }
    
    return netif;
}

void pip_netif::input(const void *buffer) {
    struct ip *hdr = (struct ip*)buffer;
    
    /// - 检测是否有options 不支持options
    if (hdr->ip_hl > 5) {
        return;
    }
    
    /// - 检查是否是IP4
    if (hdr->ip_v != 4) {
        return;
    }
    
    switch (hdr->ip_p) {
            
        case IPPROTO_UDP: {
            this->udp_input(((pip_uint8 *)buffer)+20, hdr);
            break;
        }
            
        case IPPROTO_TCP: {
            pip_tcp::input(((pip_uint8 *)buffer)+20, hdr);
            break;
        }
            
        default:
            break;
    }
}


void pip_netif::output(pip_buf *buf, pip_uint8 proto, pip_uint32 src, pip_uint32 dest) {
    
    pip_buf * ip_head_buf = new pip_buf(sizeof(struct ip));
    ip_head_buf->set_next(buf);
    
    struct ip *hdr = (struct ip *)ip_head_buf->payload;
    hdr->ip_v = 4;
    hdr->ip_hl = 5;
    hdr->ip_tos = 0;
    hdr->ip_len = htons(ip_head_buf->total_len);
    hdr->ip_id = htons(this->_identifer++);
    hdr->ip_off = htons(IP_DF);
    hdr->ip_ttl = 64;
    hdr->ip_p = proto;
    hdr->ip_sum = 0;
    hdr->ip_src.s_addr = htonl(src);
    hdr->ip_dst.s_addr = htonl(dest);
    hdr->ip_sum = htons(pip_ip_checksum(hdr, sizeof(struct ip)));
    
    if (this->output_callback) {
        this->output_callback(this, ip_head_buf);
    }
    
    delete ip_head_buf;
}


void pip_netif::timer_tick() {
    if (this->_isn >= PIP_UINT32_MAX) {
        this->_isn = 0;
    } else {
        this->_isn += 1;
    }
    
    pip_tcp::timer_tick();
}

pip_uint32 pip_netif::get_isn() {
    return this->_isn;
}


void pip_netif::udp_input(const void * buffer, struct ip *ip) {
    char * src_ip = (char *)calloc(15, sizeof(char));
    char * dest_ip = (char *)calloc(15, sizeof(char));
    strcpy(src_ip, inet_ntoa(ip->ip_src));
    strcpy(dest_ip, inet_ntoa(ip->ip_dst));
    
    struct udphdr *hdr = (struct udphdr *)buffer;
    
    pip_uint16 src_port = ntohs(hdr->uh_sport);
    pip_uint16 dest_port = ntohs(hdr->uh_dport);
    
    pip_uint16 datalen = ntohs(hdr->uh_ulen) - sizeof(struct udphdr);
    void * data = (pip_uint8 *)buffer + sizeof(struct udphdr);
    if (this->output_udp_callback) {
        this->output_udp_callback(this, data, datalen, src_ip, src_port, dest_ip, dest_port);
    }
    
#if PIP_DEBUG
    printf("udp received:\n");
    printf("source %s port %d\n", inet_ntoa(ip->ip_src), src_port);
    printf("destination %s port %d\n", inet_ntoa(ip->ip_dst), dest_port);
    printf("datalen %d\n", datalen);
    printf("\n\n");
#endif
    
    free(src_ip);
    free(dest_ip);
    
}


void pip_netif::udp_output(const void *buffer, pip_uint16 buffer_len, const char * src_ip, pip_uint16 src_port, const char * dest_ip, pip_uint16 dest_port) {
    
    pip_buf * payload_buf = new pip_buf((void *)buffer, buffer_len, 0);
    pip_buf * udp_head_buf = new pip_buf(sizeof(struct udphdr));
    udp_head_buf->set_next(payload_buf);
    
    pip_uint16 total_len = sizeof(struct udphdr) + buffer_len;
    in_addr_t src_addr = inet_addr(src_ip);
    in_addr_t dest_addr = inet_addr(dest_ip);

    struct udphdr *hdr = (struct udphdr*)udp_head_buf->payload;
    hdr->uh_dport = htons(dest_port);
    hdr->uh_sport = htons(src_port);
    hdr->uh_ulen = htons(total_len);
    hdr->uh_sum = 0;
    

    hdr->uh_sum = pip_inet_checksum_buf(udp_head_buf, IPPROTO_UDP, ntohl(src_addr), ntohl(dest_addr));
    hdr->uh_sum = htons(hdr->uh_sum);

    this->output(udp_head_buf, IPPROTO_UDP, ntohl(src_addr), ntohl(dest_addr));
}
