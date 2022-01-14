//
//  pip_netif.cpp
//
//  Created by Plumk on 2021/3/11.
//

#include "pip_netif.hpp"
#include "pip_tcp.hpp"
#include "pip_udp.hpp"
#include "pip_icmp.hpp"

#include "pip_checksum.hpp"
#include <iostream>
#include <mutex>
#include "pip_debug.hpp"

using namespace std;

mutex _lock;
static pip_netif * netif = NULL;

pip_netif::pip_netif() {
    this->_identifer = 0;
    this->_isn = 1;
    
    this->output_ip_data_callback = NULL;
    this->new_tcp_connect_callback = NULL;
    this->received_udp_data_callback = NULL;
    
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
    
#if PIP_DEBUG
    pip_debug_output_ip(hdr, "ip_input");
#endif
    
    /// - 检测是否有options 不支持options
    if (hdr->ip_hl > 5) {
        return;
    }
    
    /// - 检查是否是IP4
    if (hdr->ip_v != 4) {
        return;
    }
    
    switch (hdr->ip_p) {
        case IPPROTO_ICMP:
            /// echo
//            if (this->output_ip_data_callback) {
//                pip_buf * ip_head_buf = new pip_buf(((pip_uint8 *)buffer) + 20, ntohs(hdr->ip_len) - 20, 0);
//                this->output(ip_head_buf, IPPROTO_ICMP, ntohl(hdr->ip_dst.s_addr), ntohl(hdr->ip_src.s_addr));
//                delete ip_head_buf;
//            }
            pip_icmp::input(((pip_uint8 *)buffer)+20, hdr);
            break;
            
        case IPPROTO_UDP: {
            pip_udp::input(((pip_uint8 *)buffer)+20, hdr);
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
    
    if (this->output_ip_data_callback) {
        this->output_ip_data_callback(this, ip_head_buf);
    }
    
#if PIP_DEBUG
    pip_debug_output_ip(hdr, "ip_output");
#endif
    
    ip_head_buf->set_next(NULL);
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
