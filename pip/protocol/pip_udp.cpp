//
//  pip_udp.cpp
//  Panther-Remote
//
//  Created by laihua-tiezhu on 2022/1/13.
//

#include "pip_udp.hpp"
#include "pip_debug.hpp"
#include "pip_netif.hpp"
#include "pip_checksum.hpp"

void pip_udp::input(const void *bytes, struct ip *ip) {
    
    char * src_ip = (char *)calloc(15, sizeof(char));
    char * dest_ip = (char *)calloc(15, sizeof(char));
    strcpy(src_ip, inet_ntoa(ip->ip_src));
    strcpy(dest_ip, inet_ntoa(ip->ip_dst));
    
    struct udphdr *hdr = (struct udphdr *)bytes;
    
    pip_uint16 src_port = ntohs(hdr->uh_sport);
    pip_uint16 dest_port = ntohs(hdr->uh_dport);
    
    pip_uint16 datalen = ntohs(hdr->uh_ulen) - sizeof(struct udphdr);
    void * data = (pip_uint8 *)bytes + sizeof(struct udphdr);
    
    pip_netif * netif = pip_netif::shared();
    if (netif->received_udp_data_callback) {
        netif->received_udp_data_callback(netif, data, datalen, src_ip, src_port, dest_ip, dest_port);
    }
    
#if PIP_DEBUG
    pip_debug_output_udp(hdr, "udp_input");
#endif
    
    free(src_ip);
    free(dest_ip);
}

void pip_udp::output(const void *buffer, pip_uint16 buffer_len, const char * src_ip, pip_uint16 src_port, const char * dest_ip, pip_uint16 dest_port) {
 
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

    pip_netif::shared()->output(udp_head_buf, IPPROTO_UDP, ntohl(src_addr), ntohl(dest_addr));
    
    delete udp_head_buf;
    
}
