//
//  pip_netif.hpp
//
//  Created by Plumk on 2021/3/11.
//

#ifndef pip_netif_hpp
#define pip_netif_hpp

#include "pip_type.hpp"
#include "pip_buf.hpp"

class pip_netif;
class pip_tcp;

typedef void (*pip_netif_output_callback)(pip_netif * netif, pip_buf * buf);
typedef void (*pip_netif_output_tcp_callback)(pip_netif * netif, pip_tcp * tcp);
typedef void (*pip_netif_output_udp_callback)(pip_netif * netif, void * buffer, pip_uint16 buffer_len, const char * src_ip, pip_uint16 src_port, const char * dest_ip, pip_uint16 dest_port);

class pip_netif {
    pip_netif();
    ~pip_netif();
    
public:
    static pip_netif * shared();
    
    /// 输入IP包
    /// @param buffer _
    void input(const void * buffer);
    
    /// 内部使用 外部通过 pip_netif_output_callback 获取输出的IP包
    /// @param buf _
    /// @param proto _
    /// @param src _
    /// @param dest _
    void output(pip_buf * buf, pip_uint8 proto, pip_uint32 src, pip_uint32 dest);
    
    
    /// 需要至少250ms调用一次该函数
    void timer_tick();
    
    pip_uint32 get_isn();
    
public:
    pip_netif_output_callback output_callback;
    pip_netif_output_tcp_callback output_tcp_callback;
    pip_netif_output_udp_callback output_udp_callback;
    
public:
    void udp_output(const void *buffer, pip_uint16 buffer_len, const char * src_ip, pip_uint16 src_port, const char * dest_ip, pip_uint16 dest_port);
    
private:
    void udp_input(const void * buffer, struct ip *ip);
    
private:
    pip_uint16 _identifer = 0;
    pip_uint32 _isn = 0;
};


#endif /* pip_netif_hpp */
