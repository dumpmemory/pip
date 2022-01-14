//
//  pip_udp.hpp
//  Panther-Remote
//
//  Created by laihua-tiezhu on 2022/1/13.
//

#ifndef pip_udp_hpp
#define pip_udp_hpp

#include "pip_type.hpp"


class pip_udp {
    
public:
    static void input(const void *bytes, struct ip *ip);
    static void output(const void *buffer, pip_uint16 buffer_len, const char * src_ip, pip_uint16 src_port, const char * dest_ip, pip_uint16 dest_port);
};


#endif /* pip_udp_hpp */
