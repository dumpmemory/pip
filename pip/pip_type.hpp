//
//  pip_type.h
//
//  Created by Plumk on 2021/3/11.
//

#ifndef pip_type_h
#define pip_type_h

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


typedef u_int8_t pip_uint8;
typedef u_int16_t pip_uint16;
typedef u_int32_t pip_uint32;

typedef int32_t pip_int32;

#define PIP_UINT32_MAX 4294967295

#define PIP_MAX(A, B) (A > B ? A : B)
#define PIP_MIN(A, B) (A < B ? A : B)

typedef enum : pip_uint8 {
    pip_tcp_status_closed,
    pip_tcp_status_establishing,
    pip_tcp_status_established,
    pip_tcp_status_fin_wait_1,
    pip_tcp_status_fin_wait_2,
    /* ignore pip_tcp_status_time_wait, */
    pip_tcp_status_close_wait,
    
    /* connection released */
    pip_tcp_status_released,
    
} pip_tcp_status;

#endif /* pip_type_h */
