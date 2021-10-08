//
//  pip_tcp.hpp
//
//  Created by Plumk on 2021/3/11.
//

#ifndef pip_tcp_hpp
#define pip_tcp_hpp

#include "pip_type.hpp"
#include "pip_queue.hpp"
#include "pip_buf.hpp"
class pip_tcp_packet;
class pip_tcp;

/// 建立连接完成回调
typedef void (*pip_tcp_connected_callback) (pip_tcp * tcp);

/// 关闭回调 在这个时候资源已经释放完成
typedef void (*pip_tcp_closed_callback) (pip_tcp * tcp, void *arg);

/// 数据接收回调
typedef void (*pip_tcp_received_callback) (pip_tcp * tcp, const void * buffer, pip_uint32 buffer_len);

/// 数据发送完成回调 writeen_len完成发送的字节
typedef void (*pip_tcp_written_callback) (pip_tcp * tcp, pip_uint16 writeen_len);

class pip_tcp {
    pip_tcp();
    ~pip_tcp();
    
    void release();
public:
    
    static void input(const void * bytes, struct ip *ip);
    static void timer_tick();
    
    /// 获取当前连接数
    static pip_uint32 current_connections();
    
    /// 建立连接
    /// @param bytes 发起端的建立连接时的数据 tcphdr
    void connected(const void * bytes);
    
    /// 关闭连接
    void close();
    
    /// 重置连接
    void reset();
    
    /// 发送数据
    void write(const void *bytes, pip_uint32 len);
    
    /// 接受数据之后调用更新窗口
    /// @param len 接受的数据大小
    void received(pip_uint16 len);
    
    /// 输出当前状态
    void debug_status();
    
    /// 获取连接标识
    pip_uint32 get_iden();
    
    /// 写之前调用该方法判断当前是否能写
    bool can_write();
    
public:
    pip_tcp_connected_callback connected_callback;
    pip_tcp_closed_callback closed_callback;
    pip_tcp_received_callback received_callback;
    pip_tcp_written_callback written_callback;
    
public:
    pip_uint32 src_ip;
    char * src_ip_str;
    
    pip_uint32 dest_ip;
    char * dest_ip_str;
    
    pip_uint16 src_port;
    pip_uint16 dest_port;
    
    pip_tcp_status status;
    
    pip_uint32 seq;
    pip_uint32 ack;
    
    /// 接收mss
    pip_uint16 receive_mss;
    
    /// 发送mss 对方的mss
    pip_uint16 send_mss;
    
    /// 接收窗口大小
    pip_uint16 receive_wind;
    
    /// 发送窗口大小 对方的窗口
    pip_uint16 send_wind;
    
    /// 外部使用-用于区分
    void * arg;
    
private:
    
    /// 发送数据包
    void send_packet(pip_tcp_packet *packet);
    
    /// 发送确认ACK
    void send_ack();
    
    /// 处理建立连接
    void handle_syn(void * options, pip_uint16 optionlen);
    
    /// 处理断开连接
    void handle_fin();
    
    /// 处理ACK确认
    void handle_ack(pip_uint32 ack);
    
    /// 处理数据接收
    void handle_receive(void * data, pip_uint16 datalen);
    
    /// 处理PUSH标识
    void handle_push(void * data, pip_uint16 datalen);
    
private:
    
    /// 需要等待确认的包队列
    pip_queue<pip_tcp_packet *> * _packet_queue;
    
    /// 当前连接标识
    pip_uint32 _iden;
    
    /// 最后一次ack
    pip_uint32 _last_ack;
    
    /// 当前是否等待确认PUSH包
    bool _is_wait_push_ack;

    /// 主动关闭时间 定期检查 防止客户端不响应ACK 导致资源占用
    time_t _fin_time;
};



/// 数据包
class pip_tcp_packet {
    
public:
    ~pip_tcp_packet();
    
    pip_tcp_packet(pip_tcp *tcp, pip_uint8 flags, pip_buf * option_buf, pip_buf * payload_buf);
  
    
    pip_buf * head_buf;
    struct tcphdr * get_hdr();
    int payload_len;
private:
    pip_uint8 * buffer;
};

#endif /* pip_tcp_hpp */
