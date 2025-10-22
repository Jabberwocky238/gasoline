#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UDP连接测试脚本 - 向10.0.0.5发送UDP数据包
使用方法: python udp_client.py [目标IP] [端口] [源IP]
"""

import socket
import sys
import time

def test_udp_connection(host="10.0.0.5", port=53, source_ip=None):
    """测试UDP连接"""
    try:
        # 创建UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        
        # 如果指定了源IP，绑定到该IP
        if source_ip:
            sock.bind((source_ip, 0))
            print(f"绑定到源IP: {source_ip}")
        
        print(f"正在向 {host}:{port} 发送UDP数据包...")
        
        # 发送测试数据
        message = f"Hello from UDP client to {host}:{port}"
        sock.sendto(message.encode('utf-8'), (host, port))
        time.sleep(1)
        message = f"Hello from UDP client to {host}:{port}"
        sock.sendto(message.encode('utf-8'), (host, port))
        time.sleep(1)
        message = f"Hello from UDP client to {host}:{port}"
        sock.sendto(message.encode('utf-8'), (host, port))
        print(f"✓ 成功发送数据到 {host}:{port}")
        
        # 尝试接收响应
        try:
            data, addr = sock.recvfrom(1024)
            print(f"收到来自 {addr} 的响应 ({len(data)} 字节):")
            print("-" * 40)
            print(data.decode('utf-8', errors='ignore'))
            print("-" * 40)
        except socket.timeout:
            print("未收到响应 (UDP是无连接的)")
        
        sock.close()
        return True
        
    except socket.timeout:
        print(f"✗ 操作超时: {host}:{port}")
        return False
    except socket.error as e:
        print(f"✗ 操作失败: {e}")
        return False
    except Exception as e:
        print(f"✗ 错误: {e}")
        return False

if __name__ == "__main__":
    # 解析命令行参数
    host = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.5"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 53
    source_ip = sys.argv[3] if len(sys.argv) > 3 else None
    
    print("=" * 50)
    print("UDP连接测试")
    print("=" * 50)
    print(f"目标: {host}:{port}")
    if source_ip:
        print(f"源IP: {source_ip}")
    print("=" * 50)
    
    success = test_udp_connection(host, port, source_ip)
    sys.exit(0 if success else 1)
