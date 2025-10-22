#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TCP连接测试脚本 - 向10.0.0.5发起TCP连接
使用方法: python tcp_client.py [目标IP] [端口] [源IP]
"""

import socket
import sys
import time

def test_tcp_connection(host="10.0.0.1", port=80, source_ip=None):
    """测试TCP连接"""
    try:
        # 创建socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        # 如果指定了源IP，绑定到该IP
        if source_ip:
            sock.bind((source_ip, 0))
            print(f"绑定到源IP: {source_ip}")
        
        print(f"正在连接到 {host}:{port}...")
        
        # 建立连接
        sock.connect((host, port))
        print(f"✓ 成功连接到 {host}:{port}")
        
        # 发送HTTP请求
        request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n"
        sock.send(request.encode('utf-8'))
        time.sleep(1)
        request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n"
        sock.send(request.encode('utf-8'))
        time.sleep(1)
        request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n"
        sock.send(request.encode('utf-8'))
        
        # 接收响应
        response = sock.recv(4096)
        print(f"收到响应 ({len(response)} 字节):")
        print("-" * 40)
        print(response.decode('utf-8', errors='ignore'))
        print("-" * 40)
        
        sock.close()
        return True
        
    except socket.timeout:
        print(f"✗ 连接超时: {host}:{port}")
        return False
    except socket.error as e:
        print(f"✗ 连接失败: {e}")
        return False
    except Exception as e:
        print(f"✗ 错误: {e}")
        return False

if __name__ == "__main__":
    # 解析命令行参数
    host = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.8"
    host = sys.argv[1] if len(sys.argv) > 1 else "170.106.143.75"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 47789
    source_ip = sys.argv[3] if len(sys.argv) > 3 else None
    
    print("=" * 50)
    print("TCP连接测试")
    print("=" * 50)
    print(f"目标: {host}:{port}")
    if source_ip:
        print(f"源IP: {source_ip}")
    print("=" * 50)
    
    success = test_tcp_connection(host, port, source_ip)
    sys.exit(0 if success else 1)
