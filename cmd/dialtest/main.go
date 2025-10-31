package main

import (
	"flag"
	"fmt"
	"net"
	"time"

	"wwww/config"
	"wwww/tun"
)

func main() {
	var host = flag.String("h", "69.164.244.81", "目标主机")
	var port = flag.String("p", "47789", "目标端口")
	var timeout = flag.Int("t", 3, "连接超时时间(秒)")
	var retries = flag.Int("r", 3, "重试次数")
	var withtun = flag.Bool("w", false, "是否使用TUN设备")
	flag.Parse()

	// 启动TUN设备模拟实际网络环境
	if *withtun {
		cfg, err := config.ParseConfig("tests/client.toml")
		if err != nil {
			fmt.Println("Error parsing config:", err)
			return
		}

		tun, err := tun.NewTun("tun0000", cfg)
		if err != nil {
			fmt.Println("Error creating tun:", err)
			return
		}

		err = tun.Start()
		if err != nil {
			fmt.Println("Error starting tun:", err)
			return
		}
	}

	target := *host + ":" + *port
	fmt.Printf("测试TCP连接到: %s\n", target)
	fmt.Printf("超时时间: %d秒, 重试次数: %d\n\n", *timeout, *retries)

	for i := 0; i < *retries; i++ {
		fmt.Printf("尝试连接 %d/%d...\n", i+1, *retries)

		start := time.Now()
		conn, err := net.DialTimeout("tcp", target, time.Duration(*timeout)*time.Second)
		duration := time.Since(start)

		if err != nil {
			fmt.Printf("连接失败: %v (耗时: %v)\n", err, duration)
			if i < *retries-1 {
				fmt.Printf("等待2秒后重试...\n\n")
				time.Sleep(2 * time.Second)
			}
			continue
		}

		fmt.Printf("连接成功! (耗时: %v)\n", duration)
		fmt.Printf("本地地址: %s\n", conn.LocalAddr())
		fmt.Printf("远程地址: %s\n", conn.RemoteAddr())

		// 发送测试数据
		testData := []byte("Hello Server!")
		_, err = conn.Write(testData)
		if err != nil {
			fmt.Printf("发送数据失败: %v\n", err)
		} else {
			fmt.Printf("发送测试数据: %s\n", string(testData))
		}

		// 尝试读取响应
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Printf("读取响应失败: %v\n", err)
		} else {
			fmt.Printf("收到响应: %s\n", string(buffer[:n]))
		}

		conn.Close()
		fmt.Println("连接已关闭")
		return
	}

	fmt.Printf("所有重试都失败了\n")
}
