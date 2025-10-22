package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"

	"wwww/config"
	"wwww/device"
	"wwww/tun"
)

func main() {
	// 命令行参数
	var configPath = flag.String("f", "", "配置文件路径")
	var tunName = flag.String("n", "tun0", "TUN设备名称")
	flag.Parse()

	// 如果没有指定配置文件，尝试默认文件
	if *configPath == "" {
		*configPath = findDefaultConfig()
		if *configPath == "" {
			fmt.Println("错误：未找到默认配置文件")
			fmt.Println("请使用 -f 指定配置文件路径，或确保存在以下文件之一：")
			fmt.Println("  - tests/server.toml")
			fmt.Println("  - tests/client.toml")
			fmt.Println("  - config.toml")
			fmt.Println("使用 -help 查看帮助信息")
			os.Exit(1)
		}
		fmt.Printf("使用配置文件: %s\n", *configPath)
	}

	// 创建日志记录器
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// 解析配置文件
	cfg, err := config.ParseConfig(*configPath)
	if err != nil {
		logger.Fatalf("解析配置文件失败: %v", err)
	}

	tunDevice, err := tun.NewTun(*tunName, cfg)
	if err != nil {
		logger.Fatalf("创建TUN设备失败: %v", err)
		return
	}

	// 创建设备实例
	dev := device.NewDevice(cfg, tunDevice)

	// 启动设备
	if err := dev.Start(); err != nil {
		logger.Fatalf("启动设备失败: %v", err)
	}

	// 显示启动信息
	showStartupInfo(cfg)

	// 创建信号通道
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 等待信号
	<-sigChan

	// 停止设备
	fmt.Println("\n正在停止设备...")
	dev.Close()

	fmt.Println("设备已停止")
}

// findDefaultConfig 查找默认配置文件
func findDefaultConfig() string {
	// 按优先级顺序查找配置文件
	defaultConfigs := []string{
		"tests/server.toml",
		"tests/client.toml",
		"config.toml",
	}

	for _, configFile := range defaultConfigs {
		if _, err := os.Stat(configFile); err == nil {
			return configFile
		}
	}

	return ""
}

// showStartupInfo 显示启动信息
func showStartupInfo(cfg *config.Config) {
	fmt.Println("=== WireGuard-like VPN 设备已启动 ===")
	fmt.Printf("地址: %s\n", cfg.Interface.Address)

	if cfg.Interface.ListenPort > 0 {
		fmt.Printf("监听端口: %d\n", cfg.Interface.ListenPort)
		fmt.Println("状态: 服务器模式 - 等待客户端连接")
	} else {
		fmt.Println("状态: 客户端模式 - 准备连接服务器")
	}

	fmt.Printf("对端数量: %d\n", len(cfg.Peers))
	for i, peer := range cfg.Peers {
		fmt.Printf("  对端 %d: %s (%s)\n", i+1, peer.PublicKey, peer.Endpoint)
	}

	fmt.Println("=====================================")
	fmt.Println("按 Ctrl+C 停止设备")
}
