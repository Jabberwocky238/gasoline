package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	tunPkg "github.com/jabberwocky238/gasoline/tun"
	"golang.org/x/sys/windows"
)

func init() {
	stdout := windows.Handle(os.Stdout.Fd())
	var mode uint32
	windows.GetConsoleMode(stdout, &mode)
	windows.SetConsoleMode(stdout, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	tun, err := tunPkg.New("gasoline-tun", "10.0.0.2/24")
	if err != nil {
		fmt.Printf("Error creating TUN interface: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("TUN interface created: %v\n", tun)

	// 监听ctrl c, ctrl d等信号, 退出程序
	var sigs = make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	<-sigs
	cancel()

	fmt.Println("Exiting...")
	os.Exit(0)
}
