package udp

import (
	"context"
	"sync"
	"testing"
	"time"
	"wwww/transport"
)

// go test -v ./transport/udp
// go test -v ./transport/udp -timeout 5s

func TestUDP1(t *testing.T) {
	ctx := context.Background()
	server := NewUDPServer()
	err := server.Listen("127.0.0.1", 8080)
	defer server.Close()
	if err != nil {
		t.Fatal(err)
	}

	wg := sync.WaitGroup{}
	buf := make([]byte, 1024)
	n := 0

	wg.Add(1)
	go func() {
		defer wg.Done()
		srvConn, _ := server.Accept()
		if srvConn != nil {
			n, err = srvConn.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("received data: %s", string(buf[:n]))
		}
	}()

	ccfg := &UDPClientConfig{
		host: "127.0.0.1",
	}
	cctx := context.WithValue(ctx, "cfg", ccfg)
	client := NewUDPClient(cctx)
	cltConn, err := client.Dial("127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}

	// sleep 1 second
	time.Sleep(1 * time.Second)
	cltConn.Write([]byte("hello"))

	// wait for the server to receive the data
	wg.Wait()
	// check the data
	if string(buf[:n]) != "hello" {
		t.Fatalf("data mismatch: %s != %s", string(buf[:n]), "hello")
	}
}

// go test -v ./transport/udp -run TestUDP2 -timeout 5s
func TestUDP2(t *testing.T) {
	ctx := context.Background()

	server := NewUDPServer()
	err := server.Listen("127.0.0.1", 8080)
	defer server.Close()
	if err != nil {
		t.Fatal(err)
	}

	wg := sync.WaitGroup{}
	buf := make([]byte, 1024)
	offset := 0
	connChan := make(chan transport.TransportConn, 2)

	// 循环 Accept 连接并放入 connChan
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(connChan)
		for i := 0; i < 2; i++ {
			srvConn, _ := server.Accept()
			if srvConn != nil {
				connChan <- srvConn
			}
		}
	}()

	// 从 connChan 读取连接并读取数据
	wg.Add(1)
	go func() {
		defer wg.Done()
		for conn := range connChan {
			n, err := conn.Read(buf[offset:])
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("received data: %s", string(buf[offset:offset+n]))
			offset += n
		}
	}()

	ccfg := &UDPClientConfig{
		host: "127.0.0.1",
	}
	cctx := context.WithValue(ctx, "cfg", ccfg)
	client1 := NewUDPClient(cctx)
	client2 := NewUDPClient(cctx)
	cltConn1, err := client1.Dial("127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	cltConn2, err := client2.Dial("127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}

	// sleep 1 second
	time.Sleep(1 * time.Second)
	cltConn1.Write([]byte("hello1"))
	cltConn2.Write([]byte("hello2"))

	// wait for the server to receive the data
	wg.Wait()
	// check the data
	if string(buf[:offset]) != "hello1hello2" {
		t.Fatalf("data mismatch: %s != %s", string(buf[:offset]), "hello1hello2")
	}
}
