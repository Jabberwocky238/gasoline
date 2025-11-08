package tcp

import (
	"sync"
	"testing"
	"time"
)

// go test -v ./transport/tcp
// go test -v ./transport/tcp -timeout 5s

func TestTCP(t *testing.T) {
	server := NewTCPServer()
	err := server.Listen("127.0.0.1", 18080)
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

	client := NewTCPClient()
	cltConn, err := client.Dial("127.0.0.1:18080")
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
