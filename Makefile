BINARY_NAME = gasoline
OUTPUT_DIR  = bin

.PHONY: all linux linux-arm64 windows clean

prepare:
	git submodule update --init --recursive

all: linux

linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-amd64 .

linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-arm64 .

linux: linux-amd64 linux-arm64

windows:
	GOOS=windows GOARCH=amd64 go build -o $(OUTPUT_DIR)/$(BINARY_NAME)-windows-amd64.exe .

genproto:
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative operator/ctrl/control.proto  


test-op:
	go test ./operator/ -v -timeout 30s

test-op-dataforwarding:
	go test ./operator/ -v -run TestDataForwarding -timeout 10s

test: test-op

# bench-{topology}-{transport}
# topology: csc (client-server-client), cssc (client-server-server-client)
# transport: tcp, udp, quic, tls
bench-csc-tcp:
	go test ./tests/ -v -run TestCSC_TCP -timeout 120s

bench-csc-udp:
	go test ./tests/ -v -run TestCSC_UDP -timeout 120s

bench-csc-quic:
	go test ./tests/ -v -run TestCSC_QUIC -timeout 120s

bench-csc-tls:
	go test ./tests/ -v -run TestCSC_TLS -timeout 120s

bench-cssc-tcp:
	go test ./tests/ -v -run TestCSSC_TCP -timeout 120s

bench-cssc-udp:
	go test ./tests/ -v -run TestCSSC_UDP -timeout 120s

bench-cssc-quic:
	go test ./tests/ -v -run TestCSSC_QUIC -timeout 120s

bench-cssc-tls:
	go test ./tests/ -v -run TestCSSC_TLS -timeout 120s

clean:
	rm -rf $(OUTPUT_DIR)/$(BINARY_NAME)-*
