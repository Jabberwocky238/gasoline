BINARY_NAME = gasoline
OUTPUT_DIR  = bin

.PHONY: all linux linux-arm64 windows clean

all: linux

linux:
	GOOS=linux GOARCH=amd64 go build -o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-amd64 .

windows:
	GOOS=windows GOARCH=amd64 go build -o $(OUTPUT_DIR)/$(BINARY_NAME)-windows-amd64.exe .

genproto:
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative operator/ctrl/control.proto  


test-op:
	go test ./operator/ -v -timeout 30s

test: test-op

clean:
	rm -rf $(OUTPUT_DIR)/$(BINARY_NAME)-*
