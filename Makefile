BINARY_NAME = gasoline
OUTPUT_DIR  = bin

.PHONY: all linux linux-arm64 windows clean

all: linux

linux:
	GOOS=linux GOARCH=amd64 go build -o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-amd64 .

windows:
	GOOS=windows GOARCH=amd64 go build -o $(OUTPUT_DIR)/$(BINARY_NAME)-windows-amd64.exe .

clean:
	rm -rf $(OUTPUT_DIR)/$(BINARY_NAME)-*
