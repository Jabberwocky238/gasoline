tuntest:
	go run cmd/tuntest/main.go

dialtest:
	go run cmd/dialtest/main.go -w=true

dialtest-no:
	go run cmd/dialtest/main.go -w=false

build: $(wildcard **/*.go)
	go build -o build/run.exe main.go
	GOOS=linux GOARCH=amd64 go build -o build/run main.go

t-s:
	go run main.go -f tests/server.toml -n tun1

t-c:
	go run main.go -f tests/client.toml -n tun0

lt-s:
	go run main.go -f ./tests/server.toml -n tun1

lt-c:
	go run main.go -f ./tests/client.toml -n tun0