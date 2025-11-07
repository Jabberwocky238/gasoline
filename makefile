# Start-Process cmd -Verb RunAs
# Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -Command Set-Location -LiteralPath '$PWD'"
tuntest:
	go run cmd/tuntest/main.go

dialtest:
	go run cmd/dialtest/main.go -w=true

dialtest-no:
	go run cmd/dialtest/main.go -w=false

build: $(wildcard **/*.go)
	go build -o build/run.exe main.go
	GOOS=linux GOARCH=amd64 go build -o build/run main.go

s:
	go run main.go -f samples/server.toml -n tun1

c:
	go run main.go -f samples/client.toml -n tun0

ls:
	go run main.go -f ./samples/server.toml -n tun1

lc:
	go run main.go -f ./samples/client.toml -n tun0

c2:
	go run main.go -f ./samples/client2.toml -n tun1

c3:
	go run main.go -f ./samples/client3.toml -n tun0

# go run main.go -f samples/client2.toml -n tun1
# go run main.go -f samples/client3.toml -n tun0