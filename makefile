build:
	go build -o build/gasolinec.exe ./cmd/gasolinec
	go build -o build/gasolines.exe ./cmd/gasolines
	GOOS=linux GOARCH=amd64 go build -o build/gasolinec ./cmd/gasolinec
	GOOS=linux GOARCH=amd64 go build -o build/gasolines ./cmd/gasolines

s:
	go run ./cmd/gasolines start --serve 0.0.0.0:443 --listen 0.0.0.0:6677

c:
	go run ./cmd/gasolinec serve --endpoint 127.0.0.1:443
