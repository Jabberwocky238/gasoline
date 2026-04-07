# Gasoline

go run main.go operator --listen 0.0.0.0:8443 --network "200:10.0.0.0/24;1000:192.168.200.0/24"

go run main.go client --endpoint 127.0.0.1:8443 --vnet 200

go run main.go client --endpoint localhost:8443 --vnet 200

go run main.go client --endpoint 127.0.0.1:8443 --vnet 1000

go run main.go client --endpoint localhost:8443 --vnet 1000