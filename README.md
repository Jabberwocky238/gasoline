# Gasoline

## IDEA

多租户隔离的tunnel系统。

server之间使用udp mesh互联。

client和server之间使用udp或者tcp链接。



## ARCH

main.go是统一启用入口

./gasoline client为启动客户端，
./gasoline server为启动服务端，
客户端和服务端的差别为，是否有公网ip。

启动后，观察.gasoline/文件夹，

.gasoline/
