<!-- ANY AI AGENT SHOULD NOT MODIFY THIS FILE -->

# gasoline

go run main.go operator --listen "quic://0.0.0.0:8443" --network "200:10.0.0.0/24;1000:192.168.200.0/24"
./gasoline operator --listen "quic://0.0.0.0:20000" --network "200:10.0.0.0/24;1000:192.168.200.0/24" --op-listen "0.0.0.0:6678;69.164.244.173:6678"
./gasoline operator --listen "quic://0.0.0.0:20000;tls://0.0.0.0:20001" --network "200:10.0.0.0/24;1000:192.168.200.0/24" --op-listen "0.0.0.0:6678;69.164.253.11:6678" --discover "69.164.244.173:6678"

sudo go run main.go client --endpoint 69.164.244.173:20000 --vni 200
sudo go run main.go client --endpoint 69.164.253.11:20000 --vni 200
sudo go run main.go client --endpoint localhost:8443 --vni 200
go run main.go client --endpoint 76.13.182.201:20000 --vni 300
go run main.go client --endpoint 172.29.64.1:8443 --vni 200

sudo go run main.go client --endpoint 69.164.244.173:20000 --vni 1000
sudo go run main.go client --endpoint localhost:8443 --vni 1000
go run main.go client --endpoint 172.29.64.1:8443 --vni 1000

kubectl label node vps3359430.trouble-free.net externalip=163.245.211.144
kubectl get nodes -L externalip    
kubectl get nodes --show-labels   
比如有三个节点：    
  
kubectl label node node-1 externalip=10.0.0.1       
kubectl label node node-2 externalip=10.0.0.2
kubectl label node node-3 externalip=10.0.0.3

安装：      
                                                        
  curl -sfL https://get.k3s.io | sh -
                                                                                                                                                                
  卸载：
                                                                                                                                                                
  /usr/local/bin/k3s-uninstall.sh                     
 kubectl get nodes    

  如果是 agent 节点：
    cat /var/lib/rancher/k3s/server/node-token
 curl -sfL https://get.k3s.io | K3S_URL=https://163.245.211.144:6443 K3S_TOKEN=K10f5f954af5bc36afe4af043752b33bb8c0689cf18d1f273024b3b49176ed0f27d::server:fb5377b5568ddbc8158cb3323d05e6a2 sh -s - --node-label externalip=<该节点的外部IP>
  /usr/local/bin/k3s-agent-uninstall.sh

gasolines启动时自动连接 <serverip>:6677，server自己维护一个map，包括了所有server和自己到目标server的延迟时间。

gasolinec只链接一个server，连接上之后开始握手，握手成功后链接成功
所有gasolinec默认自带一个clientid和一个clientsecret

握手开始的时候，服务器给出一个一次性nonce，客户端返回hmac加密结果和自己的clientid，服务器校验通过，下发服务器的wg公钥和client的wg私钥，还有客户端所属ip

客户端发送aead加密后的信息给服务器，服务器解密，获取明文，加上客户端所属的vni group前缀，找到其目的地对应的server是哪个，然后转发给哪个server。对应的server接到后，根据vni group前缀，找到链接的client组，然后根据对应client的allowedips，确定是否发送给他这个包。

gasolines和gasolinec之间的连接使用quic/udp/tcp三种模式

## handshake

1. clienthello, with client_id
2. serverhello, with type, payload(nonce for hmac, salt for user/pswd)
3. clientrequest, with payload
4. serverrespond, with config
5. startsession