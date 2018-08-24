#!/bin/sh

install_frp()
{
    cd /tmp
    wget https://github.com/fatedier/frp/releases/download/v0.21.0/frp_0.21.0_linux_mipsle.tar.gz
    tar xzvf frp_0.21.0_linux_mipsle.tar.gz -C /usr
    cd /usr
    mv frp_0.21.0_linux_mipsle frp
    cd frp

    cat > frpc.ini <<EOF
[common]
server_addr = frp.madao.bid
server_port = 7000

[ssh]
type = tcp
local_ip = 127.0.0.1
local_port = 22
remote_port = 1122

[ssr]
type = tcp
local_ip = 127.0.0.1
local_port = 1024
remote_port = 11024

[luci]
type = tcp
local_ip = 127.0.0.1
local_port = 80
remote_port = 8080
EOF

        cat > frpc1 <<EOF
[common]
server_addr = frp.madao.bid
server_port = 7000

[ssh]
type = tcp
local_ip = 127.0.0.1
local_port = 22
remote_port = 1122

[ssr]
type = tcp
local_ip = 127.0.0.1
local_port = 1024
remote_port = 11024

[luci]
type = tcp
local_ip = 127.0.0.1
local_port = 80
remote_port = 8080
EOF

    
}