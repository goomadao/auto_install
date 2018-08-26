#!/bin/sh

#修改ssr luci配置
cd /usr/lib/lua/luci/model/cbi/shadowsocksr
sed -i 's/local arp_table = luci\.sys\.net\.arptable() or {}/local arp_table = luci\.ip\.neighbors()/g' client.lua
sed -i 's/local arp_table = luci\.sys\.net\.arptable() or {}/local arp_table = luci\.ip\.neighbors()/g' client-config.lua






#install frp
cd /tmp
wget https://github.com/fatedier/frp/releases/download/v0.21.0/frp_0.21.0_linux_mipsle.tar.gz
tar xzvf frp_0.21.0_linux_mipsle.tar.gz
mv frp_0.21.0_linux_mipsle frp
cd frp
rm -rf *frps*
cd ..
mv frp /usr/
cd /usr
cd frp

cat > frpc.ini <<EOF
[common]
server_addr = frp.madao.bid
server_port = 7000
token = a95655890

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
remote_port = 1180
EOF

cat > frpc1 <<EOF
[common]
server_addr = byfrp.madao.bid
server_port = 7000
token = a95655890

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
remote_port = 1180
EOF




#为openwrt添加任务计划
#包括：
#1.每分钟检查有没有以配置文件frpc.ini和frpc1运行frpc 若没有就运行
#2.早上八点重启路由器(需要先把时区改为正八区)

cd /etc/config
sed -i "s/option timezone 'UTC'/option timezone 'CST-8'/g" system
/etc/init.d/system restart



cd /etc/crontabs
cat > root <<EOF
*/1 * * * * [ $(ps | grep frpc.ini | grep -v grep | wc -l) -eq 0 ] && cd /usr/frp && ./frpc -c frpc.ini
*/1 * * * * [ $(ps | grep frpc1 | grep -v grep | wc -l) -eq 0 ] && cd /usr/frp && ./frpc -c frpc1
0 8 * * * reboot




EOF
/etc/init.d/cron start
/etc/init.d/cron enable