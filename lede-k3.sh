#!/bin/sh







#install frp
if [ -d  '/mnt/sda1/k3软件/frp' ]; then
    cd /mnt/sda1/k3软件
    cp -r frp /usr/bin/
else
    cd /tmp
    wget https://github.com/fatedier/frp/releases/download/v0.21.0/frp_0.21.0_linux_arm.tar.gz
    tar xzvf frp_0.21.0_linux_arm.tar.gz
    mv frp_0.21.0_linux_arm frp
    mv frp /usr/bin
fi
cd /usr/bin/frp


chmod +x frpc frps

cat > frpc.ini <<EOF
[common]
server_addr = www6.madao.bid
server_port = 7000
token = a95655890

[k3ssh]
type = tcp
local_ip = 127.0.0.1
local_port = 22
remote_port = 3322

[k3file]
type = tcp
local_ip = 127.0.0.1
local_port = 23333
remote_port = 9473

[k3luci]
type = tcp
local_ip = 127.0.0.1
local_port = 80
remote_port = 3380

[k3transmission]
type = tcp
local_ip = 127.0.0.1
local_port = 9091
remote_port = 3390

[k3szvnc]
type = tcp
local_ip = 192.168.1.194
local_port = 5900
remote_port = 3359
EOF

cat > frpc1 <<EOF
[common]
server_addr = 0.0.0.0
server_port = 7000

[s3localszvnc]
type = tcp
local_ip = 192.168.1.194
local_port = 5900
remote_port = 5901

[s3localtransmission]
type = tcp
local_ip = 127.0.0.1
local_port = 9091
remote_port = 9092
EOF

cat > frps.ini <<EOF
[common]
bind_port = 7000
EOF




#为openwrt添加任务计划
#包括：
#1.每分钟检查有没有以配置文件frpc.ini和frpc1运行frpc和以frps.ini运行frps 若没有就运行




cd /etc/crontabs
cat > root <<EOF
*/1 * * * * [ $(ps | grep frpc.ini | grep -v grep | wc -l) -eq 0 ] && cd /usr/bin/frp && ./frpc -c frpc.ini
*/1 * * * * [ $(ps | grep frpc1 | grep -v grep | wc -l) -eq 0 ] && cd /usr/bin/frp && ./frpc -c frpc1
*/1 * * * * [ $(ps | grep frps.ini | grep -v grep | wc -l) -eq 0 ] && cd /usr/bin/frp && ./frps -c frps.ini




EOF
/etc/init.d/cron start
/etc/init.d/cron enable



#配置filebrowser
if [ -d '/mnt/sda1/k3软件/filebrowser' ]; then
    cd /mnt/sda1/k3软件
    cp -r filebrowser /usr/bin
    cd /usr/bin/filebrowser
else
    cd /usr/bin
    mkdir filebrowser
    cd filebrowser
    wget --no-check-certificate https://raw.githubusercontent.com/goomadao/auto_install/master/filebrowser
fi
chmod +x filebrowser
./filebrowser -p 23333 --scope /mnt/sda1






#配置samba36-server

cat > /etc/config/samba <<EOF
config samba  
    optionworkgroup 'WORKGROUP'  
    optionhomes '1'  
    optionname 'k3'  
    optiondescription 'k3'  

config sambashare  
    optionname 'k3'
    optionpath '/mnt/sda1'
    optionusers 'root'  
    optionread_only 'no'  
    optionguest_ok 'no'  
    optioncreate_mask '0755'  
    optiondir_mask '0755'  
EOF

sed -i 's/unixcharset = |CHARSET|/unixcharset = utf8' /etc/samba/samba.conf.template
sed -i 's/invalid users = root/#invalid users = root' /etc/samba/samba.conf.template


touch /etc/samba/smbpasswd  
echo "请输入两次samba共享的密码，用户名为root"
smbpasswd  -a root  
