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

#连接外网的frp
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

[k3szfedoraxrdp]
type = tcp
local_ip = 192.168.1.195
local_port = 3389
remote_port = 5589

[k3szyuancheng]
type = tcp
local_ip = 192.168.1.194
local_port = 3389
remote_port = 6689
EOF


#内网的端口转发
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

[s3localszfedoraxrdp]
type = tcp
local_ip = 192.168.1.195
local_port = 3389
remote_port = 5589

[s3localyuancheng]
type = tcp
local_ip = 192.168.1.194
local_port = 3389
remote_port = 6689
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
*/1 * * * * [ \$(ps | grep frpc.ini | grep -v grep | wc -l) -eq 0 ] && cd /usr/bin/frp && ./frpc -c frpc.ini
*/1 * * * * [ \$(ps | grep frpc1 | grep -v grep | wc -l) -eq 0 ] && cd /usr/bin/frp && ./frpc -c frpc1
*/1 * * * * [ \$(ps | grep frps.ini | grep -v grep | wc -l) -eq 0 ] && cd /usr/bin/frp && ./frps -c frps.ini




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
nohup ./filebrowser -p 23333 --scope /mnt/sda1 2>&1 &






#配置samba36-server

# cat > /etc/config/samba <<EOF
# config samba  
#     option workgroup 'WORKGROUP'  
#     option homes '1'  
#     option name 'k3'  
#     option description 'k3'  

# config sambashare  
#     option name 'k3'
#     option path '/mnt/sda1'
#     option users 'root'  
#     option read_only 'no'  
#     option guest_ok 'no'  
#     option create_mask '0755'  
#     option dir_mask '0755'  
# EOF

# sed -i 's/unix charset = |CHARSET|/unixcharset = utf-8/g' /etc/samba/smb.conf.template
# sed -i 's/invalid users = root/#invalid users = root/g' /etc/samba/smb.conf.template

# cat >> /etc/samba/samba.conf.template <<EOF


# [openwrt]
# path = /mnt/sda1/
# valid users = root
# guest ok = no

# EOF


# touch /etc/samba/smbpasswd  
# echo "请输入两次samba共享的密码，用户名为root"
# smbpasswd  -a root  
