#! /bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

os='ossystem'
password='123456m'
port='1024'

libsodium_file="libsodium-1.0.16"
libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz"

shadowsocks_r_file="shadowsocksr-3.2.2"
shadowsocks_r_url="https://github.com/shadowsocksrr/shadowsocksr/archive/3.2.2.tar.gz"

kernel_ubuntu_url="http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.10.2/linux-image-4.10.2-041002-generic_4.10.2-041002.201703120131_amd64.deb"
kernel_ubuntu_file="linux-image-4.10.2-041002-generic_4.10.2-041002.201703120131_amd64.deb"

DIR=`pwd`

cur_dir=`pwd`




#clout torrent
sh_ver="1.2.3"
file="/usr/local/cloudtorrent"
ct_file="/usr/local/cloudtorrent/cloud-torrent"
dl_file="/usr/local/cloudtorrent/downloads"
ct_config="/usr/local/cloudtorrent/cloud-torrent.json"
ct_conf="/usr/local/cloudtorrent/cloud-torrent.conf"
ct_log="/tmp/ct.log"
IncomingPort="50007"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"




#加密方式
ciphers=(
none
aes-256-cfb
aes-192-cfb
aes-128-cfb
aes-256-cfb8
aes-192-cfb8
aes-128-cfb8
aes-256-ctr
aes-192-ctr
aes-128-ctr
chacha20-ietf
chacha20
salsa20
xchacha20
xsalsa20
rc4-md5
)

#protocol
protocols=(
origin
verify_deflate
auth_sha1_v4
auth_sha1_v4_compatible
auth_aes128_md5
auth_aes128_sha1
auth_chain_a
auth_chain_b
auth_chain_c
auth_chain_d
auth_chain_e
auth_chain_f
)

# obfs
obfs=(
plain
http_simple
http_simple_compatible
http_post
http_post_compatible
tls1.2_ticket_auth
tls1.2_ticket_auth_compatible
tls1.2_ticket_fastauth
tls1.2_ticket_fastauth_compatible
)

# Make sure only root can run our script
[[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] This script must be run as root!" && exit 1

wrong_para()
{
	echo -e "[${red}错误${plain}] 参数输入错误!$1"
}

#--------------------------------------------------------------------------------------------------------------------------------------1. Install ShadowsocksR--------------------------------------------------------------------------------------------------------------------


NAME=ShadowsocksR
DAEMON=/usr/local/shadowsocks/server.py
if [ -f /etc/shadowsocks-r/config.json ]; then
    CONF=/etc/shadowsocks-r/config.json
elif [ -f /etc/shadowsocks.json ]; then
    CONF=/etc/shadowsocks.json
fi
RETVAL=0

check_running(){
    PID=$(ps -ef | grep -v grep | grep -i "${DAEMON}" | awk '{print $2}')
    if [ -n "$PID" ]; then
        return 0
    else
        return 1
    fi
}

ssr_start(){
    check_running
    if [ $? -eq 0 ]; then
        echo "$NAME (pid $PID) is already running..."
        return
    else
        $DAEMON -c $CONF -d start
        RETVAL=$?
        if [ $RETVAL -eq 0 ]; then
            echo "Starting $NAME success"
			return
        else
            echo "Starting $NAME failed"
			exit 1
        fi
    fi
}

ssr_stop(){
    check_running
    if [ $? -eq 0 ]; then
        $DAEMON -c $CONF -d stop
        RETVAL=$?
        if [ $RETVAL -eq 0 ]; then
            echo "Stopping $NAME success"
			return
        else
            echo "Stopping $NAME failed"
			exit 1
        fi
    else
        echo "$NAME is stopped"
        RETVAL=1
		return
    fi
}

ssr_status(){
    check_running
    if [ $? -eq 0 ]; then
        echo "$NAME (pid $PID) is running..."
		return
    else
        echo "$NAME is stopped"
        RETVAL=1
		return
    fi
}

ssr_restart(){
    do_stop
    sleep 0.5
    do_start
	return
}



install_ssr(){

	[ -f /usr/local/shadowsocks/server.py ] && echo -e "[${red}Error${plain}] shadowsocksR已安装" && return


    disable_selinux
    pre_install
    download_files
    config_shadowsocks
    if check_sys packageManager yum || check_sys packageManager dnf; then
        firewall_set
    fi
    install
    install_cleanup
}

disable_selinux()
{
	if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

pre_install()
{
	if check_sys packageManager yum || check_sys packageManager apt || check_sys packageManager dnf; then
		#Not supporting centos 5
		if centosversion 5; then
			echo -e "[${red}Error${plain}]不支持CentOs5,请将系统换为CentOs 6+/Ubuntu 12+/Debian 7+/Fedora 27+并重试"
			exit 1
		fi
	else
		echo -e "[${red}Error${plain}]不支持你的系统,请将系统换为CentOs 6+/Ubuntu 12+/Debian 7+/Fedora 27+并重试"
		exit 1
	fi
	
	shadowsockspwd=${password}
	shadowsocksport=$port
	shadowsockscipher="aes-256-cfb"
	shadowsocksprotocol="origin"
	shadowsocksobfs="plain"
	
	if check_sys packageManager yum; then
		yum -y update
		yum -y install python python-devel python-setuptools openssl openssl-devel curl wget unzip gcc automake autoconf make libtool
	elif check_sys packageManager dnf; then
		dnf -y update
		dnf -y install python python-devel python-setuptools openssl openssl-devel curl wget unzip gcc automake autoconf make libtool
	elif check_sys packageManager apt; then
		apt-get -y update
		apt-get -y install python python-dev python-setuptools openssl libssl-dev curl wget unzip gcc automake autoconf make libtool
	fi	
	cd $cur_dir
}

check_sys()
{
	local checkType=$1
	local value=$2
	
	local release=""
	local systemPackage=""
	

	if grep -Eqi "centos" /etc/redhat-release; then
		release="centos"
		systemPackage="yum"
	elif grep -Eqi "fedora" /etc/redhat-release; then
		release="fedora"
		systemPackage="dnf"
	elif grep -Eqi "debian" /etc/issue; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /etc/issue; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos" /etc/issue; then
        release="centos"
        systemPackage="yum"
	elif grep -Eqi "fedora" /etc/issue; then
		release="fedora"
		systemPackage="dnf"
    elif grep -Eqi "debian" /proc/version; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /proc/version; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos" /proc/version; then
        release="centos"
        systemPackage="yum"
	elif grep -Eqi "fedora" /proc/version; then
        release="fedora"
        systemPackage="dnf"
    fi
	
	if [[ "${checkType}" == "sysRelease" ]]; then
		if [[ "${value}" == "${release}" ]]; then
			return 0
		else
			return 1
		fi
	elif [[ "${checkType}" == "packageManager" ]]; then
		if [[ "${value}" == "${systemPackage}" ]]; then
			return 0
		else
			return 1
		fi
	fi
}

centosversion()
{
		if check_sys sysRelease centos; then
			local code=$1
			local version="$(getversion)"
			local main_version="${version%%.*}"
			if [[ "${main_version}" == "${code}" ]]; then
				return 0
			else
				return 1
			fi
		else
			return 1
		fi
}

getversion()
{
	if [[ -s /etc/redhat-release ]]; then
		grep -oE "[0-9.]+" /etc/redhat-release
	elif [[ -s /etc/issue ]]; then
		grep -oE "[0-9.]+" /etc/issue
	fi
}

download_files()
{
	# Download libsodium file
    if ! wget --no-check-certificate -O ${libsodium_file}.tar.gz ${libsodium_url}; then
        echo -e "[${red}Error${plain}] Failed to download ${libsodium_file}.tar.gz!"
        exit 1
    fi
    # Download ShadowsocksR file
    if ! wget --no-check-certificate -O ${shadowsocks_r_file}.tar.gz ${shadowsocks_r_url}; then
        echo -e "[${red}Error${plain}] Failed to download ShadowsocksR file!"
        exit 1
    fi
    # Download ShadowsocksR init script
    if check_sys packageManager yum || check_sys packageManager dnf; then
        if ! wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR -O /etc/init.d/shadowsocks; then
            echo -e "[${red}Error${plain}] Failed to download ShadowsocksR chkconfig file!"
            exit 1
        fi
    elif check_sys packageManager apt; then
        if ! wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR-debian -O /etc/init.d/shadowsocks; then
            echo -e "[${red}Error${plain}] Failed to download ShadowsocksR chkconfig file!"
            exit 1
        fi
    fi
}

config_shadowsocks()
{
	cat > /etc/shadowsocks.json << EOF
{
	"server":"0.0.0.0",
	"server_ipv6":"[::]",
	"server_port":${shadowsocksport},
	"local_address":"127.0.0.1",
	"local_port":1080,
	"password":"${shadowsockspwd}",
	"timeout":120,
	"method":"${shadowsockscipher}",
	"protocol":"${shadowsocksprotocol}",
	"protocol_param":"",
	"obfs":"${shadowsocksobfs}",
	"obfs_param":"",
	"redirect":"",
	"dns_ipv6":false,
	"fast_open":false,
	"workers":1
}
EOF
}

firewall_set()
{
	echo -e "[${green}Info${plain}] firewall set start"
	if check_sys packageManager dnf;then
		iptables -L -n | grep -i ${shadowsocksport} > /dev/null 2>&1
		if [ $? -ne 0 ]; then
			iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
			iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
			iptables -I OUTPUT -m state --state NEW -m tcp -p tcp --dport 1024 -j ACCEPT
			iptables -I OUTPUT -m state --state NEW -m udp -p udp --dport 1024 -j ACCEPT
			service iptables save
			service iptables restart
		else
			echo -e "[${green}Info${plain}] port ${shadowsocksport} has been set up."
		fi
	elif check_sys packageManager yum; then
		if centosversion 6; then
			/etc/init.d/iptables status > /dev/null 2>&1
			if [ $? -eq 0 ]; then
				iptables -L -n | grep -i ${shadowsocksport} > /dev/null 2>&1
				if [ $? -ne 0 ]; then
					iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
					iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
					/etc/init.d/iptables save
					/etc/init.d/iptables restart
				else
					echo -e "[${green}Info${plain}] port ${shadowsocksport} has been set up."
				fi
			else
				echo -e "[${yellow}Warning${plain}] iptables looks like shutdown or not installed, please manually set it if necessary."
			fi
		elif centosversion 7; then
			systemctl status firewalld > /dev/null 2>&1
			if [ $? -eq 0 ]; then
				firewall-cmd --zone=public --add-port=${shadowsocksport}/tcp --permanent
				firewall-cmd --zone=public --add-port=${shadowsocksport}/udp --permanent
				firewall-cmd --reload
			else
				echo -e "[${yellow}Warning${plain}] iptables looks like shutdown or not installed, please manually set it if necessary."
			fi
		fi
	fi
	echo -e "[${green}Info${plain}] firewall set conplete"
}

install()
{
	#install libsodium
	if [ ! -f /usr/libsodium.a ]; then
		cd ${cur_dir}
		tar zxf ${libsodium_file}.tar.gz
		cd $libsodium_file
		./configure --prefix=/usr && make && make install
		if [ $? -ne 0 ]; then
			echo -e "[${red}Error${plain}] libsodium install failed!"
			install_cleanup
			exit 1
		fi
	fi
	
	ldconfig
	
	#install shadowsocksR
	cd ${cur_dir}
	tar zxf ${shadowsocks_r_file}.tar.gz
	mv ${shadowsocks_r_file}/shadowsocks /usr/local/
	if [ -f /usr/local/shadowsocks/server.py ]; then
		chmod +x /etc/init.d/shadowsocks
		if check_sys packageManager yum || check_sys packageManager dnf; then
			chkconfig --add shadowsocks
			chkconfig shadowsocks on
		elif check_sys packageManager apt; then
			update-rc.d -f shadowsocks defaults
		fi
		/etc/init.d/shadowsocks start
		
		
	else
		echo "shadowsocksR install failed, please try another method"
		install_cleanup
		exit 1
	fi
}

install_cleanup()
{
	cd ${cur_dir}
	rm -rf ${shadowsocks_r_file}.tar.gz ${shadowsocks_r_file} ${libsodium_file}.tar.gz ${libsodium_file}
}


get_ipv4()
{
	local ip=$( ip addr | grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | grep -vE "^192\.168\." | grep -vE "^172\.1[6-9]{1}\." | grep -vE "^172\.2[0-9]{1}\." | grep -vE "^172\.3[0-2]{1}\." | grep -vE "^10\." | grep -vE "^127\." | grep -vE "^255\." | grep -vE "^0\." | head -n 1 )     
	[ -z ${ip} ] && ip=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
	[ -z ${ip} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
	[ ! -z ${ip} ] && echo ${ip}
	[ -z ${ip} ] && echo "服务器没有公网IPv4地址，请自行检查!"
}

get_ipv6()
{
	local ip=$( ip addr | grep -oE "20[0-9a-f]{2}:[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}" )
	[ -z ${ip} ] && ip=$(wget -qO- -t1 -T2 ip.sb)
	[ ! -z ${ip} ] && echo $ip
	[ -z ${ip} ] && echo "服务器没有公网IPv6地址，请自行检查!"
	
}

# Uninstall ShadowsocksR
uninstall_shadowsocksr(){
    printf "Are you sure uninstall ShadowsocksR? (y/n)"
    printf "\n"
    read -p "(Default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        /etc/init.d/shadowsocks status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            /etc/init.d/shadowsocks stop
        fi
        if check_sys packageManager yum || check_sys packageManager dnf; then
            chkconfig --del shadowsocks
        elif check_sys packageManager apt; then
            update-rc.d -f shadowsocks remove
        fi
        rm -f /etc/shadowsocks.json
        rm -f /etc/init.d/shadowsocks
        rm -f /var/log/shadowsocks.log
        rm -rf /usr/local/shadowsocks
        echo "ShadowsocksR uninstall success!"
    else
        echo
        echo "uninstall cancelled, nothing to do..."
        echo
    fi
}



#----------------------------------------------------------------------------------------------------------------------------------------------------2. Install pip--------------------------------------------------------------------------------------------------------------------
install_pip()
{
	if check_sys packageManager yum; then
		yum -y install python-pip
	elif check_sys packageManager dnf; then
		dnf -y install python-pip
	fi
}

#----------------------------------------------------------------------------------------------------------------------------------------------------3. upgrade pip--------------------------------------------------------------------------------------------------------------------
upgrade_pip()
{
	pip install --upgrade pip
}

#----------------------------------------------------------------------------------------------------------------------------------------------------4. install speedtest--------------------------------------------------------------------------------------------------------------------
install_speedtest()
{
	pip install speedtest-cli
}

#----------------------------------------------------------------------------------------------------------------------------------------------------5. install progress--------------------------------------------------------------------------------------------------------------------
install_progress()
{
	cd ${cur_dir}
	if ! wget --no-check-certificate https://github.com/Xfennec/progress/archive/v0.14.tar.gz; then
		echo -e "[${red}Error${plain}] Failed to download progress-v0.14.tar.gz!"
		clean_progress
		return
	fi
	tar zxf v0.14.tar.gz
	mv progress-0.14 progress
	cd progress
	if check_sys packageManager yum; then
		yum -y install ncurses-devel gcc make
	elif check_sys packageManager dnf; then
		dnf -y install ncurses-devel gcc make
	fi
	make && make install
	clean_progress
}

clean_progress()
{
	cd ${cur_dir}
	rm -rf v0.14.tar.gz
}

#----------------------------------------------------------------------------------------------------------------------------------------------------6. install bbr--------------------------------------------------------------------------------------------------------------------
install_bbr()
{
	[[ -d "/proc/vz" ]] && echo -e "[${red}错误${plain}] 你的系统是OpenVZ架构的，不支持开启BBR。" && exit 1
	check_os
	check_bbr_status
	if [ $? -eq 0 ]; then
		echo -e "[${green}提示${plain}] TCP BBR加速已经开启成功。"
		return
	fi
	
	check_kernel_version
	if [ $? -eq 0 ]; then
		echo -e "[${green}提示${plain}] 你的系统版本高于4.9，直接开启BBR加速。"
		sysctl_config
		echo -e "[${green}提示${plain}] TCP BBR加速开启成功"
		return
	fi
	
	if [[ "${os}" == "centos" ]]; then
		install_elrepo
		yum -y install yum-plugin-fastestmirror
		yum -y --enablerepo=elrepo-kernel install kernel-ml kernel-ml-devel
		if [ $? -ne 0 ]; then
			echo -e "[${red}Error${plain}] 安装内核失败，请自行检查"
			exit 1
		fi
	elif [[ x"${os}" == x"debian" || x"${os}" == x"ubuntu" ]]; then
		[[ ! -e "/usr/bin/wget" ]] && apt-get -y update && apt-get -y install wget
		wget ${kernel_ubuntu_url}
		if [ $? -ne 0 ]
		then
			echo -e "[${red}错误${plain}] 下载内核失败，请自行检查。"
			exit 1
		fi
		dpkg -i ${kernel_ubuntu_file}
	else
		echo -e "[${red}错误${plain}] 脚本不支持该操作系统，请修改系统为CentOS/Debian/Ubuntu/Fedora。"
		exit 1
	fi
	
	install_config
	sysctl_config
	reboot_os
	
}

check_os() {
    if grep -Eqi "centos" /etc/redhat-release; then
        os="centos"
	elif grep -Eqi "fedora" /etc/redhat-release; then
		os="fedora"
    elif cat /etc/issue | grep -Eqi "debian"; then
        os="debian"
    elif cat /etc/issue | grep -Eqi "ubuntu"; then
        os="ubuntu"
    elif cat /etc/issue | grep -Eqi "centos"; then
        os="centos"
	elif cat /etc/issue | grep -Eqi "fedora"; then
        os="fedora"
    elif cat /proc/version | grep -Eqi "debian"; then
        os="debian"
    elif cat /proc/version | grep -Eqi "ubuntu"; then
        os="ubuntu"
    elif cat /proc/version | grep -Eqi "centos"; then
        os="centos"
	elif cat /proc/version | grep -Eqi "fedora"; then
        os="fedora"
    fi
}

check_bbr_status() {
    local param=$(sysctl net.ipv4.tcp_available_congestion_control | grep bbr)
    if [[ -n $param ]]; then
        return 0
    else
        return 1
    fi
}

check_kernel_version()
{
	local version=$( uname -r | cut -d - -f1 )
	if version_ge $version 4.9; then
		return 0
	else
		return 1
	fi
}

version_ge()
{
	test "$( echo $@ | tr " " "\n" | sort -rV | head -n 1 )" == "$1"
}

sysctl_config()
{
	sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
}

install_elrepo()
{
	if centosversion 5; then
		echo -e "[${red}Error${plain}] 脚本不支持CentOS 5"
		exit 1
	fi
	
	
	rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
	
	if centosversion 6; then
		rpm -Uvh http://www.elrepo.org/elrepo-release-6.8.el6.elrepo.noarch.rpm
	elif centosversion 7; then
		rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-2.el7.elrepo.noarch.rpm
	fi
	
	
	if [ ! -f /etc/yum.repos.d/elrepo.repo ]; then
		echo -e "[${red}Error${plain}] 安装elrepo失败，请自行检查"
		exit 1
	fi
}

install_config()
{
	if [[ "${os}" == "centos" ]]; then
		if centosversion 6; then
			if [ ! -f /boot/grub/grub.conf ]; then
				echo -e "[${red}Error${plain}] 没有找到/boot/grub/grub.conf文件"
				exit 1
			fi
			sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
		elif centosversion 7; then
			if [ ! -f "/boot/grub2/grub.cfg" ]; then
                echo -e "[${red}错误${plain}] 没有找到/boot/grub2/grub.cfg文件。"
                exit 1
            fi
			grub2-set-default 0
		fi
	elif [[ "${os}" == "ubuntu" || "${os}" == "debian" ]]; then
		/usr/sbin/update-grub
	fi
}

reboot_os()
{
	echo
	echo -e "[${green}Hint${plain}] 系统需要重启BBR才能生效"
	reboot
}

#----------------------------------------------------------------------------------------------------------------------------------------------------7. install aria2--------------------------------------------------------------------------------------------------------------------
install_aria2()
{
	cd ${cur_dir}
	if check_sys packageManager yum; then
		yum -y groupinstall "Development tools"
		yum -y install gcc-c++
	elif check_sys packageManager dnf; then
		dnf -y groupinstall "Development tools"
		dnf -y install gcc-c++
	fi
	wget --no-check-certificate https://github.com/aria2/aria2/releases/download/release-1.34.0/aria2-1.34.0.tar.gz
	tar zxf aria2-1.34.0.tar.gz
	mv aria2-1.34.0 aria2
	cd aria2
	cd src
	sed 's/make_unique/aria2::make_unique/g' bignum.h
	sed -i "20a\#include \"a2functional.h\"" bignum.h
	cd ../
	./configure
	make
	make install
	#firewall may need to be set

	clean_aria2
	start_aria2

}

clean_aria2()
{
	cd ${cur_dir}
	rm -rf aria2-1.34.0.tar.gz
}

start_aria2()
{
	aria2c --enable-rpc --rpc-listen-all --rpc-allow-origin-all --rpc-secret=pandownload -c --dir /root/downloads -D
}

#----------------------------------------------------------------------------------------------------------------------------------------------------8. install cloudt--------------------------------------------------------------------------------------------------------------------
Install_ct(){
	[[ -e ${ct_file} ]] && echo -e "${Error} 检测到 Cloud Torrent 已安装 !" && return
	check_sys2
	echo -e "${Info} 开始设置 用户配置..."
	Set_conf
	echo -e "${Info} 开始安装/配置 依赖..."
	Installation_dependency
	echo -e "${Info} 开始检测最新版本..."
	check_new_ver
	echo -e "${Info} 开始下载/安装..."
	Download_ct
	echo -e "${Info} 开始下载/安装 服务脚本(init)..."
	Service_ct
	echo -e "${Info} 开始写入 配置文件..."
	Write_config
	echo -e "${Info} 开始设置 iptables防火墙..."
	Set_iptables
	echo -e "${Info} 开始添加 iptables防火墙规则..."
	Add_iptables
	echo -e "${Info} 开始保存 iptables防火墙规则..."
	Save_iptables
	echo -e "${Info} 所有步骤 安装完毕，开始启动..."
	start_ct
}

check_sys2(){
	if grep "centos" /etc/redhat-release; then
		release="centos"
	elif grep "fedora" /etc/redhat-release; then
		release="fedora"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos"; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "fedora"; then
		release="fedora"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "fedora"; then
		release="fedora"
    fi
	bit=$(uname -m)
}

Set_conf(){
	Set_host
	Set_port
	Set_user
}

Set_host(){
	ct_host="0.0.0.0"
	echo && echo "========================"
	echo -e "	主机 : ${Red_background_prefix} ${ct_host} ${Font_color_suffix}"
	echo "========================" && echo
}

Set_port(){
	ct_port="8000"
	echo && echo "========================"
	echo -e "	端口 : ${Red_background_prefix} ${ct_port} ${Font_color_suffix}"
	echo "========================" && echo
}

Set_user(){
	ct_user="admin"
	echo && echo "========================"
	echo -e "	用户名 : ${Red_background_prefix} ${ct_user} ${Font_color_suffix}"
	echo "========================" && echo

	ct_passwd="a95655890"
	echo && echo "========================"
	echo -e "	密码 : ${Red_background_prefix} ${ct_passwd} ${Font_color_suffix}"
	echo "========================" && echo
}

Installation_dependency(){
	gzip_ver=$(gzip -V)
	if [[ -z ${gzip_ver} ]]; then
		if [[ ${release} == "centos" ]]; then
			yum update -y
			yum install -y gzip
		elif [[ ${release} == "fedora" ]]; then
			dnf update -y
			dnf install -y gzip
		else
			apt-get update
			apt-get install -y gzip
		fi
	fi
	mkdir ${file}
	mkdir ${dl_file}
}

check_new_ver(){
	ct_new_ver=$(wget --no-check-certificate -qO- https://github.com/jpillora/cloud-torrent/releases/latest | grep "<title>" | sed -r 's/.*Release (.+) · jpillora.*/\1/')
	if [[ -z ${ct_new_ver} ]]; then
		echo -e "${Error} Cloud Torrent 最新版本获取失败，请手动获取最新版本号[ https://github.com/jpillora/cloud-torrent/releases ]"
		stty erase '^H' && read -p "请输入版本号 [ 格式 x.x.xx , 如 0.8.21 ] :" ct_new_ver
		[[ -z "${ct_new_ver}" ]] && echo "取消..." && exit 1
	else
		echo -e "${Info} Cloud Torrent 目前最新版本为 ${ct_new_ver}"
	fi
}

Download_ct(){
	cd ${file}
	if [[ ${bit} == "x86_64" ]]; then
		wget --no-check-certificate -O cloud-torrent.gz "https://github.com/jpillora/cloud-torrent/releases/download/${ct_new_ver}/cloud-torrent_linux_amd64.gz"
	else
		wget --no-check-certificate -O cloud-torrent.gz "https://github.com/jpillora/cloud-torrent/releases/download/${ct_new_ver}/cloud-torrent_linux_386.gz"
	fi
	[[ ! -e "cloud-torrent.gz" ]] && echo -e "${Error} Cloud Torrent 下载失败 !" && exit 1
	gzip -d cloud-torrent.gz
	[[ ! -e ${ct_file} ]] && echo -e "${Error} Cloud Torrent 解压失败(可能是 压缩包损坏 或者 没有安装 Gzip) !" && exit 1
	rm -rf cloud-torrent.gz
	chmod +x cloud-torrent
}

Service_ct(){
	if [[ ${release} = "centos" || ${release} = "fedora" ]]; then
		if ! wget --no-check-certificate "https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/other/cloudt_centos" -O /etc/init.d/cloudt; then
			echo -e "${Error} Cloud Torrent服务 管理脚本下载失败 !" && exit 1
		fi
		chmod +x /etc/init.d/cloudt
		chkconfig --add cloudt
		chkconfig cloudt on
	else
		if ! wget --no-check-certificate "https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/other/cloudt_debian" -O /etc/init.d/cloudt; then
			echo -e "${Error} Cloud Torrent服务 管理脚本下载失败 !" && exit 1
		fi
		chmod +x /etc/init.d/cloudt
		update-rc.d -f cloudt defaults
	fi
	echo -e "${Info} Cloud Torrent服务 管理脚本下载完成 !"
}

Write_config(){
	cat > ${ct_conf}<<-EOF
host = ${ct_host}
port = ${ct_port}
user = ${ct_user}
passwd = ${ct_passwd}
EOF
}

Set_iptables(){
	if [[ ${release} == "centos" || ${release} == "fedora" ]]; then
		service iptables save
		chkconfig --level 2345 iptables on
	else
		iptables-save > /etc/iptables.up.rules
		echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules' > /etc/network/if-pre-up.d/iptables
		chmod +x /etc/network/if-pre-up.d/iptables
	fi
}

Add_iptables(){
	iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ct_port} -j ACCEPT
	iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ct_port} -j ACCEPT
	iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${IncomingPort} -j ACCEPT
	iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${IncomingPort} -j ACCEPT
	iptables -I OUTPUT -m state --state NEW -m tcp -p tcp --dport ${IncomingPort} -j ACCEPT
	iptables -I OUTPUT -m state --state NEW -m udp -p udp --dport ${IncomingPort} -j ACCEPT
}

Save_iptables(){
	if [[ ${release} == "centos" || ${release} == "fedora" ]]; then
		service iptables save
	else
		iptables-save > /etc/iptables.up.rules
	fi
}

start_ct(){
	check_installed_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} Cloud Torrent 正在运行，请检查 !" && return
	/etc/init.d/cloudt start
}

check_installed_status(){
	[[ ! -e ${ct_file} ]] && echo -e "${Error} Cloud Torrent 没有安装，请检查 !" && exit 1
}

check_pid(){
	PID=$(ps -ef | grep cloud-torrent | grep -v grep | awk '{print $2}')
}



#----------------------------------------------------------------------------------------------------------------------------------------------------9. install filebrowser--------------------------------------------------------------------------------------------------------------------
install_filebrowser()
{
	cd ${cur_dir}
	if check_sys packageManager dnf || check_sys packageManager yum && centosversion 6; then
		[ -d filebrowser ] && echo -e "[${green}Hint${plain}] filebrowser目录已存在" && cd filebrowser && ./filebrowser --port 23333 --scope /root && iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 23333 -j ACCEPT && iptables -I INPUT -m state --state NEW -m udp -p udp --dport 23333 -j ACCEPT && service iptables save && service iptables restart && return                 
	elif check_sys packageManager yum && centosversion 7; then
		[ -d filebrowser ] && echo -e "[${green}Hint${plain}] filebrowser目录已存在" && cd filebrowser && ./filebrowser --port 23333 --scope /root && firewall-cmd --zone=public --add-port=23333/tcp --permanent && firewall-cmd --zone=public --add-port=23333/udp --permanent && firewall-cmd --reload && return                 
	fi
	[ ! -d filebrowser ] && mkdir filebrowser
	cd filebrowser
	wget https://github.com/filebrowser/filebrowser/releases/download/v1.8.0/linux-amd64-filebrowser.tar.gz
	tar -zxvf linux-amd64-filebrowser.tar.gz
	./filebrowser --port 23333 --scope /root &
	
	set_filebrowser_firewall
	
	clean_filebrowser
}

set_filebrowser_firewall()
{
	if check_sys packageManager dnf; then
		iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 23333 -j ACCEPT
		iptables -I INPUT -m state --state NEW -m udp -p udp --dport 23333 -j ACCEPT
		iptables -I OUTPUT -m state --state NEW -m tcp -p tcp --dport 23333 -j ACCEPT
		iptables -I OUTPUT -m state --state NEW -m udp -p udp --dport 23333 -j ACCEPT
		service iptables save
		service iptables restart
	elif check_sys packageManager yum; then
		if centosversion 6; then
			iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 23333 -j ACCEPT
			iptables -I INPUT -m state --state NEW -m udp -p udp --dport 23333 -j ACCEPT
			iptables -I OUTPUT -m state --state NEW -m tcp -p tcp --dport 23333 -j ACCEPT
		iptables -I OUTPUT -m state --state NEW -m udp -p udp --dport 23333 -j ACCEPT
			service iptables save
			service iptables restart
		elif centosversion 7; then
			firewall-cmd --zone=public --add-port=23333/tcp --permanent
			firewall-cmd --zone=public --add-port=23333/udp --permanent
			firewall-cmd --reload
		fi
	fi
}

clean_filebrowser()
{
	cd ${cur_dir}
	cd filebrowser
	rm -rf linux-amd64-filebrowser.tar.gz
}


#----------------------------------------------------------------------------------------------------------------------------------------------------10. install rclone--------------------------------------------------------------------------------------------------------------------
install_rclone()
{
	cd ${cur_dir}
	wget --no-check-certificate https://downloads.rclone.org/v1.42/rclone-v1.42-linux-amd64.rpm
	rpm -ivh rclone-v1.42-linux-amd64.rpm
	rm -rf rclone-v1.42-linux-amd64.rpm
}

#----------------------------------------------------------------------------------------------------------------------------------------------------11. install 宝塔面板--------------------------------------------------------------------------------------------------------------------
install_bt()
{
	wget https://raw.githubusercontent.com/goomadao/auto_install/master/bt.sh
	chmod +x bt.sh
	./bt.sh
}

#----------------------------------------------------------------------------------------------------------------------------------------------------12. 下载nextcloud网页--------------------------------------------------------------------------------------------------------------------

download_nextcloud()
{
	cd /home/wwwroot
	wget https://download.nextcloud.com/server/releases/nextcloud-13.0.5.zip
	unzip nextcloud-13.0.5.zip
	rm -rf nextcloud-13.0.5.zip
}

#----------------------------------------------------------------------------------------------------------------------------------------------------13. 下载AriaNG网页--------------------------------------------------------------------------------------------------------------------

download_ariang()
{
	cd /home/wwwroot
	mkdir ariang
	cd ariang
	wget https://github.com/mayswind/AriaNg/releases/download/0.4.0/aria-ng-0.4.0.zip
	unzip aria-ng-0.4.0.zip
	rm -rf aria-ng-0.4.0.zip
}

#----------------------------------------------------------------------------------------------------------------------------------------------------14. 安装lnmp--------------------------------------------------------------------------------------------------------------------
install_lnmp()
{
	cd /root
	wget http://soft.vpser.net/lnmp/lnmp1.5.tar.gz
	tar xzvf lnmp1.5.tar.gz
	mv lnmp1.5 lnmp
	rm -rf lnmp1.5.tar.gz
	cd lnmp
	./install.sh lnmp
}

site_nginx()
{
	cd /usr/local/nginx/conf
	cat > nginx.conf <<EOF
user  www www;

worker_processes auto;

error_log  /home/wwwlogs/nginx_error.log  crit;

pid        /usr/local/nginx/logs/nginx.pid;

#Specifies the value for maximum file descriptors that can be opened by this process.
worker_rlimit_nofile 51200;

events
    {
        use epoll;
        worker_connections 51200;
        multi_accept on;
    }

http
    {
        include       mime.types;
        default_type  application/octet-stream;

        server_names_hash_bucket_size 128;
        client_header_buffer_size 32k;
        large_client_header_buffers 4 32k;
        client_max_body_size 50m;

        sendfile   on;
        tcp_nopush on;

        keepalive_timeout 60;

        tcp_nodelay on;

        fastcgi_connect_timeout 300;
        fastcgi_send_timeout 300;
        fastcgi_read_timeout 300;
        fastcgi_buffer_size 64k;
        fastcgi_buffers 4 64k;
        fastcgi_busy_buffers_size 128k;
        fastcgi_temp_file_write_size 256k;

        gzip on;
        gzip_min_length  1k;
        gzip_buffers     4 16k;
        gzip_http_version 1.1;
        gzip_comp_level 2;
        gzip_types     text/plain application/javascript application/x-javascript text/javascript text/css application/xml application/xml+rss;
        gzip_vary on;
        gzip_proxied   expired no-cache no-store private auth;
        gzip_disable   "MSIE [1-6]\.";

        #limit_conn_zone $binary_remote_addr zone=perip:10m;
        ##If enable limit_conn_zone,add "limit_conn perip 10;" to server section.

        server_tokens off;
        access_log off;


server {
    listen 80;
	listen [::]:80;
    server_name cloudt.madao.bid;
    location / {
        proxy_pass http://127.0.0.1:8000;
    }

	location /sync {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

server {
    listen 80;
	listen [::]:80;
    server_name file.madao.bid;
    location / {
        proxy_pass http://localhost:23333;
    }
}

server {
    listen 80;
	listen [::]:80;
    server_name luci.madao.bid;
    location / {
        proxy_pass http://localhost:1180;
    }
}

server
    {
        listen 80 default_server;
        listen [::]:80 default_server ipv6only=on;
        server_name nginx.madao.bid;
        index index.html index.htm index.php;
        root  /home/wwwroot/default;

        #error_page   404   /404.html;

        # Deny access to PHP files in specific directory
        #location ~ /(wp-content|uploads|wp-includes|images)/.*\.php$ { deny all; }

        include enable-php.conf;

        location /nginx_status
        {
            stub_status on;
            access_log   off;
        }

        location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$
        {
            expires      30d;
        }

        location ~ .*\.(js|css)?$
        {
            expires      12h;
        }

        location ~ /.well-known {
            allow all;
        }

        location ~ /\.
        {
            deny all;
        }

        access_log  /home/wwwlogs/access.log;
    }
include vhost/*.conf;
}
EOF
lnmp nginx restart


}



#----------------------------------------------------------------------------------------------------------------------------------------------------15. 安装frp反向代理--------------------------------------------------------------------------------------------------------------------
install_frp()
{
	cd /root
	wget https://github.com/fatedier/frp/releases/download/v0.21.0/frp_0.21.0_linux_amd64.tar.gz
	tar xzvf frp_0.21.0_linux_amd64.tar.gz
	rm -rf frp_0.21.0_linux_amd64.tar.gz
	mv frp_0.21.0_linux_amd64 frp
	cd frp
	cat > frps.ini <<EOF
[common]
bind_port = 7000
subdomain_host = frp.madao.bid
token = a95655890
EOF
	./frps -c frps.ini&

	set_frp_firewall
}

set_frp_firewall()
{
	if check_sys packageManager dnf; then
		iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 7000 -j ACCEPT
		iptables -I INPUT -m state --state NEW -m udp -p udp --dport 7000 -j ACCEPT
		iptables -I OUTPUT -m state --state NEW -m tcp -p tcp --dport 7000 -j ACCEPT
		iptables -I OUTPUT -m state --state NEW -m udp -p udp --dport 7000 -j ACCEPT
		service iptables save
		service iptables restart
	elif check_sys packageManager yum; then
		if centosversion 6; then
			iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 7000 -j ACCEPT
			iptables -I INPUT -m state --state NEW -m udp -p udp --dport 7000 -j ACCEPT
			iptables -I OUTPUT -m state --state NEW -m tcp -p tcp --dport 7000 -j ACCEPT
			iptables -I OUTPUT -m state --state NEW -m udp -p udp --dport 7000 -j ACCEPT
			service iptables save
			service iptables restart
		elif centosversion 7; then
			firewall-cmd --zone=public --add-port=7000/tcp --permanent
			firewall-cmd --zone=public --add-port=7000/udp --permanent
			firewall-cmd --reload
		fi
	fi
}

#----------------------------------------------------------------------------------------------------------------------------------------------------16. 配置MTProto Proxy--------------------------------------------------------------------------------------------------------------------
install_mtproxy()
{
	if check_sys packageManager yum; then
		yum -y update
		yum -y install openssl-devel zlib-devel
		yum -y groupinstall "Development Tools"
	elif check_sys packageManager dnf; then
		dnf -y update
		dnf -y install openssl-devel zlib-devel
		dnf -y groupinstall "Development Tools"
	elif check_sys packageManager apt; then
		apt-get -y update
		apt-get install git curl build-essential libssl-dev zlib1g-dev
	fi

	cd ${cur_dir}
	git clone https://github.com/TelegramMessenger/MTProxy
	cd MTProxy
	make
	cd objs/bin
	curl -s https://core.telegram.org/getProxySecret -o proxy-secret
	curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf
	./mtproto-proxy -u nobody -p 1026 -H 1025 -S 95655890956558909565589095655890 --aes-pwd proxy-secret proxy-multi.conf -M 5&


# 	cat > /etc/systemd/system/MTProxy.service <<EOF
# [Unit]
# Description=MTProxy
# After=network.target

# [Service]
# Type=simple
# WorkingDirectory=/root/MTProxy
# ExecStart=/root/MTProxy/objs/bin/mtproto-proxy -u nobody -p 1026 -H 1025 -S 95655890956558909565589095655890 --aes-pwd /root/MTProxy/objs/bin/proxy-secret /root/MTProxy/objs/bin/proxy-multi.conf -M 5
# Restart=on-failure

# [Install]
# WantedBy=multi-user.target
# EOF
# 	systemctl daemon-reload
# 	systemctl start MTProxy.service
# 	systemctl enable MTProxy.service

}

#----------------------------------------------------------------------------------------------------------------------------------------------------17. 配置虚拟内存--------------------------------------------------------------------------------------------------------------------
add_memory()
{
	#2G
	dd if=/dev/zero of=swapfile bs=1024000 count=2000
	mkswap swapfile
	chmod 600 swapfile
	swapon swapfile
}





usage()
{
	echo "Parameter list: -all (lnmp) | -ssr(start stop status restart) | -pip | -speedtest | -progress | -aria2(start) | -cloudt(start) | -filebrowser | -rclone | -bbr | -bt | -firewall | -lnmp | -nextcloud | -ariang | -mtproxy"
}

open_firewall()
{

	echo "ssr firewall set"
	firewall_set

	echo "cloud torrent firewall set"
	echo -e "${Info} 开始设置 iptables防火墙..."
	Set_iptables
	echo -e "${Info} 开始添加 iptables防火墙规则..."
	Add_iptables
	echo -e "${Info} 开始保存 iptables防火墙规则..."
	Save_iptables


	echo "file browser firewall set"
	set_filebrowser_firewall

	echo "frp firewall set"
	set_frp_firewall


}





if [ "$#" -eq 0 ];then
	usage
	exit 0
fi


case $1 in 
	-ssr )
		if [ "$#" -eq 1 ]; then
			install_ssr
		elif [ "$#" -eq 2 ]; then
			ssr_${2}
		fi
	;;
	
	-bbr )
		install_bbr
	;;
	
	-pip )
		install_pip
		upgrade_pip
	;;
	
	-speedtest )
		install_speedtest
	;;
	
	-progress )
		install_progress
	;;
	
	-aria2 )
		if [ "$#" -eq 1 ]; then
			install_aria2
		elif ["$#" -eq 2 ]; then
			${2}_aria2
		fi
	;;
	
	
	-cloudt )
		if [ "$#" -eq 1 ]; then
			Install_ct
		elif [ "$#" -eq 2 ]; then
			${2}_ct
		fi
	;;
	
	-start_cloudt )
		Start_ct
	;;
	
	-filebrowser )
		install_filebrowser
	;;
	
	-rclone )
		install_rclone
	;;

	-bt )
		install_bt
	;;

	-firewall )
		open_firewall
	;;

	-nextcloud )
		download_nextcloud
	;;

	-ariang )
		download_ariang
	;;

	-lnmp )
		install_lnmp
	;;

	-forwardport )
		site_nginx
	;;

	-frp )
		install_frp
	;;

	-mtproxy )
		install_mtproxy
	;;

	-memory )
		add_memory
	;;
	
	-all )



		if [ "$#" -eq 2 ];then
			install_lnmp
		fi



		#install_bt
		

		install_ssr
		install_mtproxy
		install_pip
		upgrade_pip
		install_speedtest
		install_progress
		install_aria2
		Install_ct
		install_filebrowser
		install_rclone
		install_frp
		

		download_nextcloud
		download_ariang
		
		
		
		install_bbr
	;;
	
	-* )
		echo "Wrong parameter!"
		usage
		;;
esac
