#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

os='ossystem'
password='a95655890'
port='1024'

libsodium_file="libsodium-1.0.16"
libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz"

shadowsocks_r_file="shadowsocksr-3.2.2"
shadowsocks_r_url="https://github.com/shadowsocksrr/shadowsocksr/archive/3.2.2.tar.gz"

DIR=`pwd`

cur_dir=`pwd`







# Make sure only root can run our script
[[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] This script must be run as root!" && exit 1

#--------------------------------------------------------------------------------------------------------------------------------------1. Install ShadowsocksR--------------------------------------------------------------------------------------------------------------------


NAME=ShadowsocksR
DAEMON=/usr/local/shadowsocks/local.py
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
        exit 0
    else
        $DAEMON -c $CONF -d start
        RETVAL=$?
        if [ $RETVAL -eq 0 ]; then
            echo "Starting $NAME success"
			exit 0
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
			exit 0
        else
            echo "Stopping $NAME failed"
			exit 1
        fi
    else
        echo "$NAME is stopped"
        RETVAL=1
		exit 1
    fi
}

ssr_status(){
    check_running
    if [ $? -eq 0 ]; then
        echo "$NAME (pid $PID) is running..."
		exit 0
    else
        echo "$NAME is stopped"
        RETVAL=1
		exit 1
    fi
}

ssr_restart(){
    do_stop
    sleep 0.5
    do_start
	exit 0
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
			echo -e "[${red}Error${plain}]不支持CentOs5,请将系统换为CentOs 6+/Ubuntu 12+/Debian 7+并重试"
			exit 1
		fi
	else
		echo -e "[${red}Error${plain}]不支持你的系统,请将系统换为CentOs 6+/Ubuntu 12+/Debian 7+并重试"
		exit 1
	fi
	
	shadowsockspwd=${password}
	shadowsocksport=$port
	shadowsockscipher="aes-256-cfv"
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
	"server":"107.191.39.5",
	"server_ipv6":"[::]",
	"server_port":${shadowsocksport},
	"local_address":"127.0.0.1",
	"local_port":1080,
	"password":"${shadowsockspwd}",
	"timeout":120,
	"method":"aes-256-cfb",
	"protocol":"origin",
	"protocol_param":"",
	"obfs":"plain",
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
	
	if check_sys packageManager yum && centosversion 6; then
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
	elif check_sys packageManager dnf || check_sys packageManager yum && centosversion 7; then
		systemctl status firewalld > /dev/null 2>&1
		if [ $? -eq 0 ]; then
			firewall-cmd --zone=public --add-port=${shadowsocksport}/tcp --permanent
			firewall-cmd --zone=public --add-port=${shadowsocksport}/udp --permanent
			firewall-cmd --reload
		else
			echo -e "[${yellow}Warning${plain}] iptables looks like shutdown or not installed, please manually set it if necessary."
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
		exit 1
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

#----------------------------------------------------------------------------------------------------------------------------------------------------6. install chromium--------------------------------------------------------------------------------------------------------------------
install_chromium()
{
	cd /etc/yum.repos.d
	wget http://people.centos.org/hughesjr/chromium/6/chromium-el6.repo
	if check_sys packageManager yum; then
		yum -y install chromium
	elif check_sys packageManager dnf; then
		dnf -y install chromium
	fi

}

#----------------------------------------------------------------------------------------------------------------------------------------------------7. install notepadqq--------------------------------------------------------------------------------------------------------------------
install_notepadqq()
{
	wget -O /etc/yum.repos.d/sea-devel.repo http://sea.fedorapeople.org/sea-devel.repo
	if check_sys packageManager yum; then
		yum install -y qt5-qtbase-devel qt5-qttools-devel qt5-qtwebkit-devel qt5-qtsvg-devel
		yum install -y notepadqq
	elif check_sys packageManager dnf; then
		dnf install -y qt5-qtbase-devel qt5-qttools-devel qt5-qtwebkit-devel qt5-qtsvg-devel
		dnf install -y notepadqq
	fi
}

#----------------------------------------------------------------------------------------------------------------------------------------------------8. install rclone--------------------------------------------------------------------------------------------------------------------
install_rclone()
{
	cd ${cur_dir}
	wget --no-check-certificate https://downloads.rclone.org/v1.42/rclone-v1.42-linux-amd64.rpm
	rpm -ivh rclone-v1.42-linux-amd64.rpm
	rm -rf rclone-v1.42-linux-amd64.rpm
}

#----------------------------------------------------------------------------------------------------------------------------------------------------9. upgrade kernel--------------------------------------------------------------------------------------------------------------------
kernel_upgrade()
{
	#if check_sys packageManager dnf; then
		#return
	#fi
	rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
	rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-3.el7.elrepo.noarch.rpm
	yum --enablerepo=elrepo-kernel install kernel-ml
}

#----------------------------------------------------------------------------------------------------------------------------------------------------10. install vscode--------------------------------------------------------------------------------------------------------------------
install_vscode()
{
	rpm --import https://packages.microsoft.com/keys/microsoft.asc
	sh -c 'echo -e "[code]\nname=Visual Studio Code\nbaseurl=https://packages.microsoft.com/yumrepos/vscode\nenabled=1\ngpgcheck=1\ngpgkey=https://packages.microsoft.com/keys/microsoft.asc" > /etc/yum.repos.d/vscode.repo'
	if packageManager dnf; then
		dnf install code -y
	elif packageManager yum; then
		yum install code -y
	fi
}






usage()
{
	echo "Parameter list: -chromium | -notepadqq | -ssr(start stop status restart) | -pip | -speedtest | -progress | -rclone"
}



if [ $# -eq 0 ]; then
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
	
	-chromium )
		install_chrome
	;;
	
	-notepadqq )
		install_notepadqq
	;;
	
	-rclone )
		install_rclone
	;;
	
	-kernel )
		kernel_upgrade
	;;

	-vscode )
		install_vscode
	;;
	
	-all )
	
		install_ssr
		install_pip
		upgrade_pip
		install_speedtest
		install_progress
		install_chromium
		install_notepadqq
		install_rclone
		kernel_upgrade
		install_vscode
	;;
	
	* )
		usage
		exit 0
	
esac
