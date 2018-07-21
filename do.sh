#! bin/bash

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

kernel_ubuntu_url="http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.10.2/linux-image-4.10.2-041002-generic_4.10.2-041002.201703120131_amd64.deb"
kernel_ubuntu_file="linux-image-4.10.2-041002-generic_4.10.2-041002.201703120131_amd64.deb"

DIR=`pwd`

cur_dir=`pwd`

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
install_ssr(){
    disable_selinux
    pre_install
    download_files
    config_shadowsocks
    if check_sys packageManager yum; then
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
	if check_sys packageManager yum || check_sys packageManager apt; then
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
	shadowsockscipher=${cipher[1]}
	shadowsocksprotocol=${protocols[0]}
	shadowsocksobfs=${obfs[0]}
	
	if check_sys packageManager yum; then
		yum -y update
		yum -y install python python-devel python-setuptools openssl openssl-devel curl wget unzip gcc automake autoconf make libtool
	elif check_sys packageManager apt; then
		apt-get -y update
		apt-get -y install python python-dev python-setuptools openssl libssl-dev curl wget unzip gcc automake autoconf make libtool
		
	cd ${cur_dir}
}

check_sys()
{
	local checkType=$1
	local value=$2
	
	local release=""
	local systemPackage=""
	
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
		systemPackage="yum"
	elif grep -Eqi "debian" /etc/issue; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /etc/issue; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian" /proc/version; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /proc/version; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /proc/version; then
        release="centos"
        systemPackage="yum"
    fi
	
	if [[ "${checkType}" == "sysRelease" ]]; then
		if [[ "${value}" == "${release}" ]]; then
			return 0
		else
			return 1
		fi
	elif [["${checkType}" == "packageManager" ]]; then
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
	elif [[ -s /etc/issue]]; then
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
    if check_sys packageManager yum; then
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



case $1 in 
	-ssr )
		install_ssr
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
	
	* )
		install_ssr
		install_pip
		upgrade_pip
		install_speedtest
		install_progress
		install_bbr
	;;
esac