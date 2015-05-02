#!/bin/sh
#    Setup Simple IPSec/L2TP VPN server for Ubuntu and Debian
#
#    Copyright (C) 2014 Phil Plückthun <phil@plckthn.me>
#    Based on the work of Lin Song (Copyright 2014)
#    Based on the work of Viljo Viitanen (Setup Simple PPTP VPN server for Ubuntu and Debian)
#    Based on the work of Thomas Sarlandie (Copyright 2012)
#
#    This work is licensed under the Creative Commons Attribution-ShareAlike 3.0
#    Unported License: http://creativecommons.org/licenses/by-sa/3.0/

if [ `id -u` -ne 0 ]
then
  echo "请以root权限启动该脚本!"
  echo "再试一次使用sudo."
  exit 0
fi

lsb_release -c | grep trusty > /dev/null
if [ "$?" = "1" ]
then
  echo "这个脚本是要在Ubuntu 14.04上运行!"
  echo "是否要继续?"
  while true; do
    read -p "" yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit 0;;
        * ) echo "请用Yes or No回答 [y|n].";;
    esac
  done
  echo ""
fi

echo "这个脚本将安装一个 IPSec/L2TP VPN 服务器"
echo "是否继续?"

while true; do
  read -p "" yn
  case $yn in
      [Yy]* ) break;;
      [Nn]* ) exit 0;;
      * ) echo "请用 Yes or No 回答 [y|n].";;
  esac
done

echo ""

# Generate a random key
generateKey () {
  P1=`cat /dev/urandom | tr -cd abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789 | head -c 3`
  P2=`cat /dev/urandom | tr -cd abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789 | head -c 3`
  P3=`cat /dev/urandom | tr -cd abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789 | head -c 3`
  IPSEC_PSK="$P1$P2$P3"
}

echo "VPN需要建立一个私人 PSK key."
echo "你希望自己设置?"
echo "(否则会生成一个随机密钥)"
while true; do
  read -p "" yn
  case $yn in
      [Yy]* ) echo ""; echo "Enter your preferred key:"; read -p "" IPSEC_PSK; break;;
      [Nn]* ) generateKey; break;;
      * ) echo "请用 Yes or No 回答[y|n].";;
  esac
done

echo ""
echo "The key you chose is: '$IPSEC_PSK'."
echo "请记住它，因为你将会用到它来连接!"
echo ""

read -p "请输入你的VPN用户名: " VPN_USER

if [ "$VPN_USER" = "" ]
then
  VPN_USER="vpn"
fi

echo ""

while true; do
  stty_orig=`stty -g`
  stty -echo
  read -p "请输入密码: " VPN_PASSWORD
  if [ "x$VPN_PASSWORD" = "x" ]
  then
    echo "请输入有效密码!"
  else
    stty $stty_orig
    break
  fi
done

echo ""
echo ""

echo "Making sure that apt-get is updated and wget is installed..."

apt-get update > /dev/null

if [ `sudo dpkg-query -l | grep wget | wc -l` = 0 ] ; then
  apt-get install wget -y  > /dev/null
fi

PUBLICIP=`wget -q -O - http://wtfismyip.com/text`
if [ "x$PUBLICIP" = "x" ]
then
  echo "无法检测到您的服务器的外部IP地址！"
  echo "请输入你的服务IP:"
  read -p "" PUBLICIP
else
  echo "检测到您的服务器的外部IP地址: $PUBLICIP"
fi

PRIVATEIP=$(ip addr | awk '/inet/ && /eth0/{sub(/\/.*$/,"",$2); print $2}')
IPADDRESS=$PUBLICIP

echo ""
echo "你是在Amazon EC2上?"
echo "如果你回答没有这个，你是在EC2上，客户端将无法连接到您的VPN."
echo "这是必要的，因为EC2使您的实例背后一对一NAT，并且在配置使用公共IP导致传入连接失败."
while true; do
  read -p "" yn
  case $yn in
    [Yy]* ) IPADDRESS=$PRIVATEIP; break;;
    [Nn]* ) break;;
    * ) echo "请用 Yes or No 回答[y|n].";;
  esac
done

echo "将在配置中使用的IP地址是 $IPADDRESS"

echo ""
echo "============================================================"
echo ""

echo "安装必要的依赖......"

apt-get install libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev libgmp3-dev flex bison gcc make libunbound-dev libnss3-tools -y  > /dev/null

if [ "$?" = "1" ]
then
  echo "发生意外错误!"
  exit 0
fi

echo "安装XL2TPD ...."
apt-get install xl2tpd -y > /dev/null

if [ "$?" = "1" ]
then
  echo "发生意外错误!"
  exit 0
fi

# Compile and install Libreswan
mkdir -p /opt/src
cd /opt/src
echo "下载LibreSwan的源..."
wget -qO- https://download.libreswan.org/libreswan-3.12.tar.gz | tar xvz > /dev/null
cd libreswan-3.12
echo "编译LibreSwan..."
make programs > /dev/null
echo "安装 LibreSwan..."
make install > /dev/null

if [ "$?" = "1" ]
then
  echo "发生意外错误!"
  exit 0
fi

echo "准备配置文件中..."

cat > /etc/ipsec.conf <<EOF
version 2.0
config setup
  dumpdir=/var/run/pluto/
  nat_traversal=yes
  virtual_private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12,%v4:!192.168.42.0/24
  oe=off
  protostack=netkey
  nhelpers=0
  interfaces=%defaultroute
conn vpnpsk
  connaddrfamily=ipv4
  auto=add
  left=$IPADDRESS
  leftid=$IPADDRESS
  leftsubnet=$IPADDRESS/32
  leftnexthop=%defaultroute
  leftprotoport=17/1701
  rightprotoport=17/%any
  right=%any
  rightsubnetwithin=0.0.0.0/0
  forceencaps=yes
  authby=secret
  pfs=no
  type=transport
  auth=esp
  ike=3des-sha1,aes-sha1
  phase2alg=3des-sha1,aes-sha1
  rekey=no
  keyingtries=5
  dpddelay=30
  dpdtimeout=120
  dpdaction=clear
EOF

cat > /etc/ipsec.secrets <<EOF
$IPADDRESS  %any  : PSK "$IPSEC_PSK"
EOF

cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701
;debug avp = yes
;debug network = yes
;debug state = yes
;debug tunnel = yes
[lns default]
ip range = 192.168.42.10-192.168.42.250
local ip = 192.168.42.1
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
;ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

cat > /etc/ppp/options.xl2tpd <<EOF
ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 8.8.4.4
noccp
auth
crtscts
idle 1800
mtu 1280
mru 1280
lock
lcp-echo-failure 10
lcp-echo-interval 60
connect-delay 5000
EOF

cat > /etc/ppp/chap-secrets <<EOF
# Secrets for authentication using CHAP
# client  server  secret  IP addresses
$VPN_USER  l2tpd  $VPN_PASSWORD  *
EOF

/bin/cp -f /etc/rc.local /etc/rc.local.old
cat > /etc/rc.local <<EOF
#!/bin/sh -e
#
# rc.local
#
# 这个脚本是在每个多用户运行级别结束时执行.
# 确保脚本将成功或任何其他 "exit 0" 或任何其他
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# 默认情况下这个脚本不做任何事.
iptables --table nat --append POSTROUTING --jump MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward
for each in /proc/sys/net/ipv4/conf/*
do
  echo 0 > $each/accept_redirects
  echo 0 > $each/send_redirects
done
/usr/sbin/service ipsec restart
/usr/sbin/service xl2tpd restart
EOF

echo "应用更改..."

iptables --table nat --append POSTROUTING --jump MASQUERADE > /dev/null
echo 1 > /proc/sys/net/ipv4/ip_forward
for each in /proc/sys/net/ipv4/conf/*
do
  echo 0 > $each/accept_redirects
  echo 0 > $each/send_redirects
done

if [ ! -f /etc/ipsec.d/cert8.db ] ; then
   echo > /var/tmp/libreswan-nss-pwd
   /usr/bin/certutil -N -f /var/tmp/libreswan-nss-pwd -d /etc/ipsec.d > /dev/null
   /bin/rm -f /var/tmp/libreswan-nss-pwd
fi

/sbin/sysctl -p > /dev/null

echo "Starting IPSec and XL2TP services..."

/usr/sbin/service ipsec restart > /dev/null
/usr/sbin/service xl2tpd restart > /dev/null

echo "成功!"
echo ""

clear

echo "============================================================"
echo "Host: $PUBLICIP (Or a domain pointing to your server)"
echo "IPSec PSK Key: $IPSEC_PSK"
echo "Username: $VPN_USER"
echo "Password: ********"
echo "============================================================"

echo "你的VPN服务器的密码是隐藏的。你想显示它吗?"
while true; do
  read -p "" yn
  case $yn in
      [Yy]* ) clear; break;;
      [Nn]* ) exit 0;;
      * ) echo "请用 Yes or No 回答[y|n].";;
  esac
done

echo "============================================================"
echo "Host: $PUBLICIP (Or a domain pointing to your server)"
echo "IPSec PSK Key: $IPSEC_PSK"
echo "Username: $VPN_USER"
echo "Password: $VPN_PASSWORD"
echo "============================================================"

echo "如果你打算保持这一脚本生成在互联网上使用很长一段时间（一天或更长时间），那么它可能会受到攻击!"

sleep 1
exit 0
