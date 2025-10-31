#!/bin/bash
  
# set -x
set -e
# 创建局域网的网桥
ip link add brlan1 type bridge
ip link set dev brlan1 up
iptables -A FORWARD -o brlan1 -m comment --comment "allow packets to pass from lxd lan bridge" -j ACCEPT
iptables -A FORWARD -i brlan1 -m comment --comment "allow input packets to pass to lxd lan bridge" -j ACCEPT
  
ip link add brlan2 type bridge
ip link set dev brlan2 up
iptables -A FORWARD -o brlan2 -m comment --comment "allow packets to pass from lxd lan bridge" -j ACCEPT
iptables -A FORWARD -i brlan2 -m comment --comment "allow input packets to pass to lxd lan bridge" -j ACCEPT
  
# 创建广域网的网桥
ip link add brwan type bridge
ip link set dev brwan up
iptables -A FORWARD -o brwan -m comment --comment "allow packets to pass from lxd wan bridge" -j ACCEPT
iptables -A FORWARD -i brwan -m comment --comment "allow input packets to pass to lxd wan bridge" -j ACCEPT
  
# 创建内网主机Host A,多网卡
ip netns add nsa
ip netns exec nsa ip link set lo up
  
function create_new(){
    devpair=$1  # aveth0
    devbr=$2    # brlan1
    virtnet=$3  # nsa
    devhost=$4  # eth0
    devaddr=$5  # 192.168.0.98
    gateway=$6  # 192.168.0.1
    routemap=$7 # 101
 
    dveth0=$devpair"0"
    dveth1=$devpair"1"
 
    ip link add $dveth0 type veth peer name $dveth1
      
    ip link set dev $dveth1 master $devbr
    ip link set dev $dveth1 up
      
    ip link set dev $dveth0 netns $virtnet
    ip netns exec $virtnet ip link set dev $dveth0 name $devhost
    ip netns exec $virtnet ip addr add $devaddr/24 dev $devhost
    ip netns exec $virtnet ip link set dev $devhost up
    ip netns exec $virtnet ip route add default via $gateway dev $devhost src $devaddr table $routemap
    ip netns exec $virtnet ip rule add from $devaddr table $routemap
}
 
create_new "aveth0" "brlan1" "nsa" "eth0" "192.168.0.98" "192.168.0.1" "101"
create_new "aveth1" "brlan1" "nsa" "eth1" "192.168.0.96" "192.168.0.1" "102"
create_new "aveth2" "brlan1" "nsa" "eth2" "192.168.0.88" "192.168.0.1" "103"
create_new "aveth3" "brlan1" "nsa" "eth3" "192.168.0.86" "192.168.0.1" "104"
create_new "aveth4" "brlan1" "nsa" "eth4" "192.168.0.84" "192.168.0.1" "105"
 
# Open Internel, FullCone
create_new "aveth5" "brwan" "nsa" "eth5" "10.10.0.108" "10.10.0.1" "201"
# Open Internel, RestrictedCone
create_new "aveth6" "brwan" "nsa" "eth6" "10.10.0.106" "10.10.0.1" "202"
# Open Internet,PortRestrictedCone
create_new "aveth7" "brwan" "nsa" "eth7" "10.10.0.104" "10.10.0.1" "203"
# Open Internet,UDPBlocked
create_new "aveth8" "brwan" "nsa" "eth8" "10.10.0.102" "10.10.0.1" "204"
 
create_new "aveth9" "brlan2" "nsa" "eth9" "172.16.0.48" "172.16.0.1" "301"
create_new "avetha" "brlan2" "nsa" "etha" "172.16.0.46" "172.16.0.1" "302"
create_new "avethb" "brlan2" "nsa" "ethb" "172.16.0.38" "172.16.0.1" "303"
create_new "avethc" "brlan2" "nsa" "ethc" "172.16.0.36" "172.16.0.1" "304"
create_new "avethd" "brlan2" "nsa" "ethd" "172.16.0.34" "172.16.0.1" "305"
  
ip netns exec nsa ip route add default via 192.168.0.1
  
ip netns exec nsa iptables -t filter -P OUTPUT DROP
ip netns exec nsa iptables -t filter -P INPUT DROP
ip netns exec nsa iptables -t filter -A OUTPUT ! -p udp -j ACCEPT
ip netns exec nsa iptables -t filter -A INPUT ! -p udp -j ACCEPT
# eth0:192.168.0.98, NAT, FullCone
ip netns exec nsa iptables -t filter -A OUTPUT -p udp -o eth0 -j ACCEPT
ip netns exec nsa iptables -t filter -A INPUT -p udp -i eth0 -j ACCEPT
# eth1:192.168.0.96, NAT, RestrictedCone
ip netns exec nsa iptables -t filter -A OUTPUT -p udp -o eth1 -m recent --rdest --set --name pubtrack1 -j ACCEPT
ip netns exec nsa iptables -t filter -A INPUT -p udp -i eth1 -m recent --rsource --rcheck --seconds 300 --name pubtrack1 -j ACCEPT
# eth2:192.168.0.88, NAT, PortRestrictedCone
ip netns exec nsa iptables -t filter -A OUTPUT -p udp -o eth2 -j ACCEPT
ip netns exec nsa iptables -t filter -A INPUT -p udp -i eth2 -m state --state ESTABLISHED,RELATED -j ACCEPT
# eth3:192.168.0.86, NAT, Dynamic
ip netns exec nsa iptables -t filter -A OUTPUT -p udp -o eth3 -j ACCEPT
ip netns exec nsa iptables -t filter -A INPUT -p udp -i eth3 -m state --state ESTABLISHED,RELATED -j ACCEPT
# eth4:192.168.0.84, NAT, Symmetric
ip netns exec nsa iptables -t filter -A OUTPUT -p udp -o eth4 -j ACCEPT
ip netns exec nsa iptables -t filter -A INPUT -p udp -i eth4 -m state --state ESTABLISHED,RELATED -j ACCEPT
# eth5:10.10.0.108，Open Internet，FullCone
ip netns exec nsa iptables -t filter -A OUTPUT -p udp -o eth5 -j ACCEPT
ip netns exec nsa iptables -t filter -A INPUT -p udp -i eth5 -j ACCEPT
# eth6:10.10.0.106，Open Internet，RestrictedCone
ip netns exec nsa iptables -t filter -A OUTPUT -p udp -o eth6 -m recent --rdest --set --name pubtrack6 -j ACCEPT
ip netns exec nsa iptables -t filter -A INPUT -p udp -i eth6 -m recent --rsource --rcheck --seconds 300 --name pubtrack6 -j ACCEPT
# eth7:10.10.0.104，Open Internet，PortRestrictedCone
ip netns exec nsa iptables -t filter -A OUTPUT -p udp -o eth7 -j ACCEPT
ip netns exec nsa iptables -t filter -A INPUT -p udp -i eth7 -m state --state ESTABLISHED,RELATED -j ACCEPT
# eth8:10.10.0.102, OpenInternel, UDPBlocked
# default rule DROP
# eth9:172.16.0.48, NAT, FullCone
ip netns exec nsa iptables -t filter -A OUTPUT -p udp -o eth9 -j ACCEPT
ip netns exec nsa iptables -t filter -A INPUT -p udp -i eth9 -j ACCEPT
# etha:172.16.0.46, NAT, RestrictedCone
ip netns exec nsa iptables -t filter -A OUTPUT -p udp -o etha -m recent --rdest --set --name pubtrack1 -j ACCEPT
ip netns exec nsa iptables -t filter -A INPUT -p udp -i etha -m recent --rsource --rcheck --seconds 300 --name pubtrack1 -j ACCEPT
# ethb:172.16.0.38, NAT, PortRestrictedCone
ip netns exec nsa iptables -t filter -A OUTPUT -p udp -o ethb -j ACCEPT
ip netns exec nsa iptables -t filter -A INPUT -p udp -i ethb -m state --state ESTABLISHED,RELATED -j ACCEPT
# ethc:172.16.0.36, NAT, Dynamic
ip netns exec nsa iptables -t filter -A OUTPUT -p udp -o ethc -j ACCEPT
ip netns exec nsa iptables -t filter -A INPUT -p udp -i ethc -m state --state ESTABLISHED,RELATED -j ACCEPT
# ethd:172.16.0.34, NAT, Symmetric
ip netns exec nsa iptables -t filter -A OUTPUT -p udp -o ethd -j ACCEPT
ip netns exec nsa iptables -t filter -A INPUT -p udp -i ethd -m state --state ESTABLISHED,RELATED -j ACCEPT
  
# 创建内网主机B
ip netns add nsb
ip netns exec nsb ip link set lo up
  
ip link add bveth0 type veth peer name bveth1
  
ip link set dev bveth1 master brlan1
ip link set dev bveth1 up
  
ip link set dev bveth0 netns nsb
ip netns exec nsb ip link set dev bveth0 name eth0
ip netns exec nsb ip addr add 192.168.0.100/24 dev eth0
ip netns exec nsb ip link set dev eth0 up
ip netns exec nsb ip route add 192.168.0.1 dev eth0
ip netns exec nsb ip route add default via 192.168.0.1
  
# 创建外网主机Host O
ip netns add nso
ip netns exec nso ip link set lo up
  
ip link add oveth00 type veth peer name oveth01
  
ip link set oveth00 netns nso
ip netns exec nso ip link set dev oveth00 name eth0
ip netns exec nso ip addr add 192.168.0.1/24 dev eth0
ip netns exec nso ip link set dev eth0 up
ip netns exec nso ip rule add from 192.168.0.1/24 dev eth0
ip netns exec nso sysctl -w net.ipv4.conf.eth0.proxy_arp=1
  
ip link set dev oveth01 master brlan1
ip link set dev oveth01 up
  
ip link add oveth10 type veth peer name oveth11
  
ip link set oveth10 netns nso
ip netns exec nso ip link set dev oveth10 name eth1
# ip netns exec nso ip addr add 10.10.0.1/24 dev eth1
ip netns exec nso ip addr add 10.10.0.98/24 dev eth1
ip netns exec nso ip addr add 10.10.0.96/24 dev eth1
ip netns exec nso ip addr add 10.10.0.88/24 dev eth1
ip netns exec nso ip addr add 10.10.0.86/24 dev eth1
ip netns exec nso ip addr add 10.10.0.84/24 dev eth1
ip netns exec nso ip link set dev eth1 up
ip netns exec nso ip route add default dev eth1
  
ip link set dev oveth11 master brwan
ip link set dev oveth11 up
  
ip netns exec nso iptables -A FORWARD -j LOG --log-prefix "FORWARD:" --log-level 3
ip netns exec nso iptables -t nat -A PREROUTING -j LOG --log-prefix "DNAT:" --log-level 3
ip netns exec nso iptables -t nat -A POSTROUTING -j LOG --log-prefix "SNAT:" --log-level 3
  
# 192.168.0.98 nat to 10.10.0.98, 许出许进，再通过HOST A中设计iptables规则可成为FullCone
ip netns exec nso iptables -t nat -A POSTROUTING -o eth1 -s 192.168.0.98 -d 10.10.0.1/24 -j SNAT --to-source 10.10.0.98
ip netns exec nso iptables -t nat -A PREROUTING -i eth1 -d 10.10.0.98 -s 10.10.0.1/24 -j DNAT --to-destination 192.168.0.98
# 192.168.0.96 nat to 10.10.0.96, 许出许进，确保映射地址无论如何不会变，再通过HOST A中设计iptables规则可成为RestrictedCone
ip netns exec nso iptables -t nat -A POSTROUTING -o eth1 -s 192.168.0.96 -d 10.10.0.1/24 -j SNAT --to-source 10.10.0.96
ip netns exec nso iptables -t nat -A PREROUTING -i eth1 -d 10.10.0.96 -s 10.10.0.1/24 -j DNAT --to-destination 192.168.0.96
# 192.168.0.88 nat to 10.10.0.88, 许出许进，确保映射地址无论如何不会变，再通过HOST A中设计iptables规则可成为PortRestrictedCone
ip netns exec nso iptables -t nat -A POSTROUTING -o eth1 -s 192.168.0.88 -d 10.10.0.1/24 -j SNAT --to-source 10.10.0.88
ip netns exec nso iptables -t nat -A PREROUTING -i eth1 -d 10.10.0.88 -s 10.10.0.1/24 -j DNAT --to-destination 192.168.0.88
# 192.168.0.86 nat to 10.10.0.86, 若是先进后出的，端口随机映射；否则只进行IP映射，可成为Dynamic
ip netns exec nso iptables -t nat -A PREROUTING -i eth1 -d 10.10.0.86 -s 10.10.0.1/24 -m recent --rsource --set --name strangers -j DNAT --to-destination 192.168.0.1  # 注意：故意DNAT到一个错误的地址
ip netns exec nso iptables -t nat -A POSTROUTING -o eth1 -s 192.168.0.86 -d 10.10.0.1/24 -m recent --rdest --rcheck --seconds 3600 --name strangers -j SNAT --to-source 10.10.0.86 --random
ip netns exec nso iptables -t nat -A POSTROUTING -o eth1 -s 192.168.0.86 -d 10.10.0.1/24 -j SNAT --to-source 10.10.0.86
# 192.168.0.84 nat to 10.10.0.84, 许出不许进，出的时候，端口随机映射，可成为Symmetric
ip netns exec nso iptables -t nat -A POSTROUTING -o eth1 -s 192.168.0.84 -d 10.10.0.1/24 -j SNAT --to-source 10.10.0.84 --random
  
# 创建外网主机Host N
ip netns add nsn
ip netns exec nsn ip link set lo up
  
ip link add nveth00 type veth peer name nveth01
  
ip link set nveth00 netns nsn
ip netns exec nsn ip link set dev nveth00 name eth0
ip netns exec nsn ip addr add 172.16.0.1/24 dev eth0
ip netns exec nsn ip link set dev eth0 up
ip netns exec nsn ip rule add from 172.16.0.1/24 dev eth0
ip netns exec nsn sysctl -w net.ipv4.conf.eth0.proxy_arp=1
  
ip link set dev nveth01 master brlan2
ip link set dev nveth01 up
  
ip link add nveth10 type veth peer name nveth11
  
ip link set nveth10 netns nsn
ip netns exec nsn ip link set dev nveth10 name eth1
# ip netns exec nsn ip addr add 10.10.0.2/24 dev eth1
ip netns exec nsn ip addr add 10.10.0.48/24 dev eth1
ip netns exec nsn ip addr add 10.10.0.46/24 dev eth1
ip netns exec nsn ip addr add 10.10.0.38/24 dev eth1
ip netns exec nsn ip addr add 10.10.0.36/24 dev eth1
ip netns exec nsn ip addr add 10.10.0.34/24 dev eth1
ip netns exec nsn ip link set dev eth1 up
ip netns exec nsn ip route add default dev eth1
  
ip link set dev nveth11 master brwan
ip link set dev nveth11 up
  
ip netns exec nsn iptables -A FORWARD -j LOG --log-prefix "FORWARD:" --log-level 3
ip netns exec nsn iptables -t nat -A PREROUTING -j LOG --log-prefix "DNAT:" --log-level 3
ip netns exec nsn iptables -t nat -A POSTROUTING -j LOG --log-prefix "SNAT:" --log-level 3
  
# 172.16.0.48 nat to 10.10.0.48, 许出许进，再通过HOST A中设计iptables规则可成为FullCone
ip netns exec nsn iptables -t nat -A POSTROUTING -o eth1 -s 172.16.0.48 -d 10.10.0.1/24 -j SNAT --to-source 10.10.0.48
ip netns exec nsn iptables -t nat -A PREROUTING -i eth1 -d 10.10.0.48 -s 10.10.0.1/24 -j DNAT --to-destination 172.16.0.48
# 172.16.0.46 nat to 10.10.0.46, 许出许进，确保映射地址无论如何不会变，再通过HOST A中设计iptables规则可成为RestrictedCone
ip netns exec nsn iptables -t nat -A POSTROUTING -o eth1 -s 172.16.0.46 -d 10.10.0.1/24 -j SNAT --to-source 10.10.0.46
ip netns exec nsn iptables -t nat -A PREROUTING -i eth1 -d 10.10.0.46 -s 10.10.0.1/24 -j DNAT --to-destination 172.16.0.46
# 172.16.0.38 nat to 10.10.0.38, 许出许进，确保映射地址无论如何不会变，再通过HOST A中设计iptables规则可成为PortRestrictedCone
ip netns exec nsn iptables -t nat -A POSTROUTING -o eth1 -s 172.16.0.38 -d 10.10.0.1/24 -j SNAT --to-source 10.10.0.38
ip netns exec nsn iptables -t nat -A PREROUTING -i eth1 -d 10.10.0.38 -s 10.10.0.1/24 -j DNAT --to-destination 172.16.0.38
# 172.16.0.36 nat to 10.10.0.36, 若是先进后出的，端口随机映射；否则只进行IP映射，可成为Dynamic
ip netns exec nsn iptables -t nat -A PREROUTING -i eth1 -d 10.10.0.36 -s 10.10.0.1/24 -m recent --rsource --set --name strangers -j DNAT --to-destination 172.16.0.1  # 注意：故意DNAT到一个错误的地址
ip netns exec nsn iptables -t nat -A POSTROUTING -o eth1 -s 172.16.0.36 -d 10.10.0.1/24 -m recent --rdest --rcheck --seconds 3600 --name strangers -j SNAT --to-source 10.10.0.36 --random
ip netns exec nsn iptables -t nat -A POSTROUTING -o eth1 -s 172.16.0.36 -d 10.10.0.1/24 -j SNAT --to-source 10.10.0.36
# 172.16.0.34 nat to 10.10.0.34, 许出不许进，出的时候，端口随机映射，可成为Symmetric
ip netns exec nsn iptables -t nat -A POSTROUTING -o eth1 -s 172.16.0.34 -d 10.10.0.1/24 -j SNAT --to-source 10.10.0.34 --random
  
# Host S
ip netns add nss
ip netns exec nss ip link set lo up
  
create_new "sveth0" "brwan" "nss" "eth0" "10.10.0.64" "10.10.0.1" "401"
create_new "sveth1" "brwan" "nss" "eth1" "10.10.0.66" "10.10.0.1" "402"
create_new "sveth2" "brwan" "nss" "eth2" "10.10.0.68" "10.10.0.1" "403"
  
# 创建内网主机H
ip netns add nshub
ip netns exec nshub ip link set lo up
 
ip link add hubveth0 type veth peer name hubveth1
 
ip link set dev hubveth1 master brwan
ip link set dev hubveth1 up
 
ip link set dev hubveth0 netns nshub
ip netns exec nshub ip link set dev hubveth0 name eth0
ip netns exec nshub ip addr add 10.10.0.1/24 dev eth0
ip netns exec nshub ip link set dev eth0 up
# ip netns exec nshub ip rule add from 10.10.0.1/24 dev eth0
ip netns exec nshub ip route add default dev eth0
