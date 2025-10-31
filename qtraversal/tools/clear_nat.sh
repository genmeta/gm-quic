#!/bin/bash
 
# set -x
set -e
  
ip netns exec nsa ip route flush table 101
ip netns exec nsa ip route flush table 102
ip netns exec nsa ip route flush table 103
ip netns exec nsa ip route flush table 104
ip netns exec nsa ip route flush table 105
ip netns exec nsa ip route flush table 201
ip netns exec nsa ip route flush table 202
ip netns exec nsa ip route flush table 203
ip netns exec nsa ip route flush table 204
ip netns exec nsa ip route flush table 301
ip netns exec nsa ip route flush table 302
ip netns exec nsa ip route flush table 303
ip netns exec nsa ip route flush table 304
ip netns exec nsa ip route flush table 305
ip netns exec nsa ip route flush cache
  
ip netns exec nss ip route flush table 401
ip netns exec nss ip route flush table 402
ip netns exec nss ip route flush table 403
ip netns exec nss ip route flush cache
  
ip netns del nsa
ip netns del nsb
ip netns del nso
ip netns del nss
ip netns del nsn
ip netns del nshub
  
ip link del brlan1
ip link del brlan2
ip link del brwan
  
iptables -D FORWARD -o brlan1 -m comment --comment "allow packets to pass from lxd lan bridge" -j ACCEPT
iptables -D FORWARD -i brlan1 -m comment --comment "allow input packets to pass to lxd lan bridge" -j ACCEPT
  
iptables -D FORWARD -o brlan2 -m comment --comment "allow packets to pass from lxd lan bridge" -j ACCEPT
iptables -D FORWARD -i brlan2 -m comment --comment "allow input packets to pass to lxd lan bridge" -j ACCEPT
  
iptables -D FORWARD -o brwan -m comment --comment "allow packets to pass from lxd wan bridge" -j ACCEPT
iptables -D FORWARD -i brwan -m comment --comment "allow input packets to pass to lxd wan bridge" -j ACCEPT
  
# ip link del aveth1
# ip link del bveth1
# ip link del oveth1
