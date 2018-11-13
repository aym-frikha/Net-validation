#!/bin/bash -ex

apt update
apt install -y libprotobuf-dev  libqt4-dev-bin
wget http://192.168.110.23/drone -P /root/
chmod +x /root/drone
output=$(ifconfig -a | sed 's/[ \t].*//;/^\(lo\|\)$/d')
for x in $output; do sudo ip link set dev $x up; sudo ip link set dev $x mtu 9000 || true ; done;
screen -d -m /root/drone
sleep inf

