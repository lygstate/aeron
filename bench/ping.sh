cd /home/aeron/binaries
pkill Ping
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD

./Ping -c "aeron:udp?control=239.255.0.1:40456|control-mode=dynamic" -C "aeron:udp?control=239.255.0.1:40456|control-mode=dynamic" -L 1024 -w 10000 -m 100000

./Ping -c "aeron:udp?endpoint=224.0.1.1:40456:40456|interface=192.168.199.1/24" -C "aeron:udp?endpoint=224.0.1.1:40456|interface=192.168.199.1/24"


cd /d E:\CI-Cor-Ready\xemu-rpc\aeron\build-cmake\Debug\binaries
Ping -c "aeron:udp?endpoint=224.0.1.1:40456|interface=192.168.199.1/24" -C "aeron:udp?endpoint=224.0.1.1:40456|interface=192.168.199.1/24"
