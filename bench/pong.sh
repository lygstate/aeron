cd /home/aeron/binaries
pkill Pong
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD

./Pong -c "aeron:udp?control=239.255.0.1:40456|control-mode=dynamic" -C "aeron:udp?control=239.255.0.1:40456|control-mode=dynamic"


./Pong -c "aeron:udp?endpoint=224.0.1.1:40456|interface=192.168.199.1/24" -C "aeron:udp?endpoint=224.0.1.1:40456|interface=192.168.199.1/24"



cd /d E:\CI-Cor-Ready\xemu-rpc\aeron\build-cmake\Debug\binaries
Pong -c "aeron:udp?endpoint=224.0.1.1:40456|interface=192.168.199.1/24" -C "aeron:udp?endpoint=224.0.1.1:40456|interface=192.168.199.1/24"
