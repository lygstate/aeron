cd /home/aeron/binaries
pkill ServiceDiscovery
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD


./ServiceDiscovery -c "aeron:udp?endpoint=239.255.0.1:40456|interface=192.168.192.1/18|term-length=65536"


cd /d E:\CI-Cor-Ready\xemu-rpc\aeron\build-cmake\Debug\binaries

ServiceDiscovery -c "aeron:udp?endpoint=239.255.0.1:40456|interface=192.168.192.1/18|term-length=65536"
