cd /home/aeron/binaries
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD
./StreamingPublisher -c "aeron:udp?control=239.255.0.1:40456|control-mode=dynamic|interface=192.168.199.0/24" -m 10000000 -L 1024
./RateSubscriber -c "aeron:udp?control=239.255.0.1:40456|control-mode=dynamic|interface=192.168.199.0/24"

./StreamingPublisher -c "aeron:udp?endpoint=239.255.0.1:40456|interface=192.168.199.0/24" -m 10000000 -L 1024
./RateSubscriber -c "aeron:udp?endpoint=239.255.0.1:40456|interface=192.168.199.0/24"


# ./Pong -c "aeron:udp?control=224.0.1.1:40456|control-mode=dynamic" -C "aeron:udp?control=224.0.1.1:40456|control-mode=dynamic"

# ./Pong -c "aeron:udp?endpoint=224.0.1.1:40456|ttl=16" -C "aeron:udp?endpoint=224.0.1.1:40456|ttl=16"
 ./streaming_publisher -c aeron:udp?endpoint=192.168.199.1:20121  -m 10000000000
 
 
 ./StreamingPublisher -c "aeron:udp?control=atos:40456|control-mode=dynamic" -m 1000000000000 -L 1024
./RateSubscriber -c "aeron:udp?control=atos:40456|control-mode=dynamic"


cd /d "E:\CI-Cor-Ready\xemu-rpc\aeron\build-cmake\Debug\binaries"
StreamingPublisher -c "aeron:udp?control=224.0.1.1:40456|control-mode=dynamic" -m 10000000 -L 1024
StreamingPublisher -c "aeron:udp?endpoint=224.0.1.1:40456|interface=192.168.199.0/24" -m 10000000 -L 1024