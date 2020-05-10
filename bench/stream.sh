cd /home/aeron/binaries
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD
./StreamingPublisher -c "aeron:udp?endpoint=224.0.1.1:40456|interface=192.168.199.0/24" -m 1000000000000 -L 1024

# ./Pong -c "aeron:udp?control=224.0.1.1:40456|control-mode=dynamic" -C "aeron:udp?control=224.0.1.1:40456|control-mode=dynamic"

# ./Pong -c "aeron:udp?endpoint=224.0.1.1:40456|ttl=16" -C "aeron:udp?endpoint=224.0.1.1:40456|ttl=16"
