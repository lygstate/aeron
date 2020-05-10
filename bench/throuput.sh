cd /home/aeron/binaries
pkill Pong
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD

./Pong -c "aeron:udp?control=224.0.1.1:40456|control-mode=dynamic" -C "aeron:udp?control=224.0.1.1:40456|control-mode=dynamic"

# ./Pong -c "aeron:udp?endpoint=224.0.1.1:40456|ttl=16" -C "aeron:udp?endpoint=224.0.1.1:40456|ttl=16"
