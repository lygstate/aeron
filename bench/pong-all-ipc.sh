#!/bin/bash
cd /home/aeron/binaries
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD

for (( i=1000; i< 1200; i++ ))
do
   export IS_UDP=false
   export IS_PING=false
   export PING_STREAM_ID=$i
   export PING_STREAM_COUNT=200
   echo "Pong $PING_STREAM_ID"
   ./Bench > pong_$i.log &
done
