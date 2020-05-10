#!/bin/bash
cd /home/aeron/binaries
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD
export IS_UDP=false
export IS_PING=true
export PING_STREAM_ID=1000
export PING_STREAM_COUNT=200
./Bench >ping_$PING_STREAM_ID.log &
