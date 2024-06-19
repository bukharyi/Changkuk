#!/usr/bin/env bash

ORISOCKFILE="/var/run/docker/plugins/policy-changkuk.sock"
TIPUSOCKFILE="/var/run/docker/plugins/tipu-policy-changkuk.sock"
if [ -a "$SOCKFILE" ];
then
    echo "Old sock file found."
    echo "Removing old sock file.."
    rm $SOCKFILE
fi
echo "Listening to Conversation socat....."
socat -v -t9000000000000000000000 UNIX-LISTEN:$TIPUSOCKFILE UNIX-CONNECT:$ORISOCKFILE
