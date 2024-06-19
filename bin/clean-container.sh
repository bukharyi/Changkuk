docker ps -a | awk '{ print $1 }'| while read LINE; do docker rm -f $LINE; done
