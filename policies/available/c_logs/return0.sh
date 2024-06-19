#! /bin/bash
PROGNAME=$(basename $0)
docker ps -a > output.txt
#sleep 1 
echo "allow:true,msg:$PROGNAME program $@"
exit 0 


