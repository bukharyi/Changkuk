#! /bin/bash
PROGNAME=$(basename $0)
echo $@ > "/root/GolangProjects/src/github.com/bukharyi/policy2/policies/enable/container_start/args.txt"
sleep 1 
echo "allow:true,msg:$PROGNAME program $@"
exit 0 


