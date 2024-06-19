#! /bin/bash

PRIVREGISTRY="10.1.70.70:443"
#PRIVREGISTRY='10.1.70.70:443'
DEBUGFILE="/root/GolangProjects/src/github.com/bukharyi/policy2/policies/available/i_create/argsdebug.txt"
#_fromImage="10.1.70.70:443/ubuntu:latest"
_fromImage=$1

echo `date` " :- $@ "  >> $DEBUGFILE
#IFVALID PRIV REGISTRY
if [[ $_fromImage =~ $PRIVREGISTRY ]] ; then
    echo "allow:true,msg:valid private registry $PRIVREGISTRY"
	exit 0
fi
#OTHER THAN THAT
    echo "allow:false,msg:DENIED docker pull except from $PRIVREGISTRY"
    exit 0
