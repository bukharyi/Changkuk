#!/bin/bash
_argsPrivilege=$1
PRIVILEGE="false"

if [ $_argsPrivilege == $PRIVILEGE ] ; then
	echo "PRIVILEGE=$_argsPrivilege PASS"
	exit 0
fi
#OTHER THAN THAT
echo "PRIVILEGE=$_argsPrivilege DENIED"
exit -1
