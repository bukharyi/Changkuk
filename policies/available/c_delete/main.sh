#! /bin/bash
PROGNAME=$(basename $0 )
MYDATE=`date`
DEBUGFILE="/root/GolangProjects/src/github.com/bukharyi/policy2/policies/available/c_delete/argsdebug.txt"

echo "$MYDATE:- $@ "  >> $DEBUGFILE
argContainerId=$1
argForce=$2


        if [ "$argForce" == "1" ] ; then
		/usr/bin/python /root/GolangProjects/src/github.com/bukharyi/policy2/policies/available/c_delete/backup.py backup  $argContainerId &>/dev/null 
		/bin/mv $argContainerId.tar /backup

	fi
    echo "allow:true,msg:backup done"
    exit 0


