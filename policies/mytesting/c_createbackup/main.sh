#! /bin/bash
PROGNAME=$(basename $0 )
PRIVILEGE="false"
MYDATE=`date`
DEBUGFILE="/root/GolangProjects/src/github.com/bukharyi/policy2/policies/enable/c_create/argsdebug.txt"

echo "$MYDATE:- $@ "  >> $DEBUGFILE

argsImage=`echo "\"$1\"" | sed 's/"//g'`
argsPrivilege=$2

privMsg=$(/bin/bash /root/GolangProjects/src/github.com/bukharyi/policy2/policies/enable/c_create/privilegedchecker.sh $argsPrivilege)
privExitCode=$?

wlMsg=$(/bin/bash /root/GolangProjects/src/github.com/bukharyi/policy2/policies/enable/c_create/imagewhitelist.sh $argsImage)
wlExitCode=$?
if [[ ( "$wlExitCode" -eq "0" )  &&  ( "$privExitCode" -eq "0" ) ]] ; then
    msg="allow:true,msg:"$wlMsg" | "$privMsg
    echo $msg
    echo "---"$msg >> $DEBUGFILE
    exit 0
else
    msg="allow:false,msg:"$wlMsg" | "$privMsg
    echo $msg
    echo "---"$msg >> $DEBUGFILE
    exit 0
fi

