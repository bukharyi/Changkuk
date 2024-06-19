#! /bin/bash
PROGNAME=$(basename $0 )
MYDATE=`date`
POLICYPATH="/root/GolangProjects/src/github.com/bukharyi/policy2/policies/enable/c_create"
DEBUGFILE="/$POLICYPATH/argsdebug.txt"

echo "$MYDATE:- $@ "  >> $DEBUGFILE

argImage=`echo "\"$1\"" | sed 's/"//g'`
argPrivilege=$2
argBind=$3
argCapAdd=$4


privMsg=$(/bin/bash $POLICYPATH/privilegedchecker.sh "$argPrivilege")
privExitCode=$?

wlMsg=$(/bin/bash $POLICYPATH/imagewhitelist.sh "$argImage")
wlExitCode=$?

bindMsg=$(/bin/bash $POLICYPATH/bind.sh "$argBind")
bindExitCode=$?

entryPointMsg=$(/bin/bash $POLICYPATH/entrypoint.sh "$argImage")
entryPointExitCode=$?

capAddMsg=$(/bin/bash $POLICYPATH/capadd.sh "$argCapAdd")
capAddExitCode=$?

allMsg=$wlMsg" | "$privMsg" | "$bindMsg" | "$entryPointMsg" | "$capAddMsg

if [[ ( "$wlExitCode" -eq "0" )  &&  ( "$privExitCode" -eq "0" ) && ( "$bindExitCode" -eq "0"  ) && ( "$entryPointExitCode" -eq "0"  ) && ( "$capAddExitCode" -eq "0"  ) ]] ; then
    msg="allow:true,msg:"$allMsg
else
    msg="allow:false,msg:"$allMsg
fi

echo $msg
echo "---"$msg >> $DEBUGFILE
exit 0