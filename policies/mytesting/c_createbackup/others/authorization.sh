#! /bin/bash
PROGNAME=$(basename $0 )
PRIVILEGE="false"
MYDATE=`date`
echo "$MYDATE:- $@ "  >> "/root/GolangProjects/src/github.com/bukharyi/policy2/policies/enable/container_create/argsdebug.txt"

argsImage=`echo "\"$1\"" | sed 's/"//g'`
argsPrivilege=$2
imageList=('haproxy' 'cirros' '8bea5daaf8bb')
for image in "${imageList[@]}"
do
	if [ $argsImage == $image ] ; then
		if [ $argsPrivilege == $PRIVILEGE ] ; then
			msg="allow:true,msg:$argsImage and privilege=false allowed"
			echo "---" $msg >> "/root/GolangProjects/src/github.com/bukharyi/policy2/policies/enable/container_create/argsdebug.txt"
			echo $msg
			exit 0
		else
			msg="allow:false,msg:cannot run in privileged mode"
			 echo "---" $msg >>"/root/GolangProjects/src/github.com/bukharyi/policy2/policies/enable/container_create/argsdebug.txt"
			echo $msg
			exit 0
		fi
    fi
done

		msg="allow:false,msg:image=$argsImage is not allowed"
		echo "---" $msg >> "/root/GolangProjects/src/github.com/bukharyi/policy2/policies/enable/container_create/argsdebug.txt"
	    echo $msg
		exit 0

