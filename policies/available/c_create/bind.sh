#!/bin/bash
#--------
# THE FORMAT COULD BE LIKE THIS
#1. [/etc:/insidecontainer]
#2. [/root:/insidecontainerroot /etc:/insidecontainer]

regex="(\[)(.+)(\])"
binds=$1
allowList=( '/user')

if [[ $binds =~ $regex ]] ; then
	parsed="${BASH_REMATCH[2]}"
        #echo "${parsed}"    # concatenate strings
#else
	#echo "$f doesn't match" >&2 # this could get noisy if there are a lot of non-matching files
fi

for bind in $parsed
    do
        #echo "BIND=$bind"
        bindLocal=(${bind//:/ })

	#echo $bindLocal
        if [ $bindLocal != $allowList ] ; then
               echo "BIND=$bindLocal - DENIED. ALLOWED ONLY ON $allowList" 
               exit -1
        fi
done
#OTHER THAN THAT
echo "BIND=$binds PASS"
exit 0
