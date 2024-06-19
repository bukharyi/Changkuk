#!/bin/bash
#[/etc:/insidecontainer]
#[/root:/insidecontainerroot /etc:/insidecontainer]
#!/bin/bash
regex="(\[)(.+)(\])"
binds=$1
allowlist=( '/user')

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
        if [ $bindLocal != $allowlist ] ; then
               msg=" $bindLocal - Not allowed"
               echo "allow:false,msg:$msg"
               exit 0
        fi
done

echo "allow:true,msg:Allowed all $binds"
exit 0









#for bind in "${BINDALLOWLIST[@]}"
#    do
#        if [ $_argBind == $bind ] ; then
#                echo "BINDPATH=$_argBind PASS"
#                exit 0
#        fi
#done
#OTHER THAN THAT
#    echo "BINDPATH=$_argBind DENIED"
#    exit -1
