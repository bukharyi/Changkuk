#!/bin/bash
_argsImage=$1
IMAGELIST=('10.1.70.70:443/ubuntu' 'mysql' 'haproxy' 'cirros' '8bea5daaf8bb')

for image in "${IMAGELIST[@]}"
    do
        if [ $_argsImage == $image ] ; then
                echo "IMAGE=$_argsImage PASS"
                exit 0
        fi
done
#OTHER THAN THAT
    echo "IMAGE=$_argsImage DENIED"
    exit -1
