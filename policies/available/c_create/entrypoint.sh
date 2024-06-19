#!/bin/bash
_argImage=$1

entrypoint=`docker inspect $_argImage | jq '.[0].Config.Entrypoint'`


        if [ "$entrypoint" == "null" ] ; then
                echo "ENTRYPOINT=$_argImage DENIED-NOENTRYPOINT"
                exit -1
        fi
#OTHER THAN THAT
    echo "ENTRYPOINT=$_argImage PASS"
    exit 0
