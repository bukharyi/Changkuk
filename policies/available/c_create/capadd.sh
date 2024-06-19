#!/bin/bash
_argCapAdd=$1
CAPADD="[all]"


if [ $_argCapAdd == $CAPADD ] ; then
	echo "CAPADD=$_argCapAdd PASS"
	exit 0
fi
#OTHER THAN THAT
echo "CAPADD=$_argCapAdd DENIED-Mandatory to set \"ALL\""
exit -1
