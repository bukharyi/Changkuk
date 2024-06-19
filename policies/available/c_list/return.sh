#! /bin/bash
PROGNAME=$(basename $0)
_uriArgsAll=$1


_uriArgsAll=`echo "\"$_uriArgsAll\"" | sed 's/"//g'`

#echo $_uriArgsAll

#if uriArgsAll is not empty
    #then process it.

if [ -n "${_uriArgsAll-unset}"  ] ; then

	if [ $_uriArgsAll == "1" ] ; then
	    echo "allow:false,msg:PROGRAM=$PROGNAME ARGS=$@ - we prevent FULL listing"
	    exit 0
	fi

else
        echo "allow:true,msg:PROGRAM=$PROGNAME all is unset"
        exit 0
fi


#else (is empty)
    #echo "allow:true"


