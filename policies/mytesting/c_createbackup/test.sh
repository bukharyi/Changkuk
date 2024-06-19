#! /bin/bash
input="[/etc/:/opt /root:/root]"
regex="(\[)(.+)(\])"

    if [[ $input =~ $regex ]]
    then
        middle="${BASH_REMATCH[2]}"
        echo "${middle}"    # concatenate strings

    else
        echo "$f doesn't match" >&2 # this could get noisy if there are a lot of non-matching files
    fi
