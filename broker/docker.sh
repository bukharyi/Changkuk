total=$1;
echo "START $total, $(($(date +'%s * 1000 + %-N / 1000000')))" >> new.txt
#/bin/bash total.sh $total&

for i in `seq $total`;do


	 #docker create --name mysql-$i -e MYSQL_ROOT_PASSWORD=password -p $i:3306  mysql&
#	 docker create  mysql&
docker images 
#         echo "$i, $(($(date +'%s * 1000 + %-N / 1000000')))" >> start.txt
#	 /bin/bash checker.sh $i&
done

