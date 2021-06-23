#!/bin/bash
set -x

flag=0

source converter/myconfig.py

## Variables
controller_ip=192.168.159.30
#type=GATEWAY


## Network config

#control_network_ip=$(ip route | tail -1 | awk '{print $9}')
#data_network_ip=$(ip route | tail -4 | head -1 | awk '{print $9}')
#internal_network_ip=$(ip route | tail -1 | awk '{print $1}')

control_network_ip=$(ip route | tail -3 | head -1 | awk '{print $9}')

data_network_ip=172.16.1.88

internal_network_ip=192.168.202.0/24

#if [ $type = HOST ];
#then
#cfg="{\"control_network_ip\":\"$control_network_ip\",\"data_network_ip\":\"$data_network_ip\"}"
#else
cfg="{\"control_network_ip\":\"$control_network_ip\",\"data_network_ip\":\"$data_network_ip\",\"internal_network_ip\":\"$internal_network_ip\"}"
#fi


while [ $flag -eq 0 ]
do
	Response=$(curl --header "Content-Type: application/json" --data $cfg --request POST http://$controller_ip:5000/register)
	#flag=1
	echo $Response
	if [ $Response == "OK" ]
	then
		flag=1
	elif [ $Response == "ERROR" ]
	then
		flag=0
		sleep 3
	else
		flag=0
	fi
done
