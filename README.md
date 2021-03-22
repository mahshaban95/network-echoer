# Network Traffic Echoer

Description:

The program basically impersonates two virtual hosts (victim and reflector, each with IP/Eth addresses) 
and use their addreses to manipulate the attacker into thinking he is attacking the victim while he is actually
attacking himself. (The reflector replays his attack to him and make the victim send the response)

How to use:
1) make
2) sudo ./reflector --interface {interface} --victim-ip {victim ip address} --victim-ethernet {victim ethernet address} --reflector-ip {reflector ip address} --reflector-ethernet {reflector ethernet address}
