# ksshserver
Implementation of a SSH server in C#
This should cover basic functionality and encryption but not the advanced features of a full blown SSH server. The idea is to cover atleast one algorithm of each type from the list of required algorithms for a client. The client in this case being Putty supporting SSH-2.0. Based on the idea by TyrenDe.

Algorithms (to be) supported by this server -  
key exchange - diffie-hellman-group14-sha1  
host key algorithm - ssh-rsa  
encryption - 3des-cbc  
mac algorithm - hmac-sha1  
compression - none  

-----------------------------------------------------------
Packet Protocol (https://tools.ietf.org/html/rfc4253)

uint32    packet_length  
byte      padding_length  
byte[n1]  payload; n1 = packet_length - padding_length - 1  
byte[n2]  random padding; n2 = padding_length  
byte[m]   mac (Message Authentication Code - MAC); m = mac_length  

-----------------------------------------------------------

Changelog

0.1
- Added ability to listen for incoming connections and manage connections

0.2
- Added multiple client management

0.3
- Read protocol exchange string from client

0.4
- Read key exchange packet (*broken) 

0.5
- Read key exchange packet working

0.6 
- Added support for cipher, mac, keyhost and encryption algorithms
