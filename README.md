# ksshserver
Implementation of a SSH server in C#
This should cover basic functionality and encryption and not the advanced features of a full blown SSH server

-----------------------------------------------------------
Packet Protocol (https://tools.ietf.org/html/rfc4253)

uint32    packet_length

byte      padding_length

byte[n1]  payload; n1 = packet_length - padding_length - 1

byte[n2]  random padding; n2 = padding_length

byte[m]   mac (Message Authentication Code - MAC); m = mac_length

-----------------------------------------------------------

Key Exchange Packet Format (From SSH RFC)

byte         SSH_MSG_KEXINIT   
byte[16]     cookie (random bytes)  
name-list    kex_algorithms  
name-list    server_host_key_algorithms  
name-list    encryption_algorithms_client_to_server  
name-list    encryption_algorithms_server_to_client   
name-list    mac_algorithms_client_to_server   
name-list    mac_algorithms_server_to_client  
name-list    compression_algorithms_client_to_server   
name-list    compression_algorithms_server_to_client  
name-list    languages_client_to_server   
name-list    languages_server_to_client  
boolean      first_kex_packet_follows  
uint32       0 (reserved for future extension)  
    
-----------------------------------------------------------

Changelog

0.1
- Added ability to listen for incoming connections and manage connections

0.2
- Added multiple client management

0.3
- Read protocol exchange string from client
