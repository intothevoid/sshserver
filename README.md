# sshserver
Implementation of a SSH server in C#

This should cover basic functionality and encryption and not the advanced features of a full blown SSH server

-----------------------------------------------------------
Changelog

0.1
- Added ability to listen for incoming connections and manage connections

0.2
- Added multiple client management

-----------------------------------------------------------
Packet Protocol (https://tools.ietf.org/html/rfc4253)

uint32    packet_length
      byte      padding_length
      byte[n1]  payload; n1 = packet_length - padding_length - 1
      byte[n2]  random padding; n2 = padding_length
      byte[m]   mac (Message Authentication Code - MAC); m = mac_length