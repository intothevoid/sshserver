using System;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using KSSHServer.Packets;
using Microsoft.Extensions.Logging;

namespace KSSHServer
{
    public class Client
    {
        private ILogger _Logger;
        private Socket _Socket;
        private bool _ProtocolVersionExchangeComplete = false;
        private string _ProtocolVersionExchange;
        private Packets.KexInit _KexInitServerToClient = new Packets.KexInit();

        public Client(Socket socket, ILogger logger)
        {
            _Socket = socket;
            _Logger = logger;

            _KexInitServerToClient.KexAlgorithms.AddRange(Server.GetNames(Server.SupportedKexAlgorithms));
            _KexInitServerToClient.ServerHostKeyAlgorithms.AddRange(Server.GetNames(Server.SupportedHostKeyAlgorithms));
            _KexInitServerToClient.EncryptionAlgorithmsClientToServer.AddRange(Server.GetNames(Server.SupportedCiphers));
            _KexInitServerToClient.EncryptionAlgorithmsServerToClient.AddRange(Server.GetNames(Server.SupportedCiphers));
            _KexInitServerToClient.MacAlgorithmsClientToServer.AddRange(Server.GetNames(Server.SupportedMACAlgorithms));
            _KexInitServerToClient.MacAlgorithmsServerToClient.AddRange(Server.GetNames(Server.SupportedMACAlgorithms));

            const int socketBufferSize = 2 * Packets.Packet.MaxPacketSize;
            _Socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendBuffer, socketBufferSize);
            _Socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, socketBufferSize);
            _Socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
            _Socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.DontLinger, true);

            Send($"{ServerConstants.ProtocolVersionExchange}\r\n");

            // 7.1.  Algorithm Negotiation - https://tools.ietf.org/html/rfc4253#section-7.1
            Send(_KexInitServerToClient);
        }

        private void Send(Packet packet)
        {
            Send(packet.ToByteArray());
        }

        private void Send(string message)
        {
            _Logger.LogDebug($"Sending raw string: {message.Trim()}");
            Send(Encoding.UTF8.GetBytes(message));
        }

        private void Send(byte[] message)
        {
            if (!IsConnected())
                return;

            _Socket.Send(message);
        }

        public bool IsConnected()
        {
            return (_Socket != null);
        }

        public void Poll()
        {
            if (!IsConnected())
                return;

            bool dataAvailable = _Socket.Poll(0, SelectMode.SelectRead);

            if (dataAvailable)
            {
                int read = _Socket.Available;

                if (read < 1)
                {
                    Disconnect();
                    return;
                }

                if (!_ProtocolVersionExchangeComplete)
                {
                    try
                    {
                        ReadProtocolVersionExchange();

                        if (_ProtocolVersionExchangeComplete)
                        {
                            _Logger.LogDebug($"Received ProtocolVersionExchange:{_ProtocolVersionExchange}");
                        }
                    }
                    catch (System.Exception)
                    {
                        Disconnect();
                        return;
                    }
                }

                if (_ProtocolVersionExchangeComplete)
                {
                    try
                    {
                        Packets.Packet packet = Packets.Packet.ReadPacket(_Socket);

                        while (packet != null)
                        {
                            // TODO handle specific packets
                            _Logger.LogDebug($"Received Packet: {packet.PacketType}");

                            // Read next packet
                            packet = Packets.Packet.ReadPacket(_Socket);
                        }
                    }
                    catch (System.Exception ex)
                    {
                        _Logger.LogError(ex.Message);
                        Disconnect();
                        return;
                    }
                }
            }
        }

        // Read 1 byte from the socket until \r\n
        private void ReadProtocolVersionExchange()
        {
            NetworkStream stream = new NetworkStream(_Socket, false);
            string result = null;

            List<byte> data = new List<byte>();

            bool foundCR = false;
            int val = stream.ReadByte();

            while (val != -1)
            {
                if (foundCR && (val == '\n'))
                {
                    result = Encoding.UTF8.GetString(data.ToArray());
                    _ProtocolVersionExchangeComplete = true;
                    break;
                }

                if (val == '\r')
                {
                    foundCR = true;
                }
                else
                {
                    foundCR = false;
                    data.Add((byte)val);
                }

                val = stream.ReadByte();
            }

            _ProtocolVersionExchange += result;
        }

        public void Disconnect()
        {
            _Logger.LogInformation("Client disconnected");

            if (_Socket != null)
            {
                try
                {
                    _Socket.Shutdown(SocketShutdown.Both);
                }

                catch (System.Exception) { }

                _Socket = null;
            }
        }

    };
}