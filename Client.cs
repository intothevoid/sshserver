using System;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using KSSHServer.Packets;
using Microsoft.CSharp.RuntimeBinder;
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
        private Packets.KexInit _KexInitClientToServer = null;
        private ExchangeContext _ActiveExchangeContext = new ExchangeContext();
        private ExchangeContext _PendingExchangeContext = new ExchangeContext();

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
            _KexInitServerToClient.CompressionAlgorithmsClientToServer.AddRange(Server.GetNames(Server.SupportedCompressions));
            _KexInitServerToClient.CompressionAlgorithmsServerToClient.AddRange(Server.GetNames(Server.SupportedCompressions));

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
                            _Logger.LogDebug($"Received Packet: {packet.PacketType}");

                            // Handle specific packet
                            HandlePacket(packet);

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

        private void HandlePacket(Packet packet)
        {
            try
            {
                HandleSpecificPacket((dynamic)packet);
            }
            catch (RuntimeBinderException)
            {
                // TODO: Send an SSH_MSG_UNIMPLEMENTED if we get here
            }
        }

        private void HandleSpecificPacket(KexDHInit packet)
        {
                _Logger.LogDebug("Received KexDHInit");

                // TODO: Implement Key Exchange!
        }

        private void HandleSpecificPacket(KexInit packet)
        {
            _Logger.LogDebug("Received KexInit packet.");

            if (_PendingExchangeContext == null)
            {
                _Logger.LogDebug("Re-exchanging keys!");
                _PendingExchangeContext = new ExchangeContext();
                Send(_KexInitServerToClient);
            }

            _KexInitClientToServer = packet;

            _PendingExchangeContext.KexAlgorithm = packet.PickKexAlgorithm();
            _PendingExchangeContext.HostKeyAlgorithm = packet.PickHostKeyAlgorithm();
            _PendingExchangeContext.CipherClientToServer = packet.PickCipherClientToServer();
            _PendingExchangeContext.CipherServerToClient = packet.PickCipherServerToClient();
            _PendingExchangeContext.MACAlgorithmClientToServer = packet.PickMACAlgorithmClientToServer();
            _PendingExchangeContext.MACAlgorithmServerToClient = packet.PickMACAlgorithmServerToClient();
            _PendingExchangeContext.CompressionClientToServer = packet.PickCompressionAlgorithmClientToServer();
            _PendingExchangeContext.CompressionServerToClient = packet.PickCompressionAlgorithmServerToClient();

            _Logger.LogDebug($"Selected KexAlgorithm: {_PendingExchangeContext.KexAlgorithm.Name}");
            _Logger.LogDebug($"Selected HostKeyAlgorithm: {_PendingExchangeContext.HostKeyAlgorithm.Name}");
            _Logger.LogDebug($"Selected CipherClientToServer: {_PendingExchangeContext.CipherClientToServer.Name}");
            _Logger.LogDebug($"Selected CipherServerToClient: {_PendingExchangeContext.CipherServerToClient.Name}");
            _Logger.LogDebug($"Selected MACAlgorithmClientToServer: {_PendingExchangeContext.MACAlgorithmClientToServer.Name}");
            _Logger.LogDebug($"Selected MACAlgorithmServerToClient: {_PendingExchangeContext.MACAlgorithmServerToClient.Name}");
            _Logger.LogDebug($"Selected CompressionClientToServer: {_PendingExchangeContext.CompressionClientToServer.Name}");
            _Logger.LogDebug($"Selected CompressionServerToClient: {_PendingExchangeContext.CompressionServerToClient.Name}");
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