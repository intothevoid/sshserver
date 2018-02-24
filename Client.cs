using System;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using KSSHServer.KexAlgorithms;
using KSSHServer.Packets;
using Microsoft.CSharp.RuntimeBinder;
using Microsoft.Extensions.Logging;
using System.Threading;
using System.Security.Cryptography;
using System.Linq;
using KSSHServer.Packets.SSHServer.Packets;

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
        private byte[] _SessionId = null;
        private int _CurrentSentPacketNumber = -1;
        private int _CurrentReceivedPacketNumber = -1;
        private long _TotalBytesTransferred = 0;
        private DateTime _KeyTimeout = DateTime.UtcNow.AddHours(1);

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
            packet.PacketSequence = GetSentPacketNumber();

            byte[] payload = _ActiveExchangeContext.CompressionServerToClient.Compress(packet.GetBytes());

            uint blockSize = _ActiveExchangeContext.CipherServerToClient.BlockSize;

            byte paddingLength = (byte)(blockSize - (payload.Length + 5) % blockSize);
            if (paddingLength < 4)
                paddingLength += (byte)blockSize;

            byte[] padding = new byte[paddingLength];
            RandomNumberGenerator.Create().GetBytes(padding);

            uint packetLength = (uint)(payload.Length + paddingLength + 1);

            using (ByteWriter writer = new ByteWriter())
            {
                writer.WriteUInt32(packetLength);
                writer.WriteByte(paddingLength);
                writer.WriteRawBytes(payload);
                writer.WriteRawBytes(padding);

                payload = writer.ToByteArray();
            }

            byte[] encryptedPayload = _ActiveExchangeContext.CipherServerToClient.Encrypt(payload);
            if (_ActiveExchangeContext.MACAlgorithmServerToClient != null)
            {
                byte[] mac = _ActiveExchangeContext.MACAlgorithmServerToClient.ComputeHash(packet.PacketSequence, payload);
                encryptedPayload = encryptedPayload.Concat(mac).ToArray();
            }

            Send(encryptedPayload);
            this.ConsiderReExchange();
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

            // Increase bytes transferred
            _TotalBytesTransferred += message.Length;

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
                    Disconnect(DisconnectReason.SSH_DISCONNECT_CONNECTION_LOST, "The client disconnected.");
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
                            ValidateProtocolVersionExchange();
                        }
                    }
                    catch (System.Exception)
                    {
                        Disconnect(DisconnectReason.SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED, "Failed to get the protocol version exchange.");
                        return;
                    }
                }

                if (_ProtocolVersionExchangeComplete)
                {
                    try
                    {
                        Packets.Packet packet = ReadPacket();

                        while (packet != null)
                        {
                            _Logger.LogDebug($"Received Packet: {packet.PacketType}");

                            // Handle specific packet
                            HandlePacket(packet);

                            // Read next packet
                            packet = ReadPacket();
                        }

                        ConsiderReExchange();
                    }
                    catch (KSSHServerException ex)
                    {
                        _Logger.LogError(ex.Message);
                        Disconnect(ex.Reason, ex.Message);
                        return;
                    }
                }
            }
        }

        private uint GetSentPacketNumber()
        {
            return (uint)Interlocked.Increment(ref _CurrentSentPacketNumber);
        }

        private uint GetReceivedPacketNumber()
        {
            return (uint)Interlocked.Increment(ref _CurrentReceivedPacketNumber);
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
                _Logger.LogWarning($"Unhandled packet type: {packet.PacketType}");

                Unimplemented unimplemented = new Unimplemented()
                {
                    RejectedPacketNumber = packet.PacketSequence
                };

                Send(unimplemented);
            }
        }

        private void HandleSpecificPacket(KexDHInit packet)
        {
            _Logger.LogDebug("Received KexDHInit");

            if ((_PendingExchangeContext == null) || (_PendingExchangeContext.KexAlgorithm == null))
            {
                throw new KSSHServerException(DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR, "Server did not receive SSH_MSG_KEX_INIT as expected.");
            }

            // 1. C generates a random number x (1 &lt x &lt q) and computes e = g ^ x mod p.  C sends e to S.
            // 2. S receives e.  It computes K = e^y mod p
            byte[] sharedSecret = _PendingExchangeContext.KexAlgorithm.DecryptKeyExchange(packet.ClientValue);

            // 2. S generates a random number y (0 < y < q) and computes f = g ^ y mod p.
            byte[] serverKeyExchange = _PendingExchangeContext.KexAlgorithm.CreateKeyExchange();

            byte[] hostKey = _PendingExchangeContext.HostKeyAlgorithm.CreateKeyAndCertificatesData();

            // H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
            byte[] exchangeHash = ComputeExchangeHash(
                _PendingExchangeContext.KexAlgorithm,
                hostKey,
                packet.ClientValue,
                serverKeyExchange,
                sharedSecret);

            if (_SessionId == null)
                _SessionId = exchangeHash;

            // https://tools.ietf.org/html/rfc4253#section-7.2

            // Initial IV client to server: HASH(K || H || "A" || session_id)
            // (Here K is encoded as mpint and "A" as byte and session_id as raw
            // data.  "A" means the single character A, ASCII 65).
            byte[] clientCipherIV = ComputeEncryptionKey(
                _PendingExchangeContext.KexAlgorithm,
                exchangeHash,
                _PendingExchangeContext.CipherClientToServer.BlockSize,
                sharedSecret, 'A');

            // Initial IV server to client: HASH(K || H || "B" || session_id)
            byte[] serverCipherIV = ComputeEncryptionKey(
                _PendingExchangeContext.KexAlgorithm,
                exchangeHash,
                _PendingExchangeContext.CipherServerToClient.BlockSize,
                sharedSecret, 'B');

            // Encryption key client to server: HASH(K || H || "C" || session_id)
            byte[] clientCipherKey = ComputeEncryptionKey(
                _PendingExchangeContext.KexAlgorithm,
                exchangeHash,
                _PendingExchangeContext.CipherClientToServer.KeySize,
                sharedSecret, 'C');

            // Encryption key server to client: HASH(K || H || "D" || session_id)
            byte[] serverCipherKey = ComputeEncryptionKey(
                _PendingExchangeContext.KexAlgorithm,
                exchangeHash,
                _PendingExchangeContext.CipherServerToClient.KeySize,
                sharedSecret, 'D');

            // Integrity key client to server: HASH(K || H || "E" || session_id)
            byte[] clientHmacKey = ComputeEncryptionKey(
                _PendingExchangeContext.KexAlgorithm,
                exchangeHash,
                _PendingExchangeContext.MACAlgorithmClientToServer.KeySize,
                sharedSecret, 'E');

            // Integrity key server to client: HASH(K || H || "F" || session_id)
            byte[] serverHmacKey = ComputeEncryptionKey(
                _PendingExchangeContext.KexAlgorithm,
                exchangeHash,
                _PendingExchangeContext.MACAlgorithmServerToClient.KeySize,
                sharedSecret, 'F');

            // Set all keys we just generated
            _PendingExchangeContext.CipherClientToServer.SetKey(clientCipherKey, clientCipherIV);
            _PendingExchangeContext.CipherServerToClient.SetKey(serverCipherKey, serverCipherIV);
            _PendingExchangeContext.MACAlgorithmClientToServer.SetKey(clientHmacKey);
            _PendingExchangeContext.MACAlgorithmServerToClient.SetKey(serverHmacKey);

            // Send reply to client!
            KexDHReply reply = new KexDHReply()
            {
                ServerHostKey = hostKey,
                ServerValue = serverKeyExchange,
                Signature = _PendingExchangeContext.HostKeyAlgorithm.CreateSignatureData(exchangeHash)
            };

            Send(reply);
            Send(new NewKeys());
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

        private void HandleSpecificPacket(NewKeys packet)
        {
            _Logger.LogDebug("Received NewKeys");

            _ActiveExchangeContext = _PendingExchangeContext;
            _PendingExchangeContext = null;


            // Reset re-exchange values
            _TotalBytesTransferred = 0;
            _KeyTimeout = DateTime.UtcNow.AddHours(1);
        }

        private byte[] ComputeExchangeHash(IKexAlgorithm kexAlgorithm, byte[] hostKeyAndCerts, byte[] clientExchangeValue, byte[] serverExchangeValue, byte[] sharedSecret)
        {
            // H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
            using (ByteWriter writer = new ByteWriter())
            {
                writer.WriteString(_ProtocolVersionExchange);
                writer.WriteString(ServerConstants.ProtocolVersionExchange);

                writer.WriteBytes(_KexInitClientToServer.GetBytes());
                writer.WriteBytes(_KexInitServerToClient.GetBytes());
                writer.WriteBytes(hostKeyAndCerts);

                writer.WriteMPInt(clientExchangeValue);
                writer.WriteMPInt(serverExchangeValue);
                writer.WriteMPInt(sharedSecret);

                return kexAlgorithm.ComputeHash(writer.ToByteArray());
            }
        }

        private byte[] ComputeEncryptionKey(IKexAlgorithm kexAlgorithm, byte[] exchangeHash, uint keySize, byte[] sharedSecret, char letter)
        {
            // K(X) = HASH(K || H || X || session_id)

            // Prepare the buffer
            byte[] keyBuffer = new byte[keySize];
            int keyBufferIndex = 0;
            int currentHashLength = 0;
            byte[] currentHash = null;

            // We can stop once we fill the key buffer
            while (keyBufferIndex < keySize)
            {
                using (ByteWriter writer = new ByteWriter())
                {
                    // Write "K"
                    writer.WriteMPInt(sharedSecret);

                    // Write "H"
                    writer.WriteRawBytes(exchangeHash);

                    if (currentHash == null)
                    {
                        // If we haven't done this yet, add the "X" and session_id
                        writer.WriteByte((byte)letter);
                        writer.WriteRawBytes(_SessionId);
                    }
                    else
                    {
                        // If the key isn't long enough after the first pass, we need to
                        // write the current hash as described here:
                        //      K1 = HASH(K || H || X || session_id)   (X is e.g., "A")
                        //      K2 = HASH(K || H || K1)
                        //      K3 = HASH(K || H || K1 || K2)
                        //      ...
                        //      key = K1 || K2 || K3 || ...
                        writer.WriteRawBytes(currentHash);
                    }

                    currentHash = kexAlgorithm.ComputeHash(writer.ToByteArray());
                }

                currentHashLength = Math.Min(currentHash.Length, (int)(keySize - keyBufferIndex));
                Array.Copy(currentHash, 0, keyBuffer, keyBufferIndex, currentHashLength);

                keyBufferIndex += currentHashLength;
            }

            return keyBuffer;
        }

        public Packet ReadPacket()
        {
            if (_Socket == null)
                return null;

            uint blockSize = _ActiveExchangeContext.CipherClientToServer.BlockSize;

            // We must have at least 1 block to read
            if (_Socket.Available < blockSize)
                return null;  // Packet not here

            byte[] firstBlock = new byte[blockSize];
            int bytesRead = _Socket.Receive(firstBlock);
            if (bytesRead != blockSize)
                throw new KSSHServerException(DisconnectReason.SSH_DISCONNECT_CONNECTION_LOST, "Failed to read from socket.");

            firstBlock = _ActiveExchangeContext.CipherClientToServer.Decrypt(firstBlock);

            uint packetLength = 0;
            byte paddingLength = 0;
            using (ByteReader reader = new ByteReader(firstBlock))
            {
                // uint32    packet_length
                // packet_length
                //     The length of the packet in bytes, not including 'mac' or the
                //     'packet_length' field itself.
                packetLength = reader.GetUInt32();
                if (packetLength > Packet.MaxPacketSize)
                    throw new KSSHServerException(DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR, $"Client tried to send a packet bigger than MaxPacketSize ({Packet.MaxPacketSize} bytes): {packetLength} bytes");

                // byte      padding_length
                // padding_length
                //    Length of 'random padding' (bytes).
                paddingLength = reader.GetByte();
            }

            // byte[n1]  payload; n1 = packet_length - padding_length - 1
            // payload
            //    The useful contents of the packet.  If compression has been
            //    negotiated, this field is compressed.  Initially, compression
            //    MUST be "none".
            uint bytesToRead = packetLength - blockSize + 4;

            byte[] restOfPacket = new byte[bytesToRead];
            bytesRead = _Socket.Receive(restOfPacket);
            if (bytesRead != bytesToRead)
                throw new KSSHServerException(DisconnectReason.SSH_DISCONNECT_CONNECTION_LOST, "Failed to read from socket.");

            restOfPacket = _ActiveExchangeContext.CipherClientToServer.Decrypt(restOfPacket);

            uint payloadLength = packetLength - paddingLength - 1;
            byte[] fullPacket = firstBlock.Concat(restOfPacket).ToArray();

            // Track total bytes read
            _TotalBytesTransferred += fullPacket.Length;

            byte[] payload = fullPacket.Skip(Packet._PacketHeaderSize).Take((int)(packetLength - paddingLength - 1)).ToArray();

            // byte[n2]  random padding; n2 = padding_length
            // random padding
            //    Arbitrary-length padding, such that the total length of
            //    (packet_length || padding_length || payload || random padding)
            //    is a multiple of the cipher block size or 8, whichever is
            //    larger.  There MUST be at least four bytes of padding.  The
            //    padding SHOULD consist of random bytes.  The maximum amount of
            //    padding is 255 bytes.

            // byte[m]   mac (Message Authentication Code - MAC); m = mac_length
            // mac
            //    Message Authentication Code.  If message authentication has
            //    been negotiated, this field contains the MAC bytes.  Initially,
            //    the MAC algorithm MUST be "none".

            uint packetNumber = GetReceivedPacketNumber();
            if (_ActiveExchangeContext.MACAlgorithmClientToServer != null)
            {
                byte[] clientMac = new byte[_ActiveExchangeContext.MACAlgorithmClientToServer.DigestLength];
                bytesRead = _Socket.Receive(clientMac);
                if (bytesRead != _ActiveExchangeContext.MACAlgorithmClientToServer.DigestLength)
                    throw new KSSHServerException(DisconnectReason.SSH_DISCONNECT_CONNECTION_LOST, "Failed to read from socket.");

                var mac = _ActiveExchangeContext.MACAlgorithmClientToServer.ComputeHash(packetNumber, fullPacket);
                if (!clientMac.SequenceEqual(mac))
                {
                    throw new KSSHServerException(DisconnectReason.SSH_DISCONNECT_MAC_ERROR, "MAC from client is invalid");
                }
            }

            payload = _ActiveExchangeContext.CompressionClientToServer.Decompress(payload);

            using (ByteReader packetReader = new ByteReader(payload))
            {
                PacketType type = (PacketType)packetReader.GetByte();

                if (Packet._PacketTypes.ContainsKey(type))
                {

                    Packet packet = Activator.CreateInstance(Packet._PacketTypes[type]) as Packet;
                    packet.Load(packetReader);
                    packet.PacketSequence = packetNumber;
                    return packet;
                }

                _Logger.LogWarning($"Unimplemented packet type: {type}");

                Unimplemented unimplemented = new Unimplemented()
                {
                    RejectedPacketNumber = packetNumber
                };

                Send(unimplemented);
            }

            return null;
        }

        private void ConsiderReExchange()
        {
            const long OneGB = (1024 * 1024 * 1024);
            if ((_TotalBytesTransferred > OneGB) || (_KeyTimeout < DateTime.UtcNow))
            {
                // Time to get new keys!
                _TotalBytesTransferred = 0;
                _KeyTimeout = DateTime.UtcNow.AddHours(1);

                _Logger.LogDebug("Trigger re-exchange from server");
                _PendingExchangeContext = new ExchangeContext();
                Send(_KexInitServerToClient);
            }
        }

        private void ValidateProtocolVersionExchange()
        {
            // https://tools.ietf.org/html/rfc4253#section-4.2
            //SSH-protoversion-softwareversion SP comments

            string[] pveParts = _ProtocolVersionExchange.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (pveParts.Length == 0)
                throw new UnauthorizedAccessException("Invalid Protocol Version Exchange was received - No Data");

            string[] versionParts = pveParts[0].Split(new char[] { '-' }, StringSplitOptions.RemoveEmptyEntries);
            if (versionParts.Length < 3)
                throw new UnauthorizedAccessException($"Invalid Protocol Version Exchange was received - Not enough dashes - {pveParts[0]}");

            if (versionParts[1] != "2.0")
                throw new UnauthorizedAccessException($"Invalid Protocol Version Exchange was received - Unsupported Version - {versionParts[1]}");

            // If we get here, all is well!
        }


        public void Disconnect(DisconnectReason reason, string message)
        {
            _Logger.LogDebug($"Disconnected - {reason} - {message}");
            if (_Socket != null)
            {
                if (reason != DisconnectReason.None)
                {
                    try
                    {
                        Disconnect disconnect = new Disconnect()
                        {
                            Reason = reason,
                            Description = message
                        };
                        Send(disconnect);
                    }
                    catch (Exception) { }
                }

                try
                {
                    _Socket.Shutdown(SocketShutdown.Both);
                }
                catch (Exception) { }

                _Socket = null;
            }
        }
    };
}