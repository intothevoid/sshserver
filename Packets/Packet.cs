using System;
using System.Linq;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Reflection;
using System.Security.Cryptography;

namespace KSSHServer.Packets
{
    public abstract class Packet
    {
        public const int MaxPacketSize = 35000;
        private static int _PacketHeaderSize = 5;
        public abstract PacketType PacketType { get; }

        private static Dictionary<PacketType, Type> _PacketTypes = new Dictionary<PacketType, Type>();

        static Packet()
        {
            var packets = Assembly.GetEntryAssembly().GetTypes().Where(t => typeof(Packet).IsAssignableFrom(t));
            foreach (var packet in packets)
            {
                try
                {
                Packet packetInstance = Activator.CreateInstance(packet) as Packet;
                _PacketTypes[packetInstance.PacketType] = packet;
                }
                catch { }
            }
        }

        public static Packet ReadPacket(Socket socket)
        {
            if (socket == null)
                return null;

            uint blockSize = 8;

            // We must have atleast 1 block to read
            if (socket.Available < blockSize)
                return null;

            byte[] firstBlock = new byte[blockSize];
            int bytesRead = socket.Receive(firstBlock);

            if (bytesRead != blockSize)
                throw new System.Exception("Failed to read from socket.");

            // Decrypt block using ClientToServer cipher
            uint packetLength = 0;
            byte paddingLength = 0;

            using (ByteReader reader = new ByteReader(firstBlock))
            {
                // uint32    packet_length
                // packet_length
                // The length of the packet in bytes, not including 'mac' or the
                // 'packet_length' field itself. 
                packetLength = reader.GetUInt32();

                if (packetLength > MaxPacketSize)
                {
                    throw new Exception($"Client tried to send a packet larger than" +
                        "MaxPacketSize ({MaxPacketSize} bytes : {packetLength} bytes");
                }

                // byte      padding_length
                // padding_length
                // Length of 'random padding' (bytes).
                paddingLength = reader.GetByte();
            }

            // byte[n1]  payload; n1 = packet_length - padding_length - 1
            // payload
            // The useful contents of the packet.  If compression has been
            // negotiated, this field is compressed.  Initially, compression
            // MUST be "none".
            uint bytesToRead = packetLength - blockSize + 4;

            byte[] restOfPacket = new byte[bytesToRead];
            bytesRead = socket.Receive(restOfPacket);
            if (bytesRead != bytesToRead)
                throw new Exception("Unable to read from socket.");

            // TODO Decrypt blocks using ClientToServer cipher

            uint payloadLength = packetLength - paddingLength - 1;
            byte[] fullPacket = firstBlock.Concat(restOfPacket).ToArray();

            // TODO Track total bytes read

            byte[] payload = fullPacket.Skip(_PacketHeaderSize).Take(
                (int)(packetLength - paddingLength - 1)).ToArray();

            // byte[n2]  random padding; n2 = padding_length
            // random padding
            // Arbitrary-length padding, such that the total length of
            // (packet_length || padding_length || payload || random padding)
            // is a multiple of the cipher block size or 8, whichever is
            // larger.  There MUST be at least four bytes of padding.  The
            // padding SHOULD consist of random bytes.  The maximum amount of
            // padding is 255 bytes.

            // TODO: Keep track of the received packet sequence (used for MAC)

            // TODO: Read MAC if present

            // TODO: Decompress the payload if necessary

            using (ByteReader packetReader = new ByteReader(payload))
            {
               PacketType type = (PacketType)packetReader.GetByte();

               if(_PacketTypes.ContainsKey(type))
               {
                   Packet packet = Activator.CreateInstance(_PacketTypes[type]) as Packet;
                   packet.Load(packetReader);

                   // TODO Store packet sequence for use later on

                   return packet;
               } 
            }

            return null;
        }

        public byte[] ToByteArray()
        {
            // TODO: Keep track of the received packet sequence (used for MAC)

            byte[] payload = GetBytes();

            // TODO: Compress the payload if necessary

            // TODO: Get the block size based on the ClientToServer cipher

            uint blockSize = 8;

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

            // TODO: Encrypt the payload if necessary

            // TODO: Write MAC if necesssary

            return payload;
        }

        public byte[] GetBytes()
        {
            using (ByteWriter writer = new ByteWriter())
            {
                writer.WritePacketType(PacketType);
                InternalGetBytes(writer);
                return writer.ToByteArray();   
            }
        }

        protected abstract void Load(ByteReader reader);
        protected abstract void InternalGetBytes(ByteWriter writer);
    }
}