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
        public static int _PacketHeaderSize = 5;
        public abstract PacketType PacketType { get; }
        public uint PacketSequence { get; set; }
        public static readonly Dictionary<PacketType, Type> _PacketTypes = new Dictionary<PacketType, Type>();

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
                catch (Exception e)
                {
                    string error = e.Message;
                }
            }
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

        public abstract void Load(ByteReader reader);
        protected abstract void InternalGetBytes(ByteWriter writer);
    }
}