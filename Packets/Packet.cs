using System;
using System.Linq;
using System.Net.Sockets;

namespace KSSHServer.Packets
{
    public abstract class Packet
    {
        public const int MaxPacketSize = 35000;
        private static int _PacketHeaderSize = 5;
        public abstract PacketType PacketType { get; }

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

            using (ByteReader payloadReader = new ByteReader(payload))
            {
               // TODO Create packet object and return it 
            }

            return null;
        }
    }
}