using System;

namespace KSSHServer.Packets
{
    public class KexDHReply : Packet
    {
        public override PacketType PacketType
        {
            get
            {
                return PacketType.SSH_MSG_KEXDH_REPLY;
            }
        }

        public byte[] ServerHostKey { get; set; }
        public byte[] ServerValue { get; set; }
        public byte[] Signature { get; set; }

        protected override void InternalGetBytes(ByteWriter writer)
        {
            // string server public host key and certificates(K_S)
            // mpint f
            // string signature of H
            writer.WriteBytes(ServerHostKey);
            writer.WriteMPInt(ServerValue);
            writer.WriteBytes(Signature);
        }

        public override void Load(ByteReader reader)
        {
            // Client never sends this!
            throw new KSSHServerException(DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "KSSH Client should never send a SSH_MSG_KEXDH_REPLY message");
        }
    }
}