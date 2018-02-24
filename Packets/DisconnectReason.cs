using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KSSHServer.Packets
{
    public enum DisconnectReason : uint
    {
        None = 0,
        SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1,
        SSH_DISCONNECT_PROTOCOL_ERROR = 2,
        SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3,
        SSH_DISCONNECT_RESERVED = 4,
        SSH_DISCONNECT_MAC_ERROR = 5,
        SSH_DISCONNECT_COMPRESSION_ERROR = 6,
        SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7,
        SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8,
        SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9,
        SSH_DISCONNECT_CONNECTION_LOST = 10,
        SSH_DISCONNECT_BY_APPLICATION = 11,
        SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12,
        SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13,
        SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14,
        SSH_DISCONNECT_ILLEGAL_USER_NAME = 15,
    }

    public class Disconnect : Packet
    {
        public override PacketType PacketType
        {
            get
            {
                return PacketType.SSH_MSG_DISCONNECT;
            }
        }

        public DisconnectReason Reason { get; set; }
        public string Description { get; set; }
        public string Language { get; set; } = "en";

        public override void Load(ByteReader reader)
        {
            Reason = (DisconnectReason)reader.GetUInt32();
            Description = reader.GetString(Encoding.UTF8);
            if (!reader.IsEOF)
                Language = reader.GetString();
        }

        protected override void InternalGetBytes(ByteWriter writer)
        {
            writer.WriteUInt32((uint)Reason);
            writer.WriteString(Description, Encoding.UTF8);
            writer.WriteString(Language);
        }
    }
}