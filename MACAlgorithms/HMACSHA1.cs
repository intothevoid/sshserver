using KSSHServer.Packets;

namespace KSSHServer.MACAlgorithms
{
    public class HMACSHA1 : IMACAlgorithm
    {
        System.Security.Cryptography.HMACSHA1 _HMAC = null;
        public uint KeySize
        {
            get
            {
                // https://tools.ietf.org/html/rfc4253#section-6.4
                // According to this, the KeySize is 20
                return 20;
            }
        }

        public uint DigestLength
        {
            get
            {
                // https://tools.ietf.org/html/rfc4253#section-6.4
                // According to this, the DigestLength is 20
                return 20;
            }
        }

        public string Name
        {
            get
            {
                return "hmac-sha1";
            }
        }

        public byte[] ComputeHash(uint packetNumber, byte[] data)
        {
            if (_HMAC == null)
                throw new KSSHServerException(DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "SetKey must be called before attempting to ComputeHash");

            using (ByteWriter writer = new ByteWriter())
            {
               writer.WriteUInt32(packetNumber);
               writer.WriteRawBytes(data);
               return _HMAC.ComputeHash(writer.ToByteArray()); 
            }
        }

        public void SetKey(byte[] key)
        {
            _HMAC = new System.Security.Cryptography.HMACSHA1(key);
        }
    }
}