namespace KSSHServer.KexAlgorithms
{
    public class DiffieHellmanGroup14SHA1 : IKexAlgorithm
    {
        public string Name => throw new System.NotImplementedException();

        public byte[] ComputeHash(byte[] value)
        {
            throw new System.NotImplementedException();
        }

        public byte[] CreateKeyExchange()
        {
            throw new System.NotImplementedException();
        }

        public byte[] DecryptKeyExchange(byte[] keyEx)
        {
            throw new System.NotImplementedException();
        }
    }
}