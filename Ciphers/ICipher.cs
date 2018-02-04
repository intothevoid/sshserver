namespace KSSHServer.Ciphers
{
    interface ICipher : IAlgorithm
    {
        uint BlockSize { get; }
        uint KeySize { get; }
        byte[] Encrypt(byte[] data);        
        byte[] Decrypt(byte[] data);
        void SetKey(byte[] key, byte[] iv);
    }
}