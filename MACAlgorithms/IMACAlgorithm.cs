namespace KSSHServer.MACAlgorithms
{
    interface IMACAlgorithm : IAlgorithm
    {
        uint KeySize { get; }
        uint DigestLength { get; }
        void SetKey(byte[] key);
        byte[] ComputeHash(uint packetNumber, byte[] data);
    }
}