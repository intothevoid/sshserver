namespace KSSHServer.Compressions
{
    public class NoCompression : ICompression
    {
        public string Name
        {
            get
            {
                return "none";
            }
        }

        public byte[] Compress(byte[] data)
        {
            return data;
        }

        public byte[] Decompress(byte[] data)
        {
            return data;
        }
    }
}