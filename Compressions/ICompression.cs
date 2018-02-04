namespace KSSHServer.Compressions
{
   public interface ICompression : IAlgorithm
   {
      byte[] Compress(byte[] data);
      byte[] Decompress(byte[] data); 
   } 
}