namespace KSSHServer.Compressions
{
   interface ICompression : IAlgorithm
   {
      byte[] Compress(byte[] data);
      byte[] Decompress(byte[] data); 
   } 
}