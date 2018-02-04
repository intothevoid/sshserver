namespace KSSHServer.KexAlgorithms
{
   public interface IKexAlgorithm : IAlgorithm
   {
       byte[] CreateKeyExchange();
       byte[] DecryptKeyExchange(byte[] keyEx);
       byte[] ComputeHash(byte[] value);
   } 
}