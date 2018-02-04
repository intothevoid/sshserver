using KSSHServer.Ciphers;
using KSSHServer.Compressions;
using KSSHServer.HostKeyAlgorithms;
using KSSHServer.KexAlgorithms;
using KSSHServer.MACAlgorithms;

namespace KSSHServer
{
    public class ExchangeContext
    {
        public IKexAlgorithm KexAlgorithm { get; set; } = null;
        public IHostKeyAlgorithm HostKeyAlgorithm { get; set; } = null;
        public ICipher CipherClientToServer { get; set; } = new NoCipher();
        public ICipher CipherServerToClient { get; set; } = new NoCipher();
        public IMACAlgorithm MACAlgorithmClientToServer { get; set; } = null;
        public IMACAlgorithm MACAlgorithmServerToClient { get; set; } = null;
        public ICompression CompressionClientToServer { get; set; } = new NoCompression();
        public ICompression CompressionServerToClient { get; set; } = new NoCompression();
    }
}