
using System;
using System.Security.Cryptography;
using System.Xml;

namespace KSSHServer.HostKeyAlgorithms
{
    public class SSHRSA : IHostKeyAlgorithm
    {
        private readonly RSA _RSA = RSA.Create();

        public string Name { get { return "ssh-rsa"; } }

        public byte[] CreateKeyAndCertificatesData()
        {
            RSAParameters param = _RSA.ExportParameters(false);

            using (ByteWriter writer = new ByteWriter())
            {
                writer.WriteString(Name);
                writer.WriteMPInt(param.Exponent);
                writer.WriteMPInt(param.Modulus);
                return writer.ToByteArray();
            }
        }

        public byte[] CreateSignatureData(byte[] hash)
        {
            using (ByteWriter writer = new ByteWriter())
            {
                writer.WriteString(Name);
                writer.WriteBytes(_RSA.SignData(hash, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1));
                return writer.ToByteArray();
            }
        }

        public void ImportKey(string keyXml)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(keyXml);

            XmlElement root = doc["RSAKeyValue"];

            RSAParameters p = new RSAParameters()
            {
                Modulus = Convert.FromBase64String(root["Modulus"].InnerText),
                Exponent = Convert.FromBase64String(root["Exponent"].InnerText),
                P = Convert.FromBase64String(root["P"].InnerText),
                Q = Convert.FromBase64String(root["Q"].InnerText),
                DP = Convert.FromBase64String(root["DP"].InnerText),
                DQ = Convert.FromBase64String(root["DQ"].InnerText),
                InverseQ = Convert.FromBase64String(root["InverseQ"].InnerText),
                D = Convert.FromBase64String(root["D"].InnerText)
            };

            _RSA.ImportParameters(p);
        }
    }
}