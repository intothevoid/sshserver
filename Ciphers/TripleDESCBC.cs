using System;
using System.IO;
using System.Security.Cryptography;

namespace KSSHServer.Ciphers
{
    public class TripleDESCBC : ICipher
    {
        private TripleDES _3DES = TripleDES.Create();
        private ICryptoTransform _Encryptor;
        private ICryptoTransform _Decryptor;
        public uint BlockSize
        {
            get
            {
                // TripleDES.BlockSize is the size of the block in bits, so we need to divide by 8
                // to convert from bits to bytes.
                return (uint)(_3DES.BlockSize / 8);
            }
        }

        public uint KeySize
        {
            get
            {
                // TripleDES.KeySize is the size of the key in bits, so we need to divide by 8
                // to convert from bits to bytes.
                return (uint)(_3DES.KeySize / 8);
            }
        }

        public string Name
        {
            get
            {
               return "3des-cbc"; 
            }
        }

        public byte[] Decrypt(byte[] data)
        {
           return PerformTransform(_Decryptor, data);
        }

        public byte[] Encrypt(byte[] data)
        {
           return PerformTransform(_Encryptor, data);
        }

        private byte[] PerformTransform(ICryptoTransform transform, byte[] data)
        {
            if (transform == null)
                throw new InvalidOperationException("SetKey must be called before attempting to encrypt or decrypt data.");

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
                {
                   cryptoStream.Write(data, 0, data.Length);
                   cryptoStream.FlushFinalBlock();
                   return memoryStream.ToArray(); 
                }
                
            }
                
            
        }

        public void SetKey(byte[] key, byte[] iv)
        {
            _3DES.KeySize = 192;
            _3DES.Key = key;
            _3DES.IV = iv;
            _3DES.Padding = PaddingMode.None;
            _3DES.Mode = CipherMode.CBC;

            _Decryptor = _3DES.CreateDecryptor(key, iv);
            _Encryptor = _3DES.CreateEncryptor(key, iv);
        }
    }
}