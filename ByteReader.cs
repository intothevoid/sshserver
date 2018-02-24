using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KSSHServer
{
    public class ByteReader : IDisposable
    {
        private readonly char[] _ListSeparator = new char[] {','};
        private MemoryStream _Stream;

        public bool IsEOF 
        { 
            get
            {
                if(disposedValue)
                    throw new ObjectDisposedException("ByteReader");

                return _Stream.Position == _Stream.Length;
            }

            private set {} 
        }

        public ByteReader(byte[] data)
        {
            _Stream = new MemoryStream(data);
        }

        public byte[] GetBytes(int length)
        {
            if(disposedValue)
                throw new ObjectDisposedException("ByteReader");

            byte[] data = new byte[length];
            _Stream.Read(data, 0, length);

            return data;
        }

        public byte[] GetMPInt()
        {
            UInt32 size = GetUInt32();

            if(size == 0)
                return new byte[1];

            byte[] data = GetBytes((int) size);
            
            if (data[0] == 0)
                return data.Skip(1).ToArray();

            return data;
        }

        public UInt32 GetUInt32()
        {
            byte[] data = GetBytes(4); // 4 bytes = UInt32
            
            if(BitConverter.IsLittleEndian)
                data = data.Reverse().ToArray();

            return BitConverter.ToUInt32(data, 0);            
        }

        public string GetString()
        {
            return GetString(Encoding.ASCII);
        }

        public string GetString(Encoding encoding)
        {
            int length = (int)GetUInt32();

            if (length == 0)    
                return string.Empty;
            
            return encoding.GetString(GetBytes(length)); 
        }

        public List<string> GetNameList()
        {
            return new List<string>(GetString().Split(_ListSeparator, StringSplitOptions.RemoveEmptyEntries));
        }

        public bool GetBoolean()
        {
            return (GetByte() != 0);
        }

        public byte GetByte()
        {
            if(disposedValue)
            throw new ObjectDisposedException("ByteReader");

            return (byte)_Stream.ReadByte();
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                   _Stream.Dispose();
                   _Stream = null; 
                }

                disposedValue = true;
            }
        }

       void IDisposable.Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }
        #endregion
    }
}