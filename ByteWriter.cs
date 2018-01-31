using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KSSHServer
{
    public class ByteWriter : IDisposable
    {
        private MemoryStream _Stream = new MemoryStream();

        public void WritePacketType(Packets.PacketType packetType)
        {
            WriteByte((byte)packetType);
        }

        public void WriteByte(byte value)
        {
            if (disposedValue)
                throw new ObjectDisposedException("ByteWriter");

            _Stream.WriteByte(value);
        }

        public void WriteBytes(byte[] data)
        {
            WriteUInt32((uint)data.Count());
            WriteRawBytes(data);

        }

        public void WriteString(string data)
        {
            WriteString(data, Encoding.ASCII);
        }
        public void WriteString(string data, Encoding encoding)
        {
            WriteBytes(encoding.GetBytes(data));
        }

        public void WriteStringList(IEnumerable list)
        {
            WriteString(string.Join(",", list));
        }

        public void WriteUInt32(uint data)
        {
            byte[] buffer = BitConverter.GetBytes(data);

            if (BitConverter.IsLittleEndian)
                buffer = buffer.Reverse().ToArray();

            WriteRawBytes(buffer);
        }

        public void WriteMPInt(byte[] value)
        {
            if ((value.Length == 1) && (value[0] == 0))
            {
                WriteUInt32(0);
                return;
            }

            uint length = (uint)value.Length;
            if ((value[0] & 0x80) != 0)
            {
                WriteUInt32((uint)length + 1);
                WriteByte(0x00);
            }
            else
            {
                WriteUInt32((uint)length);
            }

            WriteRawBytes(value);
        }

        public void WriteRawBytes(byte[] value)
        {
            if (disposedValue)
                throw new ObjectDisposedException("ByteWriter");

            _Stream.Write(value, 0, value.Count());
        }

        public byte[] ToByteArray()
        {
            if (disposedValue)
                throw new ObjectDisposedException("ByteWriter");

            return _Stream.ToArray();
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

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }
        #endregion 
    }
}