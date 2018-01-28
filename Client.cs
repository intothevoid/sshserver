using System;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;

namespace sshserver
{
   public class Client
    {
        private ILogger _Logger;
        private Socket _Socket;
        private bool _ProtocolVersionExchangeComplete = false;
        private string _ProtocolVersionExchange;

        public Client(Socket socket, ILogger logger)
        {
            _Socket = socket;
            _Logger = logger;

            _Socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
            _Socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.DontLinger, true);

            Send($"{ServerConstants.ProtocolVersionExchange}\r\n");
        }

        private void Send(string message)
        {
            _Logger.LogDebug($"Sending raw string: {message.Trim()}");
            Send(Encoding.UTF8.GetBytes(message));
        }

        private void Send(byte[] message)
        {
            if(!IsConnected())
                return;
            
            _Socket.Send(message);
        }

        public bool IsConnected()
        {
            return (_Socket != null);
        }

        public void Poll()
        {
            if(!IsConnected())
                return;
            
            bool dataAvailable = _Socket.Poll(0, SelectMode.SelectRead);

            if(dataAvailable)
            {
                int read = _Socket.Available;

                if(read < 1)
                {
                    Disconnect();
                    return;
                }

                if(!_ProtocolVersionExchangeComplete)
                {
                    try
                    {
                        ReadProtocolVersionExchange();

                        if (_ProtocolVersionExchangeComplete)
                        {
                           _Logger.LogDebug($"Received ProtocolVersionExchange:{_ProtocolVersionExchange}"); 
                        }
                    }
                    catch (System.Exception)
                    {
                        Disconnect();
                        return;
                    }
                }

                if (_ProtocolVersionExchangeComplete)
                {
                   // TODO Read and process packets 
                }
            }
        }

        // Read 1 byte from the socket until \r\n
        private void ReadProtocolVersionExchange()
        {
            NetworkStream stream = new NetworkStream(_Socket, false);
            string result = null;

            List<byte> data = new List<byte>();

            bool foundCR = false;
            int val = stream.ReadByte();

            while(val != -1)
            {
                if(foundCR && (val == '\n'))
                {
                    result = Encoding.UTF8.GetString(data.ToArray());
                    _ProtocolVersionExchangeComplete = true;
                    break;
                }

                if (val == '\r')
                {
                   foundCR = true; 
                }
                else
                {
                    foundCR = false;
                    data.Add((byte)val);
                }

                val = stream.ReadByte();
            }

            _ProtocolVersionExchange += result;
        }

        public void Disconnect()
        {
            _Logger.LogInformation("Client disconnected");

            if (_Socket != null)
            {
                try
                {
                    _Socket.Shutdown(SocketShutdown.Both);
                }

                catch (System.Exception) { }

                _Socket = null;
            }
        }

    };
}