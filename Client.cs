using System;
using System.Collections;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace sshserver
{
   class Client
   {
      private ILogger _Logger;
      private Socket _Socket;

      public Client(Socket socket, ILogger logger)
      {
          _Socket = socket;
          _Logger = logger;
      }

      public bool IsConnected()
      {
          return (_Socket == null);
      }

      public void Poll()
      {
          // Implement processing of data for client
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

            catch (System.Exception) {}
            
            _Socket = null;
        }
      }

   };
}