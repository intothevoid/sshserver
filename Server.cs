using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace sshserver
{
    public class Server
    {
        private IConfigurationRoot _Configuration;
        private LoggerFactory _LoggerFactory;
        private ILogger _Logger;
        private const int DefaultPort = 22;
        private const int ConectionBacklog = 64;
        private TcpListener _Listener;

        public Server()
        {
            _Configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("sshserver.json", optional:false)
                .Build();

            _LoggerFactory = new LoggerFactory();
            _LoggerFactory.AddConsole(_Configuration.GetSection("Logging"));
            _Logger = _LoggerFactory.CreateLogger("SSHServer");
        }

        public void Start()
        {
            Stop();

            _Logger.LogInformation("Starting up...");

            int port = _Configuration.GetValue<int>("port", DefaultPort);

            _Listener = new TcpListener(IPAddress.Any, port);
            _Listener.Start(ConectionBacklog);

            _Logger.LogInformation($"Listening on port: {port}");
        }

        public void Stop()
        {
            _Logger.LogInformation("Shutting down...");
            
            if (_Listener != null)
            {
                _Listener.Stop();
                _Listener = null;
            }
            
            _Logger.LogInformation("Shutting down...");
        }

        public void Poll()
        {
            // Check for new connections
            while (_Listener.Pending())
            {
                Task<Socket> acceptTask = _Listener.AcceptSocketAsync();
                acceptTask.Wait();

                Socket socket = acceptTask.Result;
                _Logger.LogDebug($"New Client: {socket.RemoteEndPoint}");

                // TODO Accept and maintain client list

            }

            // TODO Poll each client for activity
            // TODO Remove all disconnected clients
        }
    }
}