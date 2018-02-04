using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Collections.Generic;
using KSSHServer.KexAlgorithms;
using KSSHServer.HostKeyAlgorithms;

namespace KSSHServer
{
    public static class ServerConstants
    {
        public const string ProtocolVersionExchange = "SSH-2.0-ksshserver";
    }
    public class Server
    {
        private IConfigurationRoot _Configuration;
        private LoggerFactory _LoggerFactory;
        private ILogger _Logger;
        private const int DefaultPort = 22;
        private const int ConectionBacklog = 64;
        private TcpListener _Listener;
        private List<Client> _Clients = new List<Client>();
        private static Dictionary<string, string> _HostKeys = new Dictionary<string, string>();

        public Server()
        {
            _Configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("sshserver.json", optional: false)
                .Build();

            _LoggerFactory = new LoggerFactory();
            _LoggerFactory.AddConsole(_Configuration.GetSection("Logging"));
            _Logger = _LoggerFactory.CreateLogger("SSHServer");

            IConfigurationSection keys = _Configuration.GetSection("keys");
            foreach (IConfigurationSection key in keys.GetChildren())   
            {
               _HostKeys[key.Key] = key.Value; 
            }
        }

        public static IReadOnlyList<Type> SupportedHostKeyAlgorithms { get; private set; } = new List<Type>()
        {
            typeof(SSHRSA)
        };

        public static T GetType<T>(IReadOnlyList<Type> types, string selected) where T : class
        {
            foreach (Type type in types)
            {
                IAlgorithm algo = Activator.CreateInstance(type) as IAlgorithm;
                if (algo.Name.Equals(selected, StringComparison.OrdinalIgnoreCase))
                {
                    if (algo is IHostKeyAlgorithm)
                    {
                       ((IHostKeyAlgorithm)algo).ImportKey(_HostKeys[algo.Name]); 
                    }   

                    return algo as T;
                }
            }

            return default(T);
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
            if (_Listener != null)
            {
                _Logger.LogInformation("Shutting down...");

                _Listener.Stop();
                _Listener = null;

                // Disconnect each client and clear list
                _Clients.ForEach(c => c.Disconnect());
                _Clients.Clear();

                _Logger.LogInformation("Shutting down...");
            }
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

                _Clients.Add(new Client(socket, _LoggerFactory.CreateLogger(socket.RemoteEndPoint.ToString())));

            }

            // Poll each client
            _Clients.ForEach(c => c.Poll());

            // Remove all disconnected clients
            _Clients.RemoveAll(c => c.IsConnected() == false);
        }

        public static IReadOnlyList<Type> SupportedCiphers { get; private set; } = new List<Type>()
        {
            // typeof(Ciphers.NoCipher),
            typeof(Ciphers.TripleDESCBC)
        };
        
        public static IReadOnlyList<Type> SupportedKexAlgorithms { get; private set; } = new List<Type>()
        {
            typeof(DiffieHellmanGroup14SHA1)
        };

        public static IEnumerable<string> GetNames(IReadOnlyList<Type> types)
        {
            foreach (Type type in types)
            {
                IAlgorithm algo = Activator.CreateInstance(type) as IAlgorithm;
                yield return type.Name;
            }
        }
    }
}