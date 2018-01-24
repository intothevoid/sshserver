namespace sshserver
{
    public class Server
    {
        private IConfigurationRoot _configuration;
        private LoggerFactory _loggerFactory;
        private ILogger _logger;

        public Server()
        {
            _configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("sshserver.json", optional:false)
                .Build()

            _loggerFactory = new LoggerFactory();
            _loggerFactory.AddConsole(_configuration.GetSection("Logging"));
            _logger = _loggerFactory.CreateLogger("SSHServer");
        }

    }
}