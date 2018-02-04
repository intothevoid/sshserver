using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KSSHServer.Packets;

namespace KSSHServer
{
    public class KSSHServerException : Exception
    {
        public DisconnectReason Reason { get; set; }

        public KSSHServerException(DisconnectReason reason, string message) : base(message)
        {
            Reason = reason;
        }
    }
}