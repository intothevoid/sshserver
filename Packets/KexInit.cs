using System;

namespace KSSHServer.Packets
{
    public class KexInit : Packet
    {
        protected KexInit()
        {
        }

        public override PacketType PacketType
        {
            get
            {
                return PacketType.SSH_MSG_KEXINIT;
            }
        } 
    }
}