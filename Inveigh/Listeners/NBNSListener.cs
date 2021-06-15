using System;
using System.Net;
using System.Net.Sockets;
using Quiddity;
using Quiddity.NetBIOS;
using Quiddity.Support;

namespace Inveigh
{
    class NBNSListener : NetBIOSNSListener
    {
        public NBNSListener()
        {
            this.TTL = 165;
        }

        public NBNSListener(uint ttl)
        {
            this.TTL = ttl;
        }

        protected override void Output(string protocol, string clientIP, string name, string type, string message)
        {
            Inveigh.Output.SpooferOutput(protocol, type, name, clientIP, message);
        }

        protected override void OutputError(Exception ex)
        {
            Inveigh.Output.Queue(ex.ToString());
        }

        public override bool Check(string name, string type, string clientIP, out string message)
        {

            NetBIOSNSChecker helper = new NetBIOSNSChecker
            {
                IgnoreHosts = Program.argIgnoreHosts,
                ReplyToHosts = Program.argReplyToHosts,
                IgnoreIPs = Program.argIgnoreIPs,
                ReplyToIPs = Program.argReplyToIPs,
                IPCaptures = Program.IPCaptureList,
                Types = Program.argNBNSTypes,
                Enabled = Program.enabledNBNS,
                Repeat = Program.enabledRepeat,
                Inspect = Program.enabledInspect,
            };

            if (helper.Check(name, type, clientIP))
            {
                message = helper.OutputMessage;
                return true;
            }

            message = helper.OutputMessage;
            return false;
        }

    }

}
