using Quiddity.DNS;
using System;

namespace Inveigh
{
    class DNSListener : Quiddity.DNSListener
    {
        internal DNSListener()
        {
            this.TTL = 30;
        }

        internal DNSListener(uint ttl)
        {
            this.TTL = ttl;
        }

        internal DNSListener(uint ttl, string host)
        {
            this.Serial = Program.dnsSerial;
            this.TTL = ttl;
            this.Host = host;
            this.Priority = 0;
            this.Weight = 100;
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

            DNSChecker helper = new DNSChecker
            {
                IgnoreHosts = Program.argIgnoreHosts,
                ReplyToHosts = Program.argReplyToHosts,
                IgnoreIPs = Program.argIgnoreIPs,
                ReplyToIPs = Program.argReplyToIPs,
                IgnoreDomains = Program.argIgnoreDomains,
                ReplyToDomains = Program.argReplyToDomains,
                IPCaptures = Program.IPCaptureList,
                Types = Program.argDNSTypes,
                Services = Program.argDNSSRV,
                Enabled = Program.enabledDNS,
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
