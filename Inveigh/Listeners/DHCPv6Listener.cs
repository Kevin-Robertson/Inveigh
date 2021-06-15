using Quiddity.DHCPv6;
using System;

namespace Inveigh
{
    class DHCPv6Listener : Quiddity.DHCPv6Listener
    {
        public DHCPv6Listener()
        {
            this.Index = 1;
            this.DNSSuffix = "";
            this.Lifetime = 300;
            this.Prefix = (new Random()).Next(1, 9999);
        }

        public DHCPv6Listener(uint lifetime, string dnsSuffix)
        {
            this.Index = 1;
            this.DNSSuffix = dnsSuffix;
            this.Lifetime = lifetime;
            this.Prefix = (new Random()).Next(1, 9999);
        }

        protected override void Output(int msgType, string leaseIP, string clientIP, string clientMAC, string clientHostname, string message)
        {
            Inveigh.Output.DHCPv6Output(msgType, leaseIP, clientIP, clientMAC, clientHostname, message);
        }

        protected override void OutputError(string message)
        {
            Inveigh.Output.Queue(message);
        }

        public override bool Check(string clientMAC, string clientHost, string listenerMAC, bool isMicrosoft, out string message)
        {

            DHCPv6Checker helper = new DHCPv6Checker
            {
                Enabled = Program.enabledDHCPv6,
                Repeat = Program.enabledRepeat,
                Inspect = Program.enabledInspect,
                IgnoreMACs = Program.argIgnoreMACs,
                Local = Program.enabledLocal,
                ReplyToMACs = Program.argReplyToMACs,
                HostCaptures = Program.HostCaptureList,
                OutputReplyAllowed = "response sent",
                OutputInspect = "inspect only",
                OutputDisabled = "disabled",
                OutputLocal = "local ignored",
                OutputHostDenied = "host ignored",
                OutputIPDenied = "IP ignored",
                OutputMACDenied = "MAC ignored",
                OutputVendorDenied = "vendor ignored",
                OutputRepeat = "previous capture",
            };

            if (helper.Check(clientMAC, clientHost, listenerMAC, isMicrosoft))
            {
                message = helper.OutputMessage;
                return true;
            }

            message = helper.OutputMessage;
            return false;
        }

    }

}
