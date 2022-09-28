using Quiddity.MDNS;
using System;

namespace Inveigh
{
    class MDNSListener : Quiddity.MDNSListener
    {

        public MDNSListener()
        {
            this.TTL = 120;
        }

        public MDNSListener(uint ttl, bool unicastOnly)
        {
            this.TTL = ttl;
            this.UnicastOnly = unicastOnly;
        }

        protected override void Output(string protocol, string clientIP, string name, string question, string type, string message)
        {
            type = string.Concat(question, ")(", type); 
            Inveigh.Output.SpooferOutput(protocol, type, name, clientIP, message);
        }

        protected override void OutputError(Exception ex)
        {
            Inveigh.Output.Queue(ex.ToString());
        }

        public override bool Check(string name, string question, string type, string clientIP, out string message)
        {

            MDNSChecker mdnsHelper = new MDNSChecker
            {
                IgnoreQueries = Program.argIgnoreQueries,
                ReplyToQueries = Program.argReplyToQueries,
                IgnoreIPs = Program.argIgnoreIPs,
                ReplyToIPs = Program.argReplyToIPs,
                IPCaptures = Program.IPCaptureList,
                Questions = Program.argMDNSQuestions,
                Types = Program.argMDNSTypes,
                Enabled = Program.enabledMDNS,
                Repeat = Program.enabledRepeat,
                Inspect = Program.enabledInspect,
            };

            if (mdnsHelper.Check(name, question, type, clientIP))
            {
                message = mdnsHelper.OutputMessage;
                return true;
            }

            message = mdnsHelper.OutputMessage;
            return false;
        }

    }
}
