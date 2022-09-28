using System;
using Quiddity.LLMNR;

namespace Inveigh
{
    class LLMNRListener : Quiddity.LLMNRListener
    {
        internal LLMNRListener()
        {
            this.TTL = 300;
        }

        internal LLMNRListener(uint ttl)
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

            LLMNRChecker llmnrChecker = new LLMNRChecker
            {
                IgnoreQueries = Program.argIgnoreQueries,
                ReplyToQueries = Program.argReplyToQueries,
                IgnoreIPs = Program.argIgnoreIPs,
                ReplyToIPs = Program.argReplyToIPs,
                IPCaptures = Program.IPCaptureList,
                Types = Program.argLLMNRTypes,
                Enabled = Program.enabledLLMNR,
                Repeat = Program.enabledRepeat,
                Inspect = Program.enabledInspect,
            };

            if (llmnrChecker.Check(name, type, clientIP))
            {
                message = llmnrChecker.OutputMessage;
                return true;
            }

            message = llmnrChecker.OutputMessage;
            return false;
        }

    }

}
