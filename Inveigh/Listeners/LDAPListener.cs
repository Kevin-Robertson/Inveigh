using System;

namespace Inveigh
{
    class LDAPListener : Quiddity.LDAPListener
    {

        protected override void OutputChallenge(string listenerPort, string clientIP, string clientPort, string challenge)
        {
            Output.Queue(String.Format("[+] [{0}] LDAP({1}) NTLM challenge [{2}] sent to {3}:{4}", Output.Timestamp(), listenerPort, challenge, clientIP, clientPort));
        }

        protected override void OutputNTLM(string protocol, string listenerPort, string clientIP, string clientPort, string user, string domain, string host, string ntlmChallenge, string ntlmResponseHash, string lmResponseHash)
        {
            Output.NTLMOutput(user, domain, ntlmChallenge, ntlmResponseHash, clientIP, host, protocol, listenerPort, clientPort, lmResponseHash);
        }

        protected override void OutputError(Exception ex, int port)
        {

            if (ex.Message.ToString().Equals("An attempt was made to access a socket in a way forbidden by its access permissions"))
            {
                Output.Queue(String.Format("[!] Failed to start LDAP listener on port {0}, check IP and port usage.", port));
            }
            else
            {
                Output.Queue(ex.ToString());
            }

        }

    }
}
