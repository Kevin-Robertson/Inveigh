/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2025, Kevin Robertson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
using System;

namespace Inveigh
{
    class SMBListener : Quiddity.SMBListener
    {

        protected override void OutputChallenge(string listenerPort, string clientIP, string clientPort, string challenge)
        {
            Output.Queue(String.Format("[+] [{0}] SMB({1}) NTLM challenge [{2}] sent to {3}:{4}", Output.Timestamp(), listenerPort, challenge, clientIP, clientPort));
        }

        protected override void OutputNTLM(string protocol, string listenerPort, string clientIP, string clientPort, string user, string domain, string host, string ntlmChallenge, string ntlmResponseHash, string lmResponseHash)
        {
            Output.NTLMOutput(user, domain, ntlmChallenge, ntlmResponseHash, clientIP, host, protocol, listenerPort, clientPort, lmResponseHash);
        }

        protected override void OutputNegotiation(string protocol, string listenerPort, string clientIP, string clientPort)
        {
            Output.Queue(String.Format("[.] [{0}] {1}({2}) negotiation request received from {3}:{4}", Output.Timestamp(), protocol, listenerPort, clientIP, clientPort));
        }

        protected override void OutputError(Exception ex, int port)
        {

            if (ex.Message.ToString().Contains("An attempt was made to access a socket in a way forbidden by its access permissions"))
            {
                Output.Queue(String.Format("[!] Failed to start SMB listener on port {0}, check IP and port usage.", port));
            }
            else
            {
                Output.Queue(ex.ToString());
            }

        }

    }

}
