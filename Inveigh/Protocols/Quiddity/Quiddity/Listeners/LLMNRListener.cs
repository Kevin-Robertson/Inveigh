/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2021, Kevin Robertson
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
using Quiddity.LLMNR;
using System;
using System.Net;
using System.Net.Sockets;

namespace Quiddity
{
    public class LLMNRListener : DNSListener
    {

        public LLMNRListener()
        {
            this.TTL = 300;
        }

        public new void Start(IPAddress ipAddress, string replyIP, string replyIPv6)
        {
            UDPListener listener = new UDPListener(AddressFamily.InterNetwork);
            IPEndPoint ipEndPoint = new IPEndPoint(ipAddress, 5355);

            if (String.Equals(ipAddress.AddressFamily.ToString(), "InterNetwork"))
            {
                listener.JoinMulticastGroup(IPAddress.Parse("224.0.0.252"));
            }
            else
            {
                listener = new UDPListener(AddressFamily.InterNetworkV6);
                listener.JoinMulticastGroup(IPAddress.Parse("ff02::1:3"));
            }

            listener.Client.Bind(ipEndPoint);

            while (true)
            {

                try
                {
                    byte[] receiveBuffer = listener.Receive(ref ipEndPoint);
                    ProcessRequest(receiveBuffer, listener, ipEndPoint, replyIP, replyIPv6);
                }
                catch (Exception ex)
                {
                    OutputError(ex);
                }

            }

        }

        protected override void ProcessRequest(byte[] data, UDPListener udpListener, IPEndPoint ipEndPoint, string replyIP, string replyIPv6)
        {
            string clientIP = ipEndPoint.Address.ToString();
            LLMNRPacket packet = new LLMNRPacket(data);

            if (packet.Header.IsQuery())
            {

                if (Check(packet.Question.Name, packet.Question.Type, clientIP, out string message))
                {
                    byte[] buffer = packet.GetBytes(this.TTL, replyIP, replyIPv6);
                    SendTo(buffer, udpListener, ipEndPoint);
                }

                Output("LLMNR", clientIP, packet.Question.Name, packet.Question.Type, message);
            }

        }

    }
}
