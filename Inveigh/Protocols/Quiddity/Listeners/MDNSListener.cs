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
using Quiddity.MDNS;
using System;
using System.Net;
using System.Net.Sockets;

namespace Quiddity
{
    public class MDNSListener : DNSListener
    {
        public bool UnicastOnly { get; set; }

        public MDNSListener()
        {
            this.TTL = 120;
        }

        public MDNSListener(uint ttl, bool unicastOnly)
        {
            this.TTL = ttl;
            this.UnicastOnly = unicastOnly;
        }

        public new void Start(IPAddress ipAddress, string replyIP, string replyIPv6)
        {
            UDPListener listener = new UDPListener(AddressFamily.InterNetwork);
            IPEndPoint ipEndPoint = new IPEndPoint(ipAddress, 5353);

            if (string.Equals(ipAddress.AddressFamily.ToString(), "InterNetwork"))
            {
                listener.JoinMulticastGroup(IPAddress.Parse("224.0.0.251"), ipAddress);
            }
            else
            {
                listener = new UDPListener(AddressFamily.InterNetworkV6);
                listener.JoinMulticastGroup(IPAddress.Parse("ff02::fb"));
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
            MDNSPacket packet = new MDNSPacket(data);

            if (packet.Header.IsQuery())
            {

                if (Check(packet.Question.Name, packet.Question.QuestionType, packet.Question.Type, clientIP, out string message))
                {

                    if (packet.Question.QuestionType.Equals("QM") && !this.UnicastOnly && string.Equals(ipEndPoint.Address.AddressFamily.ToString(), "InterNetwork"))
                    {
                        ipEndPoint.Address = IPAddress.Parse("224.0.0.251");
                    }
                    else if (packet.Question.QuestionType.Equals("QM") && !this.UnicastOnly && string.Equals(ipEndPoint.Address.AddressFamily.ToString(), "InterNetworkV6"))
                    {
                        ipEndPoint.Address = IPAddress.Parse("ff02::fb");
                    }

                    byte[] buffer = packet.GetBytes(this.TTL, replyIP, replyIPv6);
                    SendTo(buffer, udpListener, ipEndPoint);
                }

                Output("mDNS", clientIP, packet.Question.Name, packet.Question.QuestionType, packet.Question.Type, message);
            }

        }
    }
}
