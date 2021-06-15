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
using Quiddity.DHCPv6;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Quiddity
{
    public class DHCPv6Listener
    {
        public string DNSSuffix { get; set; }
        public uint Lifetime { get; set; }
        public int Prefix { get; set; }
        public int Index { get; set; }

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

        public void Start(IPAddress ipAddress, string mac, string dnsIPv6)
        {
            UDPListener listener = new UDPListener(AddressFamily.InterNetworkV6);
            IPEndPoint ipEndPoint = new IPEndPoint(ipAddress, 547);
            listener.JoinMulticastGroup(IPAddress.Parse("ff02::1:2"));
            listener.Client.Bind(ipEndPoint);

            while (true)
            {

                try
                {
                    byte[] receiveBuffer = listener.Receive(ref ipEndPoint);
                    ProcessRequest(receiveBuffer, listener, ipEndPoint, mac, dnsIPv6);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                }

            }

        }

        protected virtual void ProcessRequest(byte[] data, UDPListener udpListener, IPEndPoint ipEndPoint, string listenerMAC, string dnsIPv6)
        {
            string clientIP = ipEndPoint.Address.ToString();
            DHCPv6Packet packet = new DHCPv6Packet(data);

            if (packet.Message?.MsgType == 1 || packet.Message?.MsgType == 3 || packet.Message?.MsgType == 5)
            {
                bool isMicrosoft = false;

                if (packet.Option16?.EnterpriseNumber == 311)
                {
                    isMicrosoft = true;
                }

                byte msgType = 0;
                string leaseIP = "";

                switch (packet.Message.MsgType)
                {
                    case 1:
                        msgType = 2;
                        
                        break;

                    case 3:
                        {
                            byte[] renewIP = new DHCPv6Option5(packet.Option3.IANAOptions).IPv6Address;
                            leaseIP = new IPAddress(renewIP).ToString();
                            msgType = 7;
                        }
                        break;

                    case 5:
                        {
                            byte[] renewIP = new DHCPv6Option5(packet.Option3.IANAOptions).IPv6Address;
                            leaseIP = new IPAddress(renewIP).ToString();
                            msgType = 7;
                        }
                        break;
                }

                byte[] clientMACData = new DHCPv6DUIDLLT(packet.Option1.DUID).LinkLayerAddress;
                string clientMAC = BitConverter.ToString(clientMACData).Replace("-", ":");
                string clientHostName = "";

                if (!String.IsNullOrEmpty(packet.Option39?.DomainName))
                {
                    clientHostName = packet.Option39.DomainName;
                }

                if (Check(clientMAC, clientHostName, listenerMAC, isMicrosoft, out string message))
                {

                    if (msgType == 2)
                    {
                        leaseIP = "fe80::" + this.Prefix + ":" + this.Index;
                        this.Index++;
                    }

                    byte[] buffer = new DHCPv6Packet().GetBytes(msgType, leaseIP, listenerMAC, dnsIPv6, this.DNSSuffix, this.Lifetime, packet);
                    SendTo(buffer, udpListener, ipEndPoint);             
                }

                Output(packet.Message.MsgType, leaseIP, clientIP, clientMAC, clientHostName, message);
            }

        }

        public virtual bool Check(string clientMAC, string clientHostName, string listenerMAC, bool isMicrosoft, out string message)
        {
            message = "response sent";
            return true;
        }

        protected virtual void SendTo(byte[] data, UDPListener udpListener, IPEndPoint ipEndPoint)
        {
            udpListener.Client.SendTo(data, ipEndPoint);
        }

        protected virtual void Output(int msgType, string leaseIP, string clientIP, string clientMAC, string clientHostName, string message)
        {
        }

        protected virtual void OutputError(string message)
        {
        }

    }
}
