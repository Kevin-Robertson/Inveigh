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
using Quiddity.Support;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Quiddity.DHCPv6
{
    class DHCPv6Packet
    {
        public DHCPv6Message Message { get; set; }
        public DHCPv6Option1 Option1 { get; set; }
        public DHCPv6Option2 Option2 { get; set; }
        public DHCPv6Option3 Option3 { get; set; }
        public DHCPv6Option6 Option6 { get; set; }
        public DHCPv6Option8 Option8 { get; set; }
        public DHCPv6Option14 Option14 { get; set; }
        public DHCPv6Option16 Option16 { get; set; }
        public DHCPv6Option23 Option23 { get; set; }
        public DHCPv6Option24 Option24 { get; set; }
        public DHCPv6Option39 Option39 { get; set; }

        public DHCPv6Packet()
        {

        }

        public DHCPv6Packet(byte[] data)
        {
            ReadBytes(data, 0);
        }

        public DHCPv6Packet(byte[] data, int offset)
        {
            ReadBytes(data, offset);
        }

        public void ReadBytes(byte[] data, int offset)
        {
            this.Message = new DHCPv6Message(data);

            if (!Utilities.ArrayIsNullOrEmpty(this.Message.Options))
            {

                using (MemoryStream memoryStream = new MemoryStream(this.Message.Options))
                {
                    PacketReader packetReader = new PacketReader(memoryStream);
                    memoryStream.Position = offset;
                    DHCPv6Option option = new DHCPv6Option();
                    option.ReadBytes(this.Message.Options, 0);

                    while (option.OptionCode != 0 && memoryStream.Length - memoryStream.Position >= 4)
                    {
                        option.ReadBytes(this.Message.Options, (int)memoryStream.Position);

                        switch (option.OptionCode)
                        {
                            case 1:
                                this.Option1 = new DHCPv6Option1(this.Message.Options, (int)memoryStream.Position);
                                break;

                            case 2:
                                this.Option2 = new DHCPv6Option2(this.Message.Options, (int)memoryStream.Position);
                                break;

                            case 3:
                                this.Option3 = new DHCPv6Option3(this.Message.Options, (int)memoryStream.Position);
                                break;

                            case 6:
                                this.Option6 = new DHCPv6Option6(this.Message.Options, (int)memoryStream.Position);
                                break;

                            case 8:
                                this.Option8 = new DHCPv6Option8(this.Message.Options, (int)memoryStream.Position);
                                break;

                            case 14:
                                this.Option14 = new DHCPv6Option14(this.Message.Options, (int)memoryStream.Position);
                                break;

                            case 16:
                                this.Option16 = new DHCPv6Option16(this.Message.Options, (int)memoryStream.Position);
                                break;

                            case 23:
                                this.Option23 = new DHCPv6Option23(this.Message.Options, (int)memoryStream.Position);
                                break;

                            case 24:
                                this.Option24 = new DHCPv6Option24(this.Message.Options, (int)memoryStream.Position);
                                break;

                            case 39:
                                this.Option39 = new DHCPv6Option39(this.Message.Options, (int)memoryStream.Position);
                                break;
                        }

                        memoryStream.Position += option.OptionLen + 4;
                    }

                }

            }

        }

        public byte[] GetBytes()
        {

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.Write(this.Message.MsgType);
                packetWriter.Write(this.Message.TransactionID);

                if (this.Option8 != null)
                {
                    packetWriter.Write(this.Option8.GetBytes());
                }

                if (this.Option1 != null)
                {
                    packetWriter.Write(this.Option1.GetBytes());
                }

                if (this.Option2 != null)
                {
                    packetWriter.Write(this.Option2.GetBytes());
                }

                if (this.Option3 != null)
                {
                    packetWriter.Write(this.Option3.GetBytes());
                }

                if (this.Option23 != null)
                {
                    packetWriter.Write(this.Option23.GetBytes());
                }

                if (this.Option24 != null)
                {
                    packetWriter.Write(this.Option24.GetBytes());
                }

                if (this.Option39 != null)
                {
                    packetWriter.Write(this.Option39.GetBytes());
                }

                if (this.Option16 != null)
                {
                    packetWriter.Write(this.Option16.GetBytes());
                }

                if (this.Option6 != null)
                {
                    packetWriter.Write(this.Option6.GetBytes());
                }

                return memoryStream.ToArray();
            }

        }

        public byte[] GetBytes(byte msgType, string leaseAddress, string listenerMAC, string dnsServer, string dnsSuffix, uint lifetime, DHCPv6Packet dhcpv6Packet)
        {

            this.Message = new DHCPv6Message
            {
                MsgType = msgType,
                TransactionID = dhcpv6Packet.Message.TransactionID
            };

            this.Option1 = dhcpv6Packet.Option1;
            this.Option2 = new DHCPv6Option2(listenerMAC);
            this.Option3 = new DHCPv6Option3(leaseAddress, lifetime, dhcpv6Packet.Option3.IAID);
            this.Option23 = new DHCPv6Option23(dnsServer);

            if (!String.IsNullOrEmpty(dnsSuffix))
            {
                this.Option24 = new DHCPv6Option24(dnsSuffix);
            }

            return GetBytes();
        }

    }
}
