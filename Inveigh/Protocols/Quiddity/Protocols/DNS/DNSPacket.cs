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
using System.Linq;
using System.Net;
using System.Text;

namespace Quiddity.DNS
{
    class DNSPacket
    {
        public DNSHeader Header { get; set; }
        public DNSQuestion Question { get; set; }
        public DNSResource Resource { get; set; }
        public DNSResource Additional { get; set; }

        public uint TTL { get; set; }
        public string Host { get; set; }

        enum ServicePort : ushort
        {
            Kerberos = 88,
            LDAP = 389,
            KPassword = 464,
            GC = 3268         
        }

        public DNSPacket()
        {
        }

        public DNSPacket(byte[] data)
        {
            ReadBytes(data);
        }

        public DNSPacket ReadBytes(byte[] data)
        {
            this.Header = new DNSHeader(data);
            this.Question = new DNSQuestion(data);
            return this;
        }

        public byte[] GetBytes(uint ttl, uint serial, string replyIP, string replyIPv6)
        {
            byte[] rdata = new byte[0];
            ushort arCount = 0;
            ushort index = 12;
            index |= (1 << 15); // set first 2 bits to 1 to indicate compression is being used
            index |= (1 << 14);
            byte[] indexData = BitConverter.GetBytes(index);
            Array.Reverse(indexData);
            byte[] nameData = this.Question.QName;

            switch (this.Question.Type)
            {
                case "A":
                    arCount = 0;
                    rdata = new DNSRecordA(replyIP).GetBytes();
                    break;

                case "AAAA":
                    arCount = 0;

                    if (!String.IsNullOrEmpty(replyIPv6))
                    {
                        rdata = new DNSRecordAAAA(replyIPv6).GetBytes();
                    }

                    break;

                case "SRV":
                    arCount = 1;
                    nameData = indexData;                 
                    index += (ushort)(this.Question.QName.Length + 14);
                    ushort port = 0;

                    if (this.Question.Name.StartsWith("_ldap."))
                    {
                        port = (ushort)ServicePort.LDAP;
                    }
                    else if (this.Question.Name.StartsWith("_kerberos."))
                    {
                        port = (ushort)ServicePort.Kerberos;
                    }
                    else if (this.Question.Name.StartsWith("_kpassword."))
                    {
                        port = (ushort)ServicePort.KPassword;
                    }
                    else if (this.Question.Name.StartsWith("_gc."))
                    {
                        port = (ushort)ServicePort.GC;
                    }

                    rdata = new DNSRecordSRV().GetBytes(this.Host, port);
                    break;

                case "SOA":
                    arCount = 1;
                    rdata = new DNSRecordSOA(serial).GetBytes(this.Host, 12);
                    index += (ushort)(this.Question.QName.Length + 14);
                    break;
            }

            this.Header = new DNSHeader
            {
                ID = this.Header.ID,
                QR = true,
                Opcode = "0000",
                AA = false,
                TC = false,
                RD = false,
                RA = false,
                Z = "000",
                RCode = "0000",
                QDCount = 1,
                ANCount = 1,
                ARCount = arCount
        };

            this.Resource = new DNSResource
            {
                Name = nameData,
                Type = this.Question.QType,
                Class = this.Question.QClass,
                TTL = ttl,
                RDLength = (ushort)rdata.Length,
                RData = rdata
            };

            if (arCount == 1)
            {
                this.Resource.Name = indexData;            
                indexData = BitConverter.GetBytes(index);
                Array.Reverse(indexData);

                this.Additional = new DNSResource
                {
                    Name = indexData,
                    Type = new byte[] { 0x00, 0x01 },
                    Class = this.Question.QClass,
                    TTL = ttl,
                    RDLength = 4,
                    RData = new DNSRecordA(replyIP).GetBytes()
                };

                return Utilities.BlockCopy(this.Header.GetBytes(), this.Question.GetBytes(), this.Resource.GetBytes(), this.Additional.GetBytes());
            }

            return Utilities.BlockCopy(this.Header.GetBytes(), this.Question.GetBytes(), this.Resource.GetBytes());
        }

    }
}
