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

namespace Quiddity.MDNS
{
    class MDNSPacket
    {
        public MDNSHeader Header { get; set; }
        public MDNSQuestion Question { get; set; }
        public MDNSResource Resource { get; set; }
        public MDNSPacket(byte[] data)
        {
            ReadBytes(data);
        }

        public MDNSPacket ReadBytes(byte[] data)
        {
            this.Header = new MDNSHeader(data);
            this.Question = new MDNSQuestion(data);
            return this;
        }

        public byte[] GetBytes(uint ttl, string replyIP, string replyIPv6)
        {

            if (string.Equals(this.Question.Type, "AAAA") && !String.IsNullOrEmpty(replyIPv6))
            {
                replyIP = replyIPv6;
            }

            byte[] rdata = IPAddress.Parse(replyIP).GetAddressBytes();

            this.Header = new MDNSHeader
            {
                ID = this.Header.ID,
                QR = true,
                Opcode = "0000",
                AA = true,
                TC = false,
                RD = false,
                RA = false,
                Z = "0",
                AD = false,
                CD = false,
                RCode = "0000",
                QDCount = 1,
                ANCount = 1
            };

            this.Resource = new MDNSResource
            {
                Name = this.Question.QName,
                Type = this.Question.QType,
                Class = this.Question.QClass,
                TTL = ttl,
                RDLength = (ushort)rdata.Length,
                RData = rdata
            };

            return Utilities.BlockCopy(this.Header.GetBytes(), this.Question.GetBytes(), this.Resource.GetBytes());
        }

    }
}
