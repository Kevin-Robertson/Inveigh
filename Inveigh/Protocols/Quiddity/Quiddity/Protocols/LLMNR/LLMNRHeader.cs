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
using Quiddity.DNS;
using System;

namespace Quiddity.LLMNR
{
    class LLMNRHeader : DNSHeader
    {
        // https://tools.ietf.org/html/rfc4795#section-2.1

        public bool C { get; set; } // 1 bit
        public bool T { get; set; } // 1 bit

        public LLMNRHeader()
        {

        }

        public LLMNRHeader (byte[] data)
        {
            ReadBytes(data, 0);
        }

        public byte[] GetPacket(uint ttl, string ip, string ipv6, byte[] data, out string name, out string type)
        {
            this.ReadBytes(data, 0);
            name = "";
            type = "A";

            if (!this.QR)
            {
                LLMNRQuestion question = new LLMNRQuestion();
                question.ReadBytes(data, 12);

                if (string.Equals(BitConverter.ToString(question.QType), "00-1C"))
                {
                    type = "AAAA";
                    ip = ipv6;
                }

                LLMNRResource response = new LLMNRResource();
                return response.GetBytes(question, ttl, ip, this.ID);
            }

            return null;
        }


        protected override void ReadFlags()
        {
            string flags = Convert.ToString(BitConverter.ToUInt16(this.Flags, 0), 2).PadLeft(16, '0');

            if (string.Equals(flags.Substring(0, 1), "1"))
            {
                this.QR = true;
            }

            this.Opcode = flags.Substring(1, 4);

            if (string.Equals(flags.Substring(5, 1), "1"))
            {
                this.C = true;
            }

            if (string.Equals(flags.Substring(6, 1), "1"))
            {
                this.TC = true;
            }

            if (string.Equals(flags.Substring(7, 1), "1"))
            {
                this.T = true;
            }

            this.Z = flags.Substring(8, 4);
            this.RCode = flags.Substring(12, 4);
        }

        protected override void WriteFlags()
        {
            string flags = this.QR ? "1" : "0";
            flags += this.Opcode;
            flags += this.C ? "1" : "0";
            flags += this.TC ? "1" : "0";
            flags += this.T ? "1" : "0";
            flags += this.Z;
            flags += this.RCode;
            byte[] bytes = new byte[2];

            for (int i = 0; i < 2; ++i)
            {
                bytes[i] = Convert.ToByte(flags.Substring(8 * i, 8), 2);
            }

            this.Flags = bytes;
        }

    }

}
