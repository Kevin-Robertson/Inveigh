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
using System;
using System.Text;
using System.IO;

namespace Quiddity.NTLM
{
    class NTLMAVPair
    {
        //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
        public ushort AvId { get; set; }
        public ushort AvLen { get; set; }
        public byte[] Value { get; set; }

        public NTLMAVPair()
        {
            this.AvId = 0;
            this.AvLen = 0;
            this.Value = new byte[0];
        }

        public byte[] GetBytes(string netBIOSDomainName, string netBIOSComputerName, string dnsDomainName, string dnsComputerName, string dnsTreeName, byte[] timestamp)
        {

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);

                if (!String.IsNullOrEmpty(netBIOSDomainName))
                {
                    this.AvId = 2;
                    this.Value = Encoding.Unicode.GetBytes(netBIOSDomainName);
                    this.AvLen = (ushort)this.Value.Length;
                    packetWriter.Write(this.AvId);
                    packetWriter.Write(this.AvLen);
                    packetWriter.Write(this.Value);
                }

                if (!String.IsNullOrEmpty(netBIOSComputerName))
                {
                    this.AvId = 1;
                    this.Value = Encoding.Unicode.GetBytes(netBIOSComputerName);
                    this.AvLen = (ushort)this.Value.Length;
                    packetWriter.Write(this.AvId);
                    packetWriter.Write(this.AvLen);
                    packetWriter.Write(this.Value);
                }

                if (!String.IsNullOrEmpty(dnsDomainName))
                {
                    this.AvId = 4;
                    this.Value = Encoding.Unicode.GetBytes(dnsDomainName);
                    this.AvLen = (ushort)this.Value.Length;
                    packetWriter.Write(this.AvId);
                    packetWriter.Write(this.AvLen);
                    packetWriter.Write(this.Value);
                }

                if (!String.IsNullOrEmpty(dnsComputerName))
                {
                    this.AvId = 3;
                    this.Value = Encoding.Unicode.GetBytes(dnsComputerName);
                    this.AvLen = (ushort)this.Value.Length;
                    packetWriter.Write(this.AvId);
                    packetWriter.Write(this.AvLen);
                    packetWriter.Write(this.Value);
                }

                if (!String.IsNullOrEmpty(dnsTreeName) && !String.Equals(dnsTreeName, netBIOSComputerName))
                {
                    this.AvId = 5;
                    this.Value = Encoding.Unicode.GetBytes(dnsTreeName);
                    this.AvLen = (ushort)this.Value.Length;
                    packetWriter.Write(this.AvId);
                    packetWriter.Write(this.AvLen);
                    packetWriter.Write(this.Value);
                }

                this.AvId = 7;
                this.Value = timestamp;
                this.AvLen = 8;
                packetWriter.Write(this.AvId);
                packetWriter.Write(this.AvLen);
                packetWriter.Write(this.Value);

                this.AvId = 0;
                this.AvLen = 0;
                packetWriter.Write(this.AvId);
                packetWriter.Write(this.AvLen);

                return memoryStream.ToArray();
            }

        }

    }

}
