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
using System.IO;
using System.Net;

namespace Quiddity.DNS
{

    class DNSResource
    {

        // https://tools.ietf.org/html/rfc1035
        public byte[] Name { get; set; }
        public byte[] Type { get; set; }
        public byte[] Class { get; set; }
        public uint TTL { get; set; }
        public ushort RDLength{ get; set; }
        public byte[] RData { get; set; }

        //custom
        public string Host { get; set; }

        public DNSResource()
        {

        }

        public void ReadBytes(byte[] data, int offset)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = offset;
                this.Name = packetReader.ReadBytes(2);
                this.Type = packetReader.ReadBytes(2);
                this.Class = packetReader.ReadBytes(2);
                this.TTL = packetReader.ReadUInt32();
                this.RDLength = packetReader.ReadUInt16();
                this.RData = packetReader.ReadBytes(this.RDLength);
            }

        }

        public byte[] GetBytes()
        {

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.Write(this.Name);
                packetWriter.Write(this.Type);
                packetWriter.Write(this.Class);
                packetWriter.BigEndianWrite(this.TTL);
                packetWriter.BigEndianWrite(this.RDLength);
                packetWriter.Write(this.RData);
                return memoryStream.ToArray();
            }

        }

        public byte[] GetBytes(DNSQuestion RequestQuestion, uint ttl, string data, byte[] id)
        {
            byte[] rdata = IPAddress.Parse(data).GetAddressBytes();

            DNSHeader responseHeader = new DNSHeader
            {
                ID = id,
                QR = true,
                Opcode = "0000",
                AA = false,
                TC = false,
                RD = false,
                RA = false,
                Z = "000",
                RCode = "0000",
                QDCount = 1,
                ANCount = 1
            };

            this.Name = RequestQuestion.QName;
            this.Type = RequestQuestion.QType;
            this.Class = RequestQuestion.QClass;
            this.TTL = ttl;
            this.RDLength = (ushort)rdata.Length;
            this.RData = rdata;

            return Utilities.BlockCopy(responseHeader.GetBytes(), RequestQuestion.GetBytes(), this.GetBytes());
        }

    }
}
