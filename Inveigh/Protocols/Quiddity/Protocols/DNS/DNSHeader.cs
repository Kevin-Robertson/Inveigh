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
using System.IO;

namespace Quiddity.DNS
{
    public class DNSHeader
    {
        // https://tools.ietf.org/html/rfc1035
        public byte[] ID { get; set; }
        public bool QR { get; set; } // 1 bit
        public string Opcode { get; set; } // 4 bit
        public bool AA { get; set; } // 1 bit
        public bool TC { get; set; } // 1 bit
        public bool RD { get; set; } // 1 bit
        public bool RA { get; set; } // 1 bit
        public string Z { get; set; } // reserved
        public string RCode { get; set; } // 4 bit
        public ushort QDCount { get; set; }
        public ushort ANCount { get; set; }
        public ushort NSCount { get; set; }
        public ushort ARCount { get; set; }

        // custom
        public byte[] Flags { get; set; }

        public DNSHeader()
        {

        }

        public DNSHeader(byte[] data)
        {
            ReadBytes(data, 0);
        }

        public void ReadBytes(byte[] data, int offset)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = offset;
                this.ID = packetReader.ReadBytes(2);
                this.Flags = packetReader.BigEndianReadBytes(2);
                this.QDCount = packetReader.BigEndianReadUInt16();
                this.ANCount = packetReader.BigEndianReadUInt16();
                this.NSCount = packetReader.BigEndianReadUInt16();
                this.ARCount = packetReader.BigEndianReadUInt16();
            }

            ReadFlags();
        }

        public byte[] GetBytes()
        {
            WriteFlags();

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.Write(this.ID);
                packetWriter.Write(this.Flags);
                packetWriter.BigEndianWrite(this.QDCount);
                packetWriter.BigEndianWrite(this.ANCount);
                packetWriter.BigEndianWrite(this.NSCount);
                packetWriter.BigEndianWrite(this.ARCount);
                return memoryStream.ToArray();
            }

        }

        protected virtual void ReadFlags()
        {
            string flags = Convert.ToString(BitConverter.ToUInt16(this.Flags, 0), 2).PadLeft(16, '0');

            if (String.Equals(flags.Substring(0, 1), "1"))
            {
                this.QR = true;
            }

            this.Opcode = flags.Substring(1, 4);

            if (String.Equals(flags.Substring(5, 1), "1"))
            {
                this.AA = true;
            }

            if (String.Equals(flags.Substring(6, 1), "1"))
            {
                this.TC = true;
            }

            if (String.Equals(flags.Substring(7, 1), "1"))
            {
                this.RD = true;
            }

            if (String.Equals(flags.Substring(7, 1), "1"))
            {
                this.RA = true;
            }

            this.Z = flags.Substring(8, 3);
            this.RCode = flags.Substring(12, 4);
        }

        protected virtual void WriteFlags()
        {
            string flags = this.QR ? "1" : "0";
            flags += this.Opcode;
            flags += this.AA ? "1" : "0";
            flags += this.TC ? "1" : "0";
            flags += this.RD ? "1" : "0";
            flags += this.RA ? "1" : "0";
            flags += this.Z;
            flags += this.RCode;
            byte[] bytes = new byte[2];

            for (int i = 0; i < 2; ++i)
            {
                bytes[i] = Convert.ToByte(flags.Substring(8 * i, 8), 2);
            }

            this.Flags = bytes;
        }

        public bool IsQuery()
        {
            if (!this.QR && this.QDCount == 1)
            {
                return true;
            }

            return false;
        }

    }
}
