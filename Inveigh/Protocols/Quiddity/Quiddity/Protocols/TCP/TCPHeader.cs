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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Quiddity.TCP
{
    class TCPHeader
    {
        // https://datatracker.ietf.org/doc/html/rfc793#section-3.1
        public ushort SourcePort { get; set; }
        public ushort DestinationPort { get; set; }
        public uint SequenceNumber { get; set; }
        public uint AcknowledgementNumber { get; set; }
        public int DataOffset { get; set; }
        public int Reserved { get; set; }
        public bool URG { get; set; }
        public bool ACK { get; set; }
        public bool PSH { get; set; }
        public bool RST { get; set; }
        public bool SYN { get; set; }
        public bool FIN { get; set; }
        public ushort Window { get; set; }
        public ushort Checksum { get; set; }
        public ushort UrgentPointer { get; set; }
        public byte[] Options { get; set; }
        public byte[] Padding { get; set; }

        // custom
        public string Flags { get; set; }

        public void ReadBytes(byte[] data, int position)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = position;
                this.SourcePort = packetReader.BigEndianReadUInt16();
                this.DestinationPort = packetReader.BigEndianReadUInt16();
                this.SequenceNumber = packetReader.BigEndianReadUInt32();
                this.AcknowledgementNumber = packetReader.BigEndianReadUInt32();
                this.Flags = packetReader.ReadBinary(2);
                ReadFlags();
                this.Window = packetReader.BigEndianReadUInt16();
                this.Checksum = packetReader.BigEndianReadUInt16();
                this.UrgentPointer = packetReader.BigEndianReadUInt16();
                this.Options = packetReader.BigEndianReadBytes(3);
                this.Padding = packetReader.BigEndianReadBytes(3);
            }

        }

        protected virtual void ReadFlags()
        {
            this.DataOffset = Convert.ToInt32(this.Flags.Substring(0, 4), 2) * 4;
            this.Reserved = Convert.ToInt32(this.Flags.Substring(4, 3), 2);

            if (string.Equals(this.Flags.Substring(10, 1), "1"))
            {
                this.URG = true;
            }

            if (string.Equals(this.Flags.Substring(11, 1), "1"))
            {
                this.ACK = true;
            }

            if (string.Equals(this.Flags.Substring(12, 1), "1"))
            {
                this.PSH = true;
            }

            if (string.Equals(this.Flags.Substring(13, 1), "1"))
            {
                this.RST = true;
            }

            if (string.Equals(this.Flags.Substring(14, 1), "1"))
            {
                this.SYN = true;
            }

            if (string.Equals(this.Flags.Substring(15, 1), "1"))
            {
                this.FIN = true;
            }

        }

    }
}
