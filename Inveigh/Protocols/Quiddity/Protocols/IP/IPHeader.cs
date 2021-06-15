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
using System.Net;

namespace Quiddity.IP
{
    class IPHeader
    {
        // https://datatracker.ietf.org/doc/html/rfc791#section-3.1
        public int Version { get; set; }
        public int IHL { get; set; }
        public byte TypeOfService { get; set; }
        public ushort TotalLength { get; set; }
        public ushort Identification { get; set; }      
        public string Flags { get; set; }
        public int FragmentOffset { get; set; }
        public byte TimeToLive { get; set; }
        public byte Protocol { get; set; }
        public ushort HeaderChecksum { get; set; }
        public IPAddress SourceAddress { get; set; }
        public IPAddress DestinationAddress { get; set; }
        public byte[] Options { get; set; }
        public byte[] Padding { get; set; }

        public void ReadBytes(byte[] data, int position)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = position;
                string versionIHL = packetReader.ReadBinary(1);
                this.Version = Convert.ToInt32(versionIHL.Substring(0, 4), 2);
                this.IHL = Convert.ToInt32(versionIHL.Substring(4, 4), 2) * 4;
                this.TypeOfService = packetReader.ReadByte();
                this.TotalLength = packetReader.BigEndianReadUInt16();
                this.Identification = packetReader.BigEndianReadUInt16();
                string flagsFragmentOffset = packetReader.ReadBinary(2);
                this.Flags = flagsFragmentOffset.Substring(0, 3);
                this.FragmentOffset = Convert.ToInt32(flagsFragmentOffset.Substring(3, 13), 2);
                this.TimeToLive = packetReader.ReadByte();
                this.Protocol = packetReader.ReadByte();
                this.HeaderChecksum = packetReader.BigEndianReadUInt16();
                this.SourceAddress = new IPAddress(packetReader.ReadBytes(4));
                this.DestinationAddress = new IPAddress(packetReader.ReadBytes(4));
            }

        }
    }
}
