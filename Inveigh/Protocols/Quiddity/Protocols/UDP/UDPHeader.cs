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

namespace Quiddity.UDP
{
    class UDPHeader
    {
        // https://tools.ietf.org/html/rfc768
        public ushort SourcePort { get; set; }
        public ushort DestinationPort { get; set; }
        public ushort Length { get; set; }
        public ushort Checksum { get; set; }

        public UDPHeader()
        {
            this.SourcePort = 0;
            this.DestinationPort = 0;
            this.Length = 0;
            this.Checksum = 0;
        }

        public UDPHeader(byte[] data, int offset)
        {
            ReadBytes(data, offset);
        }

        public UDPHeader ReadBytes(byte[] data, int offset)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = offset;
                this.SourcePort = packetReader.BigEndianReadUInt16();
                this.DestinationPort = packetReader.BigEndianReadUInt16();
                this.Length = packetReader.BigEndianReadUInt16();
                this.Checksum = packetReader.ReadUInt16();
                return this;
            }

        }

        public byte[] GetBytes()
        {

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.BigEndianWrite(this.SourcePort);
                packetWriter.BigEndianWrite(this.DestinationPort);
                packetWriter.BigEndianWrite(this.Length);
                packetWriter.Write(this.Checksum);
                return memoryStream.ToArray();
            }

        }

        public void IPv6Checksum(byte[] data, string clientIP, string sourceIP, int nextHeader)
        {
            byte[] pseudoHeader = IPv6PseudoHeader(clientIP, sourceIP, nextHeader, data.Length);
            int e = 0;

            if ((pseudoHeader.Length + data.Length) % 2 != 0)
            {
                e = 1;
            }

            byte[] packet = new byte[pseudoHeader.Length + data.Length + e];
            Buffer.BlockCopy(pseudoHeader, 0, packet, 0, pseudoHeader.Length);
            Buffer.BlockCopy(data, 0, packet, pseudoHeader.Length, data.Length);
            uint packetChecksum = 0;
            int index = 0;

            while (index < packet.Length)
            {
                packetChecksum += Convert.ToUInt32(BitConverter.ToUInt16(packet, index));
                index += 2;
            }

            packetChecksum = (packetChecksum >> 16) + (packetChecksum & 0xffff);
            packetChecksum += (packetChecksum >> 16);
            this.Checksum = (ushort)~packetChecksum;
        }

        private byte[] IPv6PseudoHeader(string clientIP, string sourceIP, int nextHeader, int length)
        {
            byte[] lengthData = BitConverter.GetBytes(length);
            Array.Reverse(lengthData);
            byte[] pseudoHeader = new byte[40];
            Buffer.BlockCopy(IPAddress.Parse(sourceIP).GetAddressBytes(), 0, pseudoHeader, 0, 16);
            Buffer.BlockCopy(IPAddress.Parse(clientIP).GetAddressBytes(), 0, pseudoHeader, 16, 16);
            Buffer.BlockCopy(lengthData, 0, pseudoHeader, 32, 4);
            pseudoHeader[39] = (byte)nextHeader;
            return pseudoHeader;
        }

    }
}
