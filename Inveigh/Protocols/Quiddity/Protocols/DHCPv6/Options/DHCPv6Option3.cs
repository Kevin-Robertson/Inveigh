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

namespace Quiddity.DHCPv6
{
    class DHCPv6Option3 : DHCPv6Option
    {
        public byte[] IAID { get; set; }
        public uint T1 { get; set; }
        public uint T2 { get; set; }
        public byte[] IANAOptions { get; set; }

        public DHCPv6Option3()
        {
            
        }

        public DHCPv6Option3(byte[] data)
        {
            ReadBytes(data, 0);
        }

        public DHCPv6Option3(byte[] data, int index)
        {
            ReadBytes(data, index);
        }

        public DHCPv6Option3(string clientIPv6Address, uint lifetime, byte[] iaid)
        {
            this.OptionCode = 3;
            this.T1 = 200;
            this.T2 = 250;
            this.IAID = iaid;
            this.IANAOptions = new DHCPv6Option5().GetBytes(clientIPv6Address, lifetime);
        }

        public new void ReadBytes(byte[] data, int index)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = index;
                this.OptionCode = packetReader.BigEndianReadUInt16();
                this.OptionLen = packetReader.BigEndianReadUInt16();
                this.IAID = packetReader.ReadBytes(4);
                this.T1 = packetReader.BigEndianReadUInt32();
                this.T2 = packetReader.BigEndianReadUInt32();
                this.IANAOptions = packetReader.ReadBytes(this.OptionLen - 12);
            }

        }

        public byte[] GetBytes()
        {
            this.OptionLen = 40;

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.BigEndianWrite(this.OptionCode);
                packetWriter.BigEndianWrite(this.OptionLen);
                packetWriter.Write(this.IAID);
                packetWriter.BigEndianWrite(this.T1);
                packetWriter.BigEndianWrite(this.T2);
                packetWriter.Write(this.IANAOptions);
                return memoryStream.ToArray();
            }

        }

    }
}
