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
using System.IO;
using System.Linq;
using System.Text;

namespace Quiddity.ICMPv6
{
    class ICMPv6RouterAdvertisement
    {
        // https://datatracker.ietf.org/doc/html/rfc4861#section-4.2
        public byte Type { get; set; }
        public byte Code { get; set; }
        public ushort Checksum { get; set; }
        public byte CurHopLimit { get; set; }
        public bool M{ get; set; } // 1 bit
        public bool O { get; set; } // 1 bit
        public string Reserved { get; set; } // 6 bits
        public ushort RouterLifeTime { get; set; }
        public uint ReachableTime  { get; set; }
        public uint RetransTimer { get; set; }
        public byte[] Options { get; set; }

        // custom fields
        public byte Flags { get; set; }

        public ICMPv6RouterAdvertisement()
        {
            this.Type = 134;
            this.Code = 0;
            this.Checksum = 0;
            this.Flags = 0;
            this.RouterLifeTime = 0;
            this.ReachableTime = 0;
            this.RetransTimer = 0;
        }

        public byte[] GetBytes()
        {

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.Write(this.Type);
                packetWriter.Write(this.Code);
                packetWriter.Write(this.Checksum);
                packetWriter.Write(this.CurHopLimit);
                packetWriter.Write(this.Flags);
                packetWriter.BigEndianWrite(this.RouterLifeTime);
                packetWriter.BigEndianWrite(this.ReachableTime);
                packetWriter.BigEndianWrite(this.RetransTimer);

                if (!Utilities.ArrayIsNullOrEmpty(Options))
                {
                    packetWriter.Write(this.Options);
                }

                return memoryStream.ToArray();
            }

        }

        protected virtual void WriteFlags()
        {
            string flags = this.M ? "1" : "0";
            flags += this.O ? "1" : "0";
            flags += this.Reserved;

            for (int i = 0; i < 2; ++i)
            {
                this.Flags = Convert.ToByte(flags.Substring(8 * i, 8), 1); ;
            }
        }
    }
}
