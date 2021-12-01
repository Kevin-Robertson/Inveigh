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
using System.IO;

namespace Quiddity.SMB2
{

    class SMB2NegotiatelRequest
    {
        //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5
        public ushort StructureSize { get; set; }
        public ushort DialectCount { get; set; }
        public ushort SecurityMode { get; set; }
        public byte[] Reserved { get; set; }
        public byte[] Capabilities { get; set; }
        public byte[] ClientGUID { get; set; }
        public uint NegotiateContextOffset { get; set; }
        public ushort NegotiateContextCount { get; set; }
        public byte[] Reserved2 { get; set; }
        public byte[] ClientStartTime { get; set; }
        public byte[] Dialects { get; set; }
        public byte[] Padding { get; set; } // todo check
        public byte[] NegotiateContextList { get; set; }

        public SMB2NegotiatelRequest(byte[] data, int offset)
        {
            ReadBytes(data, offset);
        }

        public byte[] GetBytes()
        {

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.Write(this.StructureSize);
                packetWriter.Write(this.DialectCount);
                packetWriter.Write(this.SecurityMode);
                packetWriter.Write(this.Reserved);
                packetWriter.Write(this.Capabilities);
                packetWriter.Write(this.ClientGUID);
                packetWriter.Write(this.NegotiateContextOffset);
                packetWriter.Write(this.NegotiateContextCount);
                packetWriter.Write(this.Reserved2);
                packetWriter.Write(this.ClientStartTime);
                packetWriter.Write(this.Dialects);
                packetWriter.Write(this.Padding);
                packetWriter.Write(this.NegotiateContextList);
                return memoryStream.ToArray();
            }

        }

        public ushort GetMaxDialect()
        {
            byte[] maxDialectData = new byte[2];
            maxDialectData[0] = this.Dialects[this.Dialects.Length - 2];
            maxDialectData[1] = this.Dialects[this.Dialects.Length - 1];
            return Utilities.DataToUInt16(maxDialectData);
        }

        public void ReadBytes(byte[] data, int offset)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = offset;
                this.StructureSize = packetReader.ReadUInt16();
                this.DialectCount = packetReader.ReadUInt16();
                this.SecurityMode = packetReader.ReadUInt16();
                this.Reserved = packetReader.ReadBytes(2);
                this.Capabilities = packetReader.ReadBytes(4);
                this.ClientGUID = packetReader.ReadBytes(16);
                this.NegotiateContextOffset = packetReader.ReadUInt32();
                this.NegotiateContextCount = packetReader.ReadUInt16();
                this.Reserved2 = packetReader.ReadBytes(2);
                this.Dialects = packetReader.ReadBytes(this.DialectCount * 2);
                this.Padding = packetReader.ReadBytes(8);
            }

        }

    }

}
