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
using System.IO;

namespace Quiddity.SMB2
{
    class SMB2SessionSetupRequest
    {
        //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a3c2c28-d6b0-48ed-b917-a86b2ca4575f
        public ushort StructureSize { get; set; }
        public byte Flags { get; set; }
        public byte SecurityMode { get; set; }
        public byte[] Capabilities { get; set; }
        public byte[] Channel { get; set; }
        public ushort SecurityBufferOffset { get; set; }
        public ushort SecurityBufferLength { get; set; }
        public byte[] PreviousSessionId { get; set; }
        public byte[] Buffer { get; set; }

        public SMB2SessionSetupRequest()
        {
            this.StructureSize = 19;
            this.Flags = 0x00;
            this.SecurityMode = 0x01;
            this.Capabilities = new byte[4] { 0x01, 0x00, 0x00, 0x00 };
            this.Channel = new byte[4];
            this.SecurityBufferOffset = 88;
            this.SecurityBufferLength = 0;
            this.PreviousSessionId = new byte[8];
            this.Buffer = new byte[0];
        }

        public SMB2SessionSetupRequest(byte[] data, int offset)
        {
            ReadBytes(data, offset);
        }

        public void ReadBytes(byte[] data, int offset)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = offset;
                this.StructureSize = packetReader.ReadUInt16();
                this.Flags = packetReader.ReadByte();
                this.SecurityMode = packetReader.ReadByte();
                this.Capabilities = packetReader.ReadBytes(4);
                this.Channel = packetReader.ReadBytes(4);
                this.SecurityBufferOffset = packetReader.ReadUInt16();
                this.SecurityBufferLength = packetReader.ReadUInt16();
                this.PreviousSessionId = packetReader.ReadBytes(8);
                this.Buffer = packetReader.ReadBytes(this.SecurityBufferLength);
            }

        }

    }

}
