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
    class SMB2Header
    {
        /*
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4
        */
        public byte[] Protocol { get; set; }
        public ushort StructureSize { get; set; }
        public ushort CreditCharge { get; set; }
        public byte[] Status { get; set; } // SMB2.x requests and all responses
        public ushort ChannelSequence { get; set; } // SMB3.x requests
        public ushort Reserved { get; set; } // SMB3.x requests
        public ushort Command { get; set; }
        public ushort Credit { get; set; } // CreditRequest/CreditResponse
        public byte[] Flags { get; set; }
        public byte[] NextCommand { get; set; }
        public ulong MessageId { get; set; }
        public uint Reserved2 { get; set; } // Process ID?
        public uint TreeId { get; set; }
        public byte[] SessionId { get; set; }
        public byte[] Signature { get; set; }

        public SMB2Header()
        {
            this.Protocol = new byte[4] { 0xfe, 0x53, 0x4d, 0x42 };
            this.StructureSize = 64;
            this.CreditCharge = 0;
            this.Status = new byte[4];
            this.Command = 0;
            this.Credit = 1;
            this.Flags = new byte[4] { 0x01, 0x00, 0x00, 0x00 };
            this.NextCommand = new byte[4];
            this.MessageId = 0;
            this.Reserved2 = 0;
            this.TreeId = 0;
            this.SessionId = new byte[8];
            this.Signature = new byte[16];
        }

        public SMB2Header(byte[] data)
        {
            ReadBytes(data, 0);
        }

        public SMB2Header(byte[] data, int offset)
        {
            ReadBytes(data, offset);
        }

        public void ReadBytes(byte[] data, int offset)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = offset;
                this.Protocol = packetReader.ReadBytes(4);
                this.StructureSize = packetReader.ReadUInt16();
                this.CreditCharge = packetReader.ReadUInt16();
                this.Status = packetReader.ReadBytes(4);
                this.Command = packetReader.ReadUInt16();
                this.Credit = packetReader.ReadUInt16();
                this.Flags = packetReader.ReadBytes(4);
                this.NextCommand = packetReader.ReadBytes(4);
                this.MessageId = packetReader.ReadUInt64();
                this.Reserved2 = packetReader.ReadUInt32();
                this.TreeId = packetReader.ReadUInt32();
                this.SessionId = packetReader.ReadBytes(8);
                this.Signature = packetReader.ReadBytes(16);
            }

        }

        public byte[] GetBytes()
        {

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.Write(this.Protocol);
                packetWriter.Write(this.StructureSize);
                packetWriter.Write(this.CreditCharge);
                packetWriter.Write(this.Status);
                packetWriter.Write(this.Command);
                packetWriter.Write(this.Credit);
                packetWriter.Write(this.Flags);
                packetWriter.Write(this.NextCommand);
                packetWriter.Write(this.MessageId);
                packetWriter.Write(this.Reserved2);
                packetWriter.Write(this.TreeId);
                packetWriter.Write(this.SessionId);
                packetWriter.Write(this.Signature);
                return memoryStream.ToArray();
            }

        }

    }
}
