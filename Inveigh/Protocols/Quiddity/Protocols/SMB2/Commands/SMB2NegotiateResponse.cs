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
using Quiddity.GSSAPI;
using Quiddity.SPNEGO;
using Quiddity.Support;

namespace Quiddity.SMB2
{
    class SMB2NegotiateResponse
    {
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5
        public ushort StructureSize { get; set; }
        public ushort SecurityMode { get; set; }
        public byte[] DialectRivision { get; set; }
        public ushort NegotiateContextCount { get; set; }
        public byte[] ServerGUID { get; set; }
        public byte[] Capabilities { get; set; }
        public uint MaxTransactSize { get; set; }
        public uint MaxReadSize { get; set; }
        public uint MaxWriteSize { get; set; }
        public byte[] SystemTime { get; set; } // todo create type
        public byte[] ServerStartTime { get; set; }
        public ushort SecurityBufferOffset { get; set; }
        public ushort SecurityBufferLength { get; set; }
        public uint NegotiateContextOffset { get; set; }
        public byte[] Buffer { get; set; }
        public byte[] Padding { get; set; } // todo check
        public byte[] NegotiateContextList { get; set; }

        public SMB2NegotiateResponse()
        {
            this.StructureSize = 65;
            this.SecurityMode = 1;
            this.DialectRivision = new byte[2];
            this.NegotiateContextCount = 0;
            this.ServerGUID = new byte[16];
            this.Capabilities = new byte[4];
            this.MaxTransactSize = 8388608;
            this.MaxReadSize = 8388608;
            this.MaxWriteSize = 8388608;
            this.SystemTime = BitConverter.GetBytes(DateTime.Now.ToFileTime()); ;
            this.ServerStartTime = new byte[8];
            this.SecurityBufferOffset = 128;
            this.SecurityBufferLength = 320;
            this.NegotiateContextOffset = 0;
            this.Buffer = new byte[0];
            this.Padding = new byte[0]; // todo check
            this.NegotiateContextList = new byte[0];
        }

        public SMB2NegotiateResponse(byte[] data, int offset)
        {
            ReadBytes(data, offset);
        }

        public byte[] GetBytes()
        {

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.Write(this.StructureSize);
                packetWriter.Write(this.SecurityMode);
                packetWriter.Write(this.DialectRivision);
                packetWriter.Write(this.NegotiateContextCount);
                packetWriter.Write(this.ServerGUID);
                packetWriter.Write(this.Capabilities);
                packetWriter.Write(this.MaxTransactSize);
                packetWriter.Write(this.MaxReadSize);
                packetWriter.Write(this.MaxWriteSize);
                packetWriter.Write(this.SystemTime);
                packetWriter.Write(this.ServerStartTime);
                packetWriter.Write(this.SecurityBufferOffset);
                packetWriter.Write(this.SecurityBufferLength);
                packetWriter.Write(this.NegotiateContextOffset);
                packetWriter.Write(this.Buffer);

                if (!Utilities.ArrayIsNullOrEmpty(NegotiateContextList))
                {
                    packetWriter.Write(this.NegotiateContextList);
                }

                return memoryStream.ToArray();
            }

        }

        public void ReadBytes(byte[] data, int offset)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = offset;
                this.StructureSize = packetReader.ReadUInt16();
                this.SecurityMode = packetReader.ReadUInt16();
                this.DialectRivision = packetReader.ReadBytes(2);
                this.NegotiateContextCount = packetReader.ReadUInt16();
                this.ServerGUID = packetReader.ReadBytes(16);
                this.Capabilities = packetReader.ReadBytes(4);
                this.MaxTransactSize = packetReader.ReadUInt32();
                this.MaxReadSize = packetReader.ReadUInt16();
                this.MaxWriteSize = packetReader.ReadUInt32();
                this.SystemTime = packetReader.ReadBytes(8);
                this.ServerStartTime = packetReader.ReadBytes(8);
                this.SecurityBufferOffset = packetReader.ReadUInt16();
                this.SecurityBufferLength = packetReader.ReadUInt16();
                this.NegotiateContextOffset = packetReader.ReadUInt32();
                this.Buffer = packetReader.ReadBytes(8);
            }

        }

        public void EncodeBuffer()
        {
            GSSAPIInitSecContext gssapi = new GSSAPIInitSecContext();
            SPNEGONegTokenInit spnego = new SPNEGONegTokenInit();
            spnego.MechTypes = new byte[24] { 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };
            spnego.MechToken = new byte[264] { 0x4e, 0x45, 0x47, 0x4f, 0x45, 0x58, 0x54, 0x53, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x45, 0x42, 0x37, 0xe2, 0x9c, 0xec, 0xed, 0x6a, 0x73, 0x8a, 0x3e, 0x19, 0x27, 0xdc, 0xa0, 0xb0, 0x64, 0x56, 0x91, 0x92, 0xb4, 0x5c, 0x3d, 0x8d, 0xba, 0x32, 0xd3, 0xb1, 0x31, 0xbc, 0xab, 0x29, 0xfa, 0x47, 0x3d, 0xeb, 0x87, 0x6e, 0x53, 0xd7, 0x0c, 0x91, 0x91, 0xb1, 0xae, 0x9e, 0x6b, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5c, 0x33, 0x53, 0x0d, 0xea, 0xf9, 0x0d, 0x4d, 0xb2, 0xec, 0x4a, 0xe3, 0x78, 0x6e, 0xc3, 0x08, 0x4e, 0x45, 0x47, 0x4f, 0x45, 0x58, 0x54, 0x53, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x45, 0x42, 0x37, 0xe2, 0x9c, 0xec, 0xed, 0x6a, 0x73, 0x8a, 0x3e, 0x19, 0x27, 0xdc, 0xa0, 0xb0, 0x5c, 0x33, 0x53, 0x0d, 0xea, 0xf9, 0x0d, 0x4d, 0xb2, 0xec, 0x4a, 0xe3, 0x78, 0x6e, 0xc3, 0x08, 0x40, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x30, 0x56, 0xa0, 0x54, 0x30, 0x52, 0x30, 0x27, 0x80, 0x25, 0x30, 0x23, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x18, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x20, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x4b, 0x65, 0x79, 0x30, 0x27, 0x80, 0x25, 0x30, 0x23, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x18, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x20, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x4b, 0x65, 0x79 };
            byte[] mechTokenSegment = ASN1.Encode(4, spnego.MechToken);
            mechTokenSegment = ASN1.Encode(162, mechTokenSegment);
            byte[] mechTypesSegment = ASN1.Encode(48, spnego.MechTypes);
            mechTypesSegment = ASN1.Encode(160, mechTypesSegment);
            byte[] negTokenInitSegment = Utilities.BlockCopy(mechTypesSegment, mechTokenSegment);
            negTokenInitSegment = ASN1.Encode(48, negTokenInitSegment);
            negTokenInitSegment = ASN1.Encode(160, negTokenInitSegment);
            byte[] gssapiData = Utilities.BlockCopy(gssapi.OID, negTokenInitSegment);
            this.Buffer =  ASN1.Encode(96, gssapiData);
        }

    }

}
