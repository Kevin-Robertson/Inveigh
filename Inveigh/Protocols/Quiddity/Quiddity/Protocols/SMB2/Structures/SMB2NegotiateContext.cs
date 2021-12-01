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
using System.Linq;
using System.IO;

namespace Quiddity.SMB2
{
    class SMB2NegotiateContext
    {
        //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/15332256-522e-4a53-8cd7-0bd17678a2f7
        public ushort ContextType { get; set; }
        public ushort DataLength { get; set; }
        public uint Reserved { get; set; }
        public byte[] Data { get; set; }

        public SMB2NegotiateContext()
        {
            this.ContextType = 0;
            this.DataLength = 0;
            this.Reserved = 0;
            this.Data = new byte[0];
        }

        public byte[] GetBytes(string[] contextTypes)
        {
  
            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);

                if (contextTypes.Contains("1"))
                {
                    this.ContextType = 1;
                    this.DataLength = 38;
                    byte[] key = new byte[32];
                    Random random = new Random();
                    random.NextBytes(key);
                    this.Data = new byte[38];
                    Buffer.BlockCopy(new byte[6] { 0x01, 0x00, 0x20, 0x00, 0x01, 0x00 }, 0, this.Data, 0, 6);
                    Buffer.BlockCopy(key, 0, this.Data, 6, key.Length);
                    packetWriter.Write(this.ContextType);
                    packetWriter.Write(this.DataLength);
                    packetWriter.Write(this.Reserved);
                    packetWriter.Write(this.Data);
                    packetWriter.Write(new byte[2] { 0x000, 0x00 });
                }

                if (contextTypes.Contains("2"))
                {
                    this.ContextType = 2;
                    this.DataLength = 4;
                    this.Data = new byte[4] { 0x01, 0x00, 0x2, 0x00 };
                    packetWriter.Write(this.ContextType);
                    packetWriter.Write(this.DataLength);
                    packetWriter.Write(this.Reserved);
                    packetWriter.Write(this.Data);
                    packetWriter.Write(new byte[4] { 0x000, 0x00, 0x00, 0x00 });
                }

                if (contextTypes.Contains("3"))
                {
                    this.ContextType = 3;
                    this.DataLength = 12;
                    this.Data = new byte[12] { 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00 };
                    packetWriter.Write(this.ContextType);
                    packetWriter.Write(this.DataLength);
                    packetWriter.Write(this.Reserved);
                    packetWriter.Write(this.Data);
                }

                return memoryStream.ToArray();
            }

        }

    }

}
