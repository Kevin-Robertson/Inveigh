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
using Quiddity.NTLM;

namespace Quiddity.SMB2
{
    class SMB2SessionSetupResponse
    {
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0324190f-a31b-4666-9fa9-5c624273a694
        public ushort StructureSize { get; set; }
        public ushort SessionFlags { get; set; }
        public ushort SecurityBufferOffset { get; set; }
        public ushort SecurityBufferLength { get; set; }
        public byte[] Buffer { get; set; }

        public SMB2SessionSetupResponse()
        {
            this.StructureSize = 9;
            this.SessionFlags = 0;
            this.SecurityBufferOffset = 72;
            this.SecurityBufferLength = 0;
            this.Buffer = new byte[0];
        }

        public SMB2SessionSetupResponse(byte[] data, int offset)
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
                this.SessionFlags = packetReader.ReadUInt16();
                this.SecurityBufferOffset = packetReader.ReadUInt16();
                this.SecurityBufferLength = packetReader.ReadUInt16();
                this.Buffer = packetReader.ReadBytes(this.SecurityBufferLength);
            }

        }

        public byte[] GetBytes()
        {
            this.SecurityBufferLength = (ushort)Buffer.Length;

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.Write(this.StructureSize);
                packetWriter.Write(this.SessionFlags);
                packetWriter.Write(this.SecurityBufferOffset);
                packetWriter.Write(this.SecurityBufferLength);

                if (this.SecurityBufferLength > 0)
                {
                    packetWriter.Write(this.Buffer);
                }

                return memoryStream.ToArray();
            }

        }

        public void Pack(string challenge, string netBIOSName, string computerName, string dnsDomain, string dnsComputerName, string dnsTreeName, out byte[] challengeData)
        {
            NTLMChallenge ntlmChallenge = new NTLMChallenge();
            ntlmChallenge.ServerChallenge = ntlmChallenge.Challenge(challenge);
            challengeData = ntlmChallenge.ServerChallenge;
            byte[] timestamp = BitConverter.GetBytes(DateTime.Now.ToFileTime());
            NTLMAVPair ntlmAVPair = new NTLMAVPair();
            ntlmChallenge.Payload = ntlmAVPair.GetBytes(netBIOSName, computerName, dnsDomain, dnsComputerName, dnsTreeName, timestamp);
            byte[] ntlmChallengeData = ntlmChallenge.GetBytes(computerName);
            byte[] gssapiData = ntlmChallenge.Encode(ntlmChallengeData);
            this.SecurityBufferLength = (ushort)gssapiData.Length;
            this.Buffer = gssapiData;
        }

    }
}
