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

using Quiddity.SPNEGO;
using Quiddity.Support;
using System;
using System.IO;
using System.Text;

namespace Quiddity.NTLM
{
    class NTLMResponse
    {
        //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce
        public byte[] Signature { get; set; }
        public uint MessageType { get; set; }
        public ushort LmChallengeResponseLen { get; set; }
        public ushort LmChallengeResponseMaxLen { get; set; }
        public uint LmChallengeResponseBufferOffset { get; set; }
        public ushort NtChallengeResponseLen { get; set; }
        public ushort NtChallengeResponseMaxLen { get; set; }
        public uint NtChallengeResponseBufferOffset { get; set; }
        public ushort DomainNameLen { get; set; }
        public ushort DomainNameMaxLen { get; set; }
        public uint DomainNameBufferOffset { get; set; }
        public ushort UserNameLen { get; set; }
        public ushort UserNameMaxLen { get; set; }
        public uint UserNameBufferOffset { get; set; }
        public ushort WorkstationLen { get; set; }
        public ushort WorkstationMaxLen { get; set; }
        public uint WorkstationBufferOffset { get; set; }
        public ushort EncryptedRandomSessionKeyLen { get; set; }
        public ushort EncryptedRandomSessionKeyMaxLen { get; set; }
        public uint EncryptedRandomSessionKeyBufferOffset { get; set; }
        public byte[] NegotiateFlags { get; set; }
        public byte[] Version { get; set; }
        public byte[] MIC { get; set; }
        public byte[] Payload { get; set; }

        // custom properties
        public byte[] DomainName { get; set; }
        public byte[] UserName { get; set; }
        public byte[] Workstation { get; set; }
        public byte[] EncryptedRandomSessionKey { get; set; }
        public byte[] NtChallengeResponse { get; set; }
        public byte[] LmChallengeResponse { get; set; }
        public byte[] Timestamp { get; set; }

        public NTLMResponse()
        {
            this.Signature = new byte[8] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 }; // NTLMSSP
            this.MessageType = 3;
            this.LmChallengeResponseLen = 0;
            this.LmChallengeResponseMaxLen = 0;
            this.LmChallengeResponseBufferOffset = 0;
            this.NtChallengeResponseLen = 0;
            this.NtChallengeResponseMaxLen = 0;
            this.NtChallengeResponseBufferOffset = 0;
            this.DomainNameLen = 0;
            this.DomainNameMaxLen = 0;
            this.DomainNameBufferOffset = 0;
            this.UserNameLen = 0;
            this.UserNameMaxLen = 0;
            this.UserNameBufferOffset = 0;
            this.WorkstationLen = 0;
            this.WorkstationMaxLen = 0;
            this.WorkstationBufferOffset = 0;
            this.EncryptedRandomSessionKeyLen = 0;
            this.EncryptedRandomSessionKeyMaxLen = 0;
            this.EncryptedRandomSessionKeyBufferOffset = 0;
            this.NegotiateFlags = new byte[4] { 0x15, 0x82, 0x8a, 0xe2 };
            this.Version = new byte[8] { 0x0a, 0x00, 0x61, 0x4a, 0x00, 0x00, 0x00, 0x0f };
            this.MIC = new byte[16];
            this.Payload = new byte[0];
        }

        public NTLMResponse(byte[] data)
        {
            string signature = Encoding.UTF8.GetString(data);

            if (signature.StartsWith("NTLMSSP"))
            {
                ReadBytes(data);
            }
            else
            {
                SPNEGONegTokenResp token = this.Decode(data);
                this.ReadBytes(token.ResponseToken);
            }

            ParseValues();
        }

        public NTLMResponse(byte[] data, bool decode)
        {

            if(decode)
            {
                SPNEGONegTokenResp token = this.Decode(data);
                this.ReadBytes(token.ResponseToken);
            }
            else
            {
                ReadBytes(data);
            }

            ParseValues();
        }

        public void ReadBytes(byte[] data)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                this.Signature = packetReader.ReadBytes(8);
                this.MessageType = packetReader.ReadUInt32();
                this.LmChallengeResponseLen = packetReader.ReadUInt16();
                this.LmChallengeResponseMaxLen = packetReader.ReadUInt16();
                this.LmChallengeResponseBufferOffset = packetReader.ReadUInt32();
                this.NtChallengeResponseLen = packetReader.ReadUInt16();
                this.NtChallengeResponseMaxLen = packetReader.ReadUInt16();
                this.NtChallengeResponseBufferOffset = packetReader.ReadUInt32();
                this.DomainNameLen = packetReader.ReadUInt16();
                this.DomainNameMaxLen = packetReader.ReadUInt16();
                this.DomainNameBufferOffset = packetReader.ReadUInt32();
                this.UserNameLen = packetReader.ReadUInt16();
                this.UserNameMaxLen = packetReader.ReadUInt16();
                this.UserNameBufferOffset = packetReader.ReadUInt32();
                this.WorkstationLen = packetReader.ReadUInt16();
                this.WorkstationMaxLen = packetReader.ReadUInt16();
                this.WorkstationBufferOffset = packetReader.ReadUInt32();
                this.EncryptedRandomSessionKeyLen = packetReader.ReadUInt16();
                this.EncryptedRandomSessionKeyMaxLen = packetReader.ReadUInt16();
                this.EncryptedRandomSessionKeyBufferOffset = packetReader.ReadUInt32();
                this.NegotiateFlags = packetReader.ReadBytes(4);
                this.Version = packetReader.ReadBytes(8);
                this.MIC = packetReader.ReadBytes(16);
                this.Payload = packetReader.ReadBytes(data.Length - 88);
            }

        }

        public string GetFormattedHash(string challenge, string user, string domain)
        {
            string hash = "";

            if (this.NtChallengeResponse.Length > 24)
            {
                hash = user + "::" + domain + ":" + challenge + ":" + BitConverter.ToString(this.NtChallengeResponse).Replace("-", "").Insert(32, ":");
            }
            else if (this.NtChallengeResponse.Length == 24)
            {
                hash = user + "::" + domain + ":" + BitConverter.ToString(this.LmChallengeResponse).Replace("-", "") + ":" + BitConverter.ToString(this.NtChallengeResponse).Replace("-", "").Insert(32, ":") + ":" + challenge;
            }

            return hash;
        }

        private SPNEGONegTokenResp Decode(byte[] data)
        {

            SPNEGONegTokenResp spnegoNegTokenResp = new SPNEGONegTokenResp
            {
                NegState = ASN1.GetTagBytes(10, data)[0],
                //SupportedMech = ASN1.GetTagBytes(6, data),
                ResponseToken = ASN1.GetTagBytes(4, data),
                //MechListMIC = ASN1.GetTagBytes(4, ASN1.GetTagBytes(163, data))
            };

            return spnegoNegTokenResp;
        }

        private void ParseValues()
        {
            this.DomainName = new byte[this.DomainNameLen];
            Buffer.BlockCopy(this.Payload, (int)(this.DomainNameBufferOffset - 88), this.DomainName, 0, this.DomainNameLen);
            this.UserName = new byte[this.UserNameLen];
            Buffer.BlockCopy(this.Payload, (int)(this.UserNameBufferOffset - 88), this.UserName, 0, this.UserNameLen);
            this.Workstation = new byte[this.WorkstationLen];
            Buffer.BlockCopy(this.Payload, (int)(this.WorkstationBufferOffset - 88), this.Workstation, 0, this.WorkstationLen);
            this.EncryptedRandomSessionKey = new byte[this.EncryptedRandomSessionKeyLen];
            Buffer.BlockCopy(this.Payload, (int)(this.EncryptedRandomSessionKeyBufferOffset - 88), this.EncryptedRandomSessionKey, 0, this.EncryptedRandomSessionKeyLen);
            this.LmChallengeResponse = new byte[this.LmChallengeResponseLen];
            Buffer.BlockCopy(this.Payload, (int)(this.LmChallengeResponseBufferOffset - 88), this.LmChallengeResponse, 0, this.LmChallengeResponseLen);
            this.NtChallengeResponse = new byte[this.NtChallengeResponseLen];
            Buffer.BlockCopy(this.Payload, (int)(this.NtChallengeResponseBufferOffset - 88), this.NtChallengeResponse, 0, this.NtChallengeResponseLen);
        }

    }

}
