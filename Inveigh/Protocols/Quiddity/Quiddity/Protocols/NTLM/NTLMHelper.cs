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
using System.IO;
using System.Text;

namespace Quiddity.NTLM
{
    class NTLMHelper
    {
        public string Signature { get; set; }
        public uint MessageType { get; set; }

        public NTLMHelper()
        {

        }
        public NTLMHelper(byte[]data)
        {
            string signature = Encoding.UTF8.GetString(data);

            if (signature.StartsWith("NTLMSSP"))
            {
                ReadBytes(data, 0);
            }
            else
            {
                SPNEGONegTokenInit token = this.Decode(data);
                this.ReadBytes(token.MechToken, 0);
            }
        }

        public NTLMHelper(byte[] data, int offset)
        {
            ReadBytes(data, offset);
        }

        public void ReadBytes(byte[] data, int offset)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = offset;
                this.Signature = Encoding.UTF8.GetString(packetReader.ReadBytes(8));
                this.MessageType = packetReader.ReadUInt16();
            }

        }

        private SPNEGONegTokenInit Decode(byte[] data)
        {
            SPNEGONegTokenInit spnegoNegTokenInit = new SPNEGONegTokenInit
            {
                MechTypes = ASN1.GetTagBytes(6, data),
                MechToken = ASN1.GetTagBytes(4, data)
            };

            return spnegoNegTokenInit;
        }

    }

}
