/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2022, Kevin Robertson
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
using Quiddity.NetBIOS;
using Quiddity.Support;
using System.IO;

namespace Quiddity.SMB
{
    class SMBHelper
    {
        public byte[] Protocol { get; set; }

        public SMBHelper()
        {
            this.Protocol = new byte[4];
        }

        public SMBHelper(byte[] data)
        {
            ReadBytes(data, 0);
        }

        public SMBHelper(byte[] data, int offset)
        {
            ReadBytes(data, offset);
        }

        public SMBHelper ReadBytes(byte[] data, int offset)
        {
          
            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = offset;
                this.Protocol = packetReader.ReadBytes(4);
                return this;
            }

        }

        public static byte[] GetBytes(object smbCommand)
        {
            NetBIOSSessionService netBIOSSessionService = new NetBIOSSessionService();
            SMBHeader smbHeader = new SMBHeader();
            return GetBytes(netBIOSSessionService, smbHeader, smbCommand);
        }

        public static byte[] GetBytes(NetBIOSSessionService netBIOSSessionService, SMBHeader smbHeader, object smbCommand)
        {
            byte[] headerData = smbHeader.GetBytes();
            byte[] commandData = new byte[0];

            switch (smbHeader.Command)
            {

                case 0x72:
                    {
                        SMBCOMNegotiateRequest command = (SMBCOMNegotiateRequest)smbCommand;
                        commandData = command.GetBytes();
                    }
                    break;

            }

            netBIOSSessionService.Length = (ushort)(commandData.Length + 32);
            byte[] netbiosData = netBIOSSessionService.GetBytes();
            return Utilities.BlockCopy(netbiosData, headerData, commandData);
        }

    }

}
