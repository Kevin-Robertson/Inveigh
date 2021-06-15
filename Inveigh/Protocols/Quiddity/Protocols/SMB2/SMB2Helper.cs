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
using System.Net.Sockets;
using Quiddity.NetBIOS;
using Quiddity.Support;

namespace Quiddity.SMB2
{
    class SMB2Helper
    {
        public NetBIOSSessionService NetBIOS = new NetBIOSSessionService();
        public SMB2Header Header = new SMB2Header();
        public object Payload = new object();

        public void Write(SMB2Helper Packet, NetworkStream Stream)
        {
            byte[] headerData = Packet.Header.GetBytes();
            byte[] commandData = new byte[0];

            switch (Packet.Header.Command)
            {

                case 0:
                    {
                        SMB2NegotiateResponse command = (SMB2NegotiateResponse)Packet.Payload;
                        commandData = command.GetBytes();
                    }
                    break;

                case 1:
                    {
                        SMB2SessionSetupResponse command = (SMB2SessionSetupResponse)Packet.Payload;
                        commandData = command.GetBytes();
                    }
                    break;

            }

            Packet.NetBIOS.Length = (ushort)(commandData.Length + 64);
            byte[] netbiosData = Packet.NetBIOS.GetBytes();
            byte[] buffer = Utilities.BlockCopy(netbiosData, headerData, commandData);
            Stream.Write(buffer, 0, buffer.Length);
            Stream.Flush();
        }

        public static byte[] GetBytes(object smb2Command)
        {
            NetBIOSSessionService netBIOSSessionService = new NetBIOSSessionService();
            SMB2Header smb2Header = new SMB2Header();
            return GetBytes(netBIOSSessionService, smb2Header, smb2Command);
        }

        public static byte[] GetBytes(NetBIOSSessionService netBIOSSessionService, SMB2Header smb2Header, object smb2Command)
        {
            byte[] headerData = smb2Header.GetBytes();
            byte[] commandData = new byte[0];

            switch (smb2Header.Command)
            {

                case 0:
                    {
                        SMB2NegotiateResponse command = (SMB2NegotiateResponse)smb2Command;
                        commandData = command.GetBytes();
                    }
                    break;

                case 1:
                    {
                        SMB2SessionSetupResponse command = (SMB2SessionSetupResponse)smb2Command;
                        commandData = command.GetBytes();
                    }
                    break;

            }

            netBIOSSessionService.Length = (ushort)(commandData.Length + 64);
            byte[] netbiosData = netBIOSSessionService.GetBytes();
            return Utilities.BlockCopy(netbiosData, headerData, commandData);
        }

        public void NegotiateProtocol()
        {

        }

        public void SessionSetup()
        {

        }

    }

}
