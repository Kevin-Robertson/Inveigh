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
using Quiddity.SMB;
using Quiddity.SMB2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;

namespace Quiddity.Clients
{
    class SMBClient
    {
        public TCPClient TCPClient { get; set; }

        public static NetworkStream tcpStream;

        internal void Connect(string ipAddress, int port)
        {
            TCPClient = new TCPClient(ipAddress, port);
            //TCPClient.Connect(ipAddress, port);
            tcpStream = TCPClient.GetStream();
        }

        internal void Negotiate(string ipAddress, int port)
        {
            Connect(ipAddress, port);
            byte[] readBuffer = new byte[1024];

            SMBHeader smbHeader = new SMBHeader
            {
                Command = 0x72,
                Status = 0,
                Flags = 0x18,
                Flags2 = 51283,
                PIDHigh = 0,
                SecurityFeatures = new byte[8],
                TID = 65535,
                PIDLow = 65279,
                UID = 0,
                MID = 0
            };

            SMBCOMNegotiateRequest smbCOMNegotiateRequest = new SMBCOMNegotiateRequest();
            byte[] sendBuffer = SMBHelper.GetBytes(new NetBIOSSessionService(), smbHeader, smbCOMNegotiateRequest);
            tcpStream.Write(sendBuffer, 0, sendBuffer.Length);
            tcpStream.Flush();
            tcpStream.Read(readBuffer, 0, readBuffer.Length);

            NetBIOSSessionService requestNetBIOSSessionService = new NetBIOSSessionService(readBuffer);
            SMBHelper smbHelper = new SMBHelper();

            if (requestNetBIOSSessionService.Type == 0 || smbHelper.Protocol[0] == 0xfe || smbHelper.Protocol[0] == 0xff)
            {
                int sessionServiceIndex = 0;

                if (requestNetBIOSSessionService.Type == 0)
                {
                    sessionServiceIndex = 4;
                }

                SMBHeader requestSMBHeader = new SMBHeader();
                SMB2Header requestSMB2Header = new SMB2Header();
                smbHelper.ReadBytes(readBuffer, sessionServiceIndex);
            }

        }

        internal void Authenticate(string ipAddress, int port)
        {

        }

        internal void SCMExecute(string ipAddress, int port)
        {

        }

    }

}
