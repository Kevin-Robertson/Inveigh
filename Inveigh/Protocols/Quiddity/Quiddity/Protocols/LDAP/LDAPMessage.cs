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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices.Protocols;
using Quiddity.Support;

namespace Quiddity.LDAP
{
    // https://datatracker.ietf.org/doc/html/rfc2251#section-4.2
    class LDAPMessage
    {
        public int MessageID { get; set; }
        public object ProtocolOp { get; set; }
        public byte[] Controls { get; set; }

        //custom

        public int Tag { get; set; }

        public byte[] Encode()
        {
            return BerConverter.Encode("{iX}", this.MessageID, this.ProtocolOp);
        }

        public byte[] Encode(int type)
        {

            switch (type)
            {

                case 3:
                    {
                        LDAPBindResponse protocolOp = (LDAPBindResponse)this.ProtocolOp;
                        return BerConverter.Encode("{it{eooto}}", this.MessageID, 0x61, protocolOp.ResultCode, protocolOp.MatchedDN, protocolOp.DiagnosticMessage, 0x87, protocolOp.ServerSaslCreds);
                    }

                case 4:
                    {
                        LDAPSearchResEntry protocolOp = (LDAPSearchResEntry)this.ProtocolOp;               
                        return BerConverter.Encode("{it{sto}}", this.MessageID, 0x64, protocolOp.ObjectDN, 0x30, protocolOp.Attributes);
                    }

                case 5:
                    {
                        LDAPSearchResDone protocolOp = (LDAPSearchResDone)this.ProtocolOp;
                        return BerConverter.Encode("{it{eoo}}", this.MessageID, 0x65, protocolOp.ResultCode, protocolOp.MatchedDN, protocolOp.ErrorMessage);
                    }

            }

            return null;
        }

        public byte[] Encode(LDAPSearchResDone resdone)
        {
            return BerConverter.Encode("{it{eoo}}", this.MessageID, 0x65, resdone.ResultCode, resdone.MatchedDN, resdone.ErrorMessage);
        }

        public byte[] Encode(LDAPSearchResEntry search)
        {
            return BerConverter.Encode("{it{stX}}", this.MessageID, 0x64, search.ObjectDN, 0x30, search.Attributes);
        }

        public void Decode(byte[] data)
        {
            this.Tag = GetMessageType(data);
            object[] message = BerConverter.Decode("{iV}", data);
            this.MessageID = (int)message[0];
            this.ProtocolOp = message[1];
        }

        public static int GetLength(int index, byte[] data)
        {
            int length = 0;

            switch (data[index])
            {

                case 0x84:
                    {
                        index++;
                        byte[] valueLength = new byte[4];
                        Buffer.BlockCopy(data, index, valueLength, 0, 4);
                        Array.Reverse(valueLength);
                        length = BitConverter.ToInt32(valueLength, 0);
                        length += 4;
                    }
                    break;

            }

            return length;
        }

        public static int GetMessageType(byte[]data)
        {
            int type = -1;
            int index = 1;
            byte tag;
            int valueLength = data[index++];

            if ((valueLength & 0x80) == 0x80)
            {
                int length = valueLength & 0x7f;
                valueLength = 0;

                for (int i = 0; i < length; i++)
                {
                    valueLength = valueLength * 256 + data[index++];
                }

            }
            else
            {
                index += valueLength;
            }

            index++;
            valueLength = data[index];

            if ((valueLength & 0x80) == 0x80)
            {
                int length = valueLength & 0x7f;
                valueLength = 0;

                for (int i = 0; i < length; i++)
                {
                    valueLength = valueLength * 256 + data[index++];
                }

            }
            else
            {
                index += valueLength;
            }

            index++;
            tag = data[index];

            if ((tag & 0x60) == 0x60 || (tag & 0x40) == 0x40)
            {
                type = tag & 0x1f;
            }

            return type;
        }

    }

}
