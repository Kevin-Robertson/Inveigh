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
using Quiddity.Support;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Quiddity.HTTP
{
    class HTTPRequest
    {
        public string Method { get; set; }
        public string URI { get; set; }
        public string Version { get; set; }
        public string Host { get; set; }
        public string Connection { get; set; }
        public string UserAgent { get; set; }
        public string Accept { get; set; }
        public string AcceptEncoding { get; set; }
        public string AcceptLanguage { get; set; }
        public string Authorization { get; set; }
        public string ProxyAuthorization { get; set; }

        public void ReadBytes(byte[] data, int offset)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = offset;
                int index = Array.IndexOf<byte>(data, 0x20, 0);

                if (index > -1)
                {
                    this.Method = Encoding.UTF8.GetString(packetReader.ReadBytes(index));
                    memoryStream.Position++;
                    index = Array.IndexOf<byte>(data, 0x20, (int)memoryStream.Position);

                    if (index > -1)
                    {
                        index -= (int)memoryStream.Position;
                        this.URI = Encoding.UTF8.GetString(packetReader.ReadBytes(index));
                        memoryStream.Position++;
                        index = Array.IndexOf<byte>(data, 0x0d, (int)memoryStream.Position);

                        if (index > -1)
                        {
                            index -= (int)memoryStream.Position;
                            this.Version = Encoding.UTF8.GetString(packetReader.ReadBytes(index));
                            memoryStream.Position += 2;
                        }

                    }

                }

                while (index > -1)
                {                
                    index = Array.IndexOf<byte>(data, 0x20, (int)memoryStream.Position);
                    
                    if (index > -1)
                    {
                        index -= (int)memoryStream.Position;
                        string field = Encoding.UTF8.GetString(packetReader.ReadBytes(index));
                        memoryStream.Position++;
                        index = Array.IndexOf<byte>(data, 0x0d, (int)memoryStream.Position);
                        index -= (int)memoryStream.Position;

                        if (index > -1)
                        {
                            string value = Encoding.UTF8.GetString(packetReader.ReadBytes(index));
                            GetField(field, value);
                        }

                        memoryStream.Position += 2;
                    }
                    
                }

            }

        }

        public void GetField(string field, string value)
        {

            switch (field.ToUpper())
            {

                case "HOST:":
                    this.Host = value;
                    break;

                case "CONNECTION:":
                    this.Connection = value;
                    break;

                case "USER-AGENT:":
                    this.UserAgent = value;
                    break;

                case "ACCEPT:":
                    this.Accept = value;
                    break;

                case "ACCEPT-ENCODING:":
                    this.AcceptEncoding = value;
                    break;

                case "ACCEPT-LANGUAGE:":
                    this.AcceptLanguage = value;
                    break;

                case "AUTHORIZATION:":
                    this.Authorization = value;
                    break;

                case "PROXY-AUTHORIZATION:":
                    this.ProxyAuthorization = value;
                    break;

            }

        }

    }

}
