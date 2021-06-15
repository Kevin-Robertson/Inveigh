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
    class HTTPResponse
    {
        public string Version { get; set; }
        public string StatusCode { get; set; }
        public string ReasonPhrase { get; set; }
        public string Server { get; set; }
        public string Date { get; set; }
        public string ContentType { get; set; }
        public string ContentLength { get; set; }
        public string Connection { get; set; }
        public string CacheControl { get; set; }
        public string Allow { get; set; }
        public string Public { get; set; }
        public string DAV { get; set; }
        public string Author { get; set; }
        public string ProxyAuthenticate { get; set; }
        public string WWWAuthenticate { get; set; }
        public byte[] Message { get; set; }

        public byte[] GetBytes()
        {

            if (!Utilities.ArrayIsNullOrEmpty(this.Message))
            {
                this.ContentLength = Convert.ToString(this.Message.Length);
            }

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.StringWrite(this.Version);
                packetWriter.Write(new byte[1] { 0x20 });
                packetWriter.StringWrite(this.StatusCode);
                packetWriter.Write(new byte[1] { 0x20 });
                packetWriter.StringWrite(this.ReasonPhrase);
                packetWriter.Write(new byte[2] { 0x0d, 0x0a });

                if (!String.IsNullOrEmpty(this.Connection))
                {
                    packetWriter.StringWrite("Connection: ");
                    packetWriter.StringWrite(this.Connection);
                    packetWriter.Write(new byte[2] { 0x0d, 0x0a });
                }

                if (!String.IsNullOrEmpty(this.Allow))
                {
                    packetWriter.StringWrite("Allow: ");
                    packetWriter.StringWrite(this.Allow);
                    packetWriter.Write(new byte[2] { 0x0d, 0x0a });
                }

                if (!String.IsNullOrEmpty(this.Public))
                {
                    packetWriter.StringWrite("Public: ");
                    packetWriter.StringWrite(this.Public);
                    packetWriter.Write(new byte[2] { 0x0d, 0x0a });
                }

                if (!String.IsNullOrEmpty(this.DAV))
                {
                    packetWriter.StringWrite("DAV: ");
                    packetWriter.StringWrite(this.DAV);
                    packetWriter.Write(new byte[2] { 0x0d, 0x0a });
                }

                if (!String.IsNullOrEmpty(this.Author))
                {
                    packetWriter.StringWrite("MS-Author-via: ");
                    packetWriter.StringWrite(this.Author);
                    packetWriter.Write(new byte[2] { 0x0d, 0x0a });
                }

                if (!String.IsNullOrEmpty(this.Server))
                {
                    packetWriter.StringWrite("Server: ");
                    packetWriter.StringWrite(this.Server);
                    packetWriter.Write(new byte[2] { 0x0d, 0x0a });
                }

                if (!String.IsNullOrEmpty(this.Date))
                {
                    packetWriter.StringWrite("Date: ");
                    packetWriter.StringWrite(this.Date);
                    packetWriter.Write(new byte[2] { 0x0d, 0x0a });
                }

                packetWriter.StringWrite("Content-Length: ");
                packetWriter.StringWrite(this.ContentLength);
                packetWriter.Write(new byte[2] { 0x0d, 0x0a });

                if (!String.IsNullOrEmpty(this.ProxyAuthenticate))
                {
                    packetWriter.StringWrite("Proxy-Authenticate: ");
                    packetWriter.StringWrite(this.ProxyAuthenticate);
                    packetWriter.Write(new byte[2] { 0x0d, 0x0a });
                }

                if (!String.IsNullOrEmpty(this.WWWAuthenticate))
                {
                    packetWriter.StringWrite("WWW-Authenticate: ");
                    packetWriter.StringWrite(this.WWWAuthenticate);
                    packetWriter.Write(new byte[2] { 0x0d, 0x0a });
                }

                if (!String.IsNullOrEmpty(this.ContentType))
                {
                    packetWriter.StringWrite("Content-Type: ");
                    packetWriter.StringWrite(this.ContentType);
                    packetWriter.Write(new byte[2] { 0x0d, 0x0a });
                }

                packetWriter.Write(new byte[2] { 0x0d, 0x0a });  

                if (!Utilities.ArrayIsNullOrEmpty(this.Message))
                {
                    packetWriter.Write(this.Message);
                }

                return memoryStream.ToArray();
            }

        }

    }

}
