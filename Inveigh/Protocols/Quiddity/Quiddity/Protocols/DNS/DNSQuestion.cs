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
using System.Text;

namespace Quiddity.DNS
{
    class DNSQuestion
    {

        // https://tools.ietf.org/html/rfc1035
        public byte[] QName { get; set; }
        public byte[] QType { get; set; }
        public byte[] QClass { get; set; }

        // Custom
        public string Name { get; set; }
        public string Type { get; set; }

        public DNSQuestion()
        {
            this.QName = new byte[0];
            this.QType = new byte[0];
            this.QClass = new byte[0];
        }

        public DNSQuestion(byte[] data)
        {
            ReadBytes(data, 12);
        }

        public DNSQuestion(byte[] data, int offset)
        {
            ReadBytes(data, offset);
        }

        public void ReadBytes(byte[] data, int offset)
        {
            int segmentLength = data[offset];
            int lengthIndex = offset;
            int length = segmentLength + 1;

            do
            {
                lengthIndex += segmentLength + 1;
                segmentLength = data[lengthIndex];
                length += segmentLength + 1;
            }
            while (segmentLength != 0);

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = offset;
                this.QName = packetReader.ReadBytes(length);
                this.QType = packetReader.ReadBytes(2);
                this.QClass = packetReader.ReadBytes(2);
            }

            this.Name = ConvertName();
            this.Type = GetType();
        }

        public byte[] GetBytes()
        {

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.Write(this.QName);
                packetWriter.Write(this.QType);
                packetWriter.Write(this.QClass);
                return memoryStream.ToArray();
            }

        }

        protected virtual string ConvertName()
        {
            string hostname = "";
            int hostnameLength = this.QName[0];
            int index = 0;
            int i = 0;

            do
            {
                int hostnameSegmentLength = hostnameLength;
                byte[] hostnameSegment = new byte[hostnameSegmentLength];
                Buffer.BlockCopy(this.QName, (index + 1), hostnameSegment, 0, hostnameSegmentLength);
                hostname += Encoding.UTF8.GetString(hostnameSegment);
                index += hostnameLength + 1;
                hostnameLength = this.QName[index];
                i++;

                if (hostnameLength > 0)
                {
                    hostname += ".";
                }

            }
            while (hostnameLength != 0 && i <= 127);

            return hostname;
        }

        protected new virtual string GetType()
        {
            string type = "";

            switch (BitConverter.ToString(this.QType))
            {

                case "00-01":
                    type = "A";
                    break;

                case "00-1C":
                    type = "AAAA";
                    break;

                case "00-05":
                    type = "CNAME";
                    break;

                case "00-27":
                    type = "DNAME";
                    break;

                case "00-0F":
                    type = "MX";
                    break;

                case "00-02":
                    type = "NS";
                    break;

                case "00-0C":
                    type = "PTR";
                    break;

                case "00-06":
                    type = "SOA";
                    break;

                case "00-21":
                    type = "SRV";
                    break;

                case "00-10":
                    type = "TXT";
                    break;

                case "00-FF":
                    type = "ANY";
                    break;

            }

            return type;
        }

    }
}
