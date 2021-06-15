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
using Quiddity.DNS;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Quiddity.NetBIOS
{
    class NetBIOSNSQuestion : DNSQuestion
    {
        public NetBIOSNSQuestion()
        {

        }

        public NetBIOSNSQuestion(byte[] data)
        {
            ReadBytes(data, 12);
        }

        protected override string ConvertName()
        {
            byte[] nameData = new byte[30];
            Buffer.BlockCopy(this.QName, 1, nameData, 0, 30);
            string hex = BitConverter.ToString(nameData);
            string[] nameArray = hex.Split('-');
            string characters = "";

            foreach (string character in nameArray)
            {
                characters += new string(Convert.ToChar(Convert.ToInt16(character, 16)), 1);
            }

            if (characters.Contains("CA"))
            {
                characters = characters.Substring(0, characters.IndexOf("CA"));
            }

            int i = 0;
            string nameSubstring = "";

            do
            {
                byte characterByte = (byte)Convert.ToChar(characters.Substring(i, 1));
                characterByte -= 0x41;
                nameSubstring += Convert.ToString(characterByte, 16);
                i++;
            }
            while (i < characters.Length);

            i = 0;
            string name = "";

            do
            {
                name += (Convert.ToChar(Convert.ToInt16(nameSubstring.Substring(i, 2), 16)));
                i += 2;
            }
            while (i < nameSubstring.Length - 1);

            if (characters.StartsWith("ABAC") && characters.EndsWith("AC"))
            {
                name = name.Substring(2);
                name = name.Substring(0, name.Length - 1);
                name = string.Concat("<01><02>", name, "<02>");
            }

            Regex printable = new Regex("[^\x00-\x7F]+");

            if (printable.IsMatch(name))
            {
                return "";
            }

            return name;
        }

        protected override string GetType()
        {
            byte[] typeData = new byte[2];
            Buffer.BlockCopy(this.QName, 31, typeData, 0, 2);
            string nbnsQuery = BitConverter.ToString(typeData);
            string nbnsQueryType = "";

            switch (nbnsQuery)
            {

                case "41-41":
                    nbnsQueryType = "00";
                    break;

                case "41-42":
                    nbnsQueryType = "01";
                    break;

                case "41-43":
                    nbnsQueryType = "02";
                    break;

                case "41-44":
                    nbnsQueryType = "03";
                    break;

                case "43-41":
                    nbnsQueryType = "20";
                    break;

                case "42-4C":
                    nbnsQueryType = "1B";
                    break;

                case "42-4D":
                    nbnsQueryType = "1C";
                    break;

                case "42-4E":
                    nbnsQueryType = "1D";
                    break;

                case "42-4F":
                    nbnsQueryType = "1E";
                    break;

            }

            return nbnsQueryType;
        }

    }
}
