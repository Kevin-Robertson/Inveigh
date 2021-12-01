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
using System.Linq;
using System.Text;

namespace Quiddity.DHCPv6
{
    class DHCPv6Checker
    {
        public string[] IgnoreMACs { get; set; }
        public string[] ReplyToMACs { get; set; }
        public IList<string> HostCaptures { get; set; }
        public bool Enabled { get; set; }
        public bool Inspect { get; set; }
        public bool Repeat { get; set; }
        public bool Microsoft { get; set; }
        public bool Local { get; set; }
        public string OutputReplyAllowed { get; set; }
        public string OutputMessage { get; set; }
        public string OutputInspect { get; set; }
        public string OutputDisabled { get; set; }
        public string OutputLocal { get; set; }
        public string OutputHostDenied { get; set; }
        public string OutputMACDenied { get; set; }
        public string OutputVendorDenied { get; set; }
        public string OutputIPDenied { get; set; }
        public string OutputRepeat { get; set; }

        public bool Check(string clientMAC, string clientHost, string listenerMAC, bool isMicrosoft)
        {

            if (this.Inspect)
            {
                this.OutputMessage = this.OutputInspect;
                return false;
            }
            else if (!this.Enabled)
            {
                this.OutputMessage = this.OutputDisabled;
                return false;
            }
            else if (!isMicrosoft)
            {
                this.OutputMessage = this.OutputVendorDenied;
                return false;
            }
            else if (IsLocal(clientMAC, listenerMAC))
            {
                this.OutputMessage = this.OutputLocal;
                return false;
            }
            else if (IsRepeat(clientHost))
            {
                this.OutputMessage = this.OutputRepeat;
                return false;
            }
            else if (MACIsDenied(clientMAC))
            {
                this.OutputMessage = this.OutputMACDenied;
                return false;
            }
            else if (!MACIsAllowed(clientMAC))
            {
                this.OutputMessage = this.OutputMACDenied;
                return false;
            }

            this.OutputMessage = this.OutputReplyAllowed;
            return true;
        }

        public bool IsRepeat(string host)
        {
            host = host.Split('.')[0].ToUpper();

            if (!this.Repeat && this.HostCaptures.Contains(host))
            {
                return true;
            }

            return false;
        }

        public bool IsLocal(string clientMAC, string listenerMAC)
        {

            if (!this.Local && string.Equals(clientMAC, listenerMAC))
            {
                return true;
            }

            return false;
        }

        public bool MACIsDenied(string mac)
        {
          
            if (!Utilities.ArrayIsNullOrEmpty(this.IgnoreMACs) && (Array.Exists(this.IgnoreMACs, element => element == mac.Replace(":", "").ToUpper())))
            {
                return true;
            }

            return false;
        }

        public bool MACIsAllowed(string mac)
        {

            if (!Utilities.ArrayIsNullOrEmpty(this.ReplyToMACs) && (!Array.Exists(this.ReplyToMACs, element => element == mac.Replace(":","").ToUpper())))
            {
                return false;
            }

            return true;
        }

    }
}
