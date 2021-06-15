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

namespace Quiddity.DNS
{
    class DNSChecker
    {
        public string[] IgnoreHosts { get; set; }
        public string[] ReplyToHosts { get; set; }
        public string[] IgnoreIPs { get; set; }
        public string[] ReplyToIPs { get; set; }
        public string[] IgnoreDomains { get; set; }
        public string[] ReplyToDomains { get; set; }
        public string[] Types { get; set; }
        public string[] Services { get; set; }
        public IList<string> IPCaptures { get; set; }
        public bool Enabled { get; set; }
        public bool Inspect { get; set; }
        public bool IPv6 { get; set; }
        public bool Local { get; set; }
        public bool Repeat { get; set; }
        public string OutputReplyAllowed { get; set; }
        public string OutputMessage { get; set; }
        public string OutputInspect { get; set; }
        public string OutputDisabled { get; set; }
        public string OutputTypeDenied { get; set; }
        public string OutputServiceDenied { get; set; }
        public string OutputHostDenied { get; set; }
        public string OutputIPDenied { get; set; }
        public string OutputDomainDenied { get; set; }
        public string OutputRepeat { get; set; }

        public DNSChecker()
        {
            this.OutputReplyAllowed = "response sent";
            this.OutputInspect = "inspect only";
            this.OutputDisabled = "disabled";
            this.OutputHostDenied = "host ignored";
            this.OutputIPDenied = "IP ignored";
            this.OutputDomainDenied = "domain ignored";
            this.OutputTypeDenied = "type ignored";
            this.OutputServiceDenied = "service ignored";
            this.OutputRepeat = "previous capture";
        }

        public bool Check(string name, string type, string clientIP)
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
            else if (IsRepeat(clientIP))
            {
                this.OutputMessage = this.OutputRepeat;
                return false;
            }
            else if (!TypeIsAllowed(type))
            {
                this.OutputMessage = this.OutputTypeDenied;
                return false;
            }
            else if (!ServiceIsAllowed(name, type))
            {
                this.OutputMessage = this.OutputServiceDenied;
                return false;
            }
            else if (HostIsDenied(name))
            {
                this.OutputMessage = this.OutputHostDenied;
                return false;
            }
            else if (!HostIsAllowed(name))
            {
                this.OutputMessage = this.OutputIPDenied;
                return false;
            }
            else if (FQDNIsDenied(name))
            {
                this.OutputMessage = this.OutputHostDenied;
                return false;
            }
            else if (!FQDNIsAllowed(name))
            {
                this.OutputMessage = this.OutputIPDenied;
                return false;
            }
            else if (IPIsDenied(clientIP))
            {
                this.OutputMessage = this.OutputIPDenied;
                return false;
            }
            else if (!IPIsAllowed(clientIP))
            {
                this.OutputMessage = this.OutputIPDenied;
                return false;
            }
            else if (DomainIsDenied(name))
            {
                this.OutputMessage = this.OutputDomainDenied;
                return false;
            }
            else if (!DomainIsAllowed(name))
            {
                this.OutputMessage = this.OutputDomainDenied;
                return false;
            }

            this.OutputMessage = this.OutputReplyAllowed;
            return true;
        }

        public bool IsRepeat(string clientIP)
        {

            if (!this.Repeat && this.IPCaptures.Contains(clientIP))
            {
                return true;
            }

            return false;
        }

        public bool TypeIsAllowed(string type)
        {

            if (!Utilities.ArrayIsNullOrEmpty(this.Types) && (!Array.Exists(this.Types, element => element == type.ToUpper())))
            {
                return false;
            }

            return true;
        }

        public bool ServiceIsAllowed(string name, string type)
        {

            if (type.Equals("SRV") && TypeIsAllowed("SRV"))
            {
                string service = "";

                if (name.StartsWith("_ldap."))
                {
                    service = "LDAP";
                }
                else if (name.StartsWith("_kerberos."))
                {
                    service = "Kerberos";
                }
                else if (name.StartsWith("_kpassword."))
                {
                    service = "KPassword";
                }
                else if (name.StartsWith("_gc."))
                {
                    service = "GC";
                }

                if (!Utilities.ArrayIsNullOrEmpty(this.Services) && (!Array.Exists(this.Services, element => element == service.ToUpper())))
                {
                    return false;
                }
            }

            return true;
        }

        public bool HostIsDenied(string name)
        {
            string host = (name.Split('.'))[0];

            if (!Utilities.ArrayIsNullOrEmpty(this.IgnoreHosts) && Array.Exists(this.IgnoreHosts, element => element == host.ToUpper()))
            {
                return true;
            }

            return false;
        }

        public bool HostIsAllowed(string name)
        {
            string host = (name.Split('.'))[0];

            if (!Utilities.ArrayIsNullOrEmpty(this.ReplyToHosts) && !Array.Exists(this.ReplyToHosts, element => element == host.ToUpper()))
            {
                return false;
            }

            return true;
        }

        public bool FQDNIsDenied(string name)
        {

            if (!Utilities.ArrayIsNullOrEmpty(this.IgnoreHosts) && Array.Exists(this.IgnoreHosts, element => element == name.ToUpper()))
            {
                return true;
            }

            return false;
        }

        public bool FQDNIsAllowed(string name)
        {

            if (!Utilities.ArrayIsNullOrEmpty(this.ReplyToHosts) && !Array.Exists(this.ReplyToHosts, element => element == name.ToUpper()))
            {
                return false;
            }

            return true;
        }

        public bool IPIsDenied(string clientIP)
        {

            if (!Utilities.ArrayIsNullOrEmpty(this.IgnoreIPs) && Array.Exists(this.IgnoreIPs, element => element == clientIP.ToUpper()))
            {
                return true;
            }

            return false;
        }

        public bool IPIsAllowed(string clientIP)
        {

            if (!Utilities.ArrayIsNullOrEmpty(this.ReplyToIPs) && !Array.Exists(this.ReplyToIPs, element => element == clientIP.ToUpper()))
            {
                return false;
            }

            return true;
        }

        public bool DomainIsDenied(string domain)
        {
            int index = domain.IndexOf(".");
            
            while (index > -1)
            {

                if (!Utilities.ArrayIsNullOrEmpty(this.IgnoreDomains) && Array.Exists(this.IgnoreDomains, element => element == domain.ToUpper()))
                {
                    return true;
                }

                
                index = domain.IndexOf(".");

                if (index > -1)
                {
                    domain = domain.Substring(index).TrimStart('.');
                }

            }

            return false;
        }

        public bool DomainIsAllowed(string domain)
        {
            int index = domain.IndexOf(".");

            if (index == -1 || Utilities.ArrayIsNullOrEmpty(this.ReplyToDomains))
            {
                return true;
            }

            while (index > -1)
            {

                if (Array.Exists(this.ReplyToDomains, element => element == domain.ToUpper()))
                {
                    return true;
                }

                index = domain.IndexOf(".");

                if (index > -1)
                {
                    domain = domain.Substring(index).TrimStart('.');
                }

            }

            return false;
        }

    }

}
