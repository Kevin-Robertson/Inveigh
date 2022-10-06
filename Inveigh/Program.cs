using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.IO;
using System.Collections;

namespace Inveigh
{
    class Program
    {
        //begin parameters - set defaults as needed before compile
        public static string argCert = "MIIKaQIBAzCCCiUGCSqGSIb3DQEHAaCCChYEggoSMIIKDjCCBg8GCSqGSIb3DQEHAaCCBgAEggX8MIIF+DCCBfQGCyqGSIb3DQEMCgECoIIE/jCCBPowHAYKKoZIhvcNAQwBAzAOBAgWD1s9eOnQ+gICB9AEggTYRCVf30yt6/DwB9YstkoQ/dYXtDyGEUychrTBlJleP3xHlqkglZXuJXje2Wkx5U25+fajC6EsOJUjDzzF3Jm/1iyS7J9uXs5INEtA1Qg8zLlkggaxQcl6izWAg7cgNWGb2mVg+cYWe88WnCc04h05X01GsQ53YZkWTAoGJ3ogPei8C0n+MFkj73t++WhC2T7oVnQTd0IzPnfDwwCPzPJB9wqKJF6WwImysTMAaVdFCRd+4nqWZsYqgwhjEtdAKLZfxpxRoYvLwvLL/+QtK9MxlaOX3j5/Hk+EuwqsUTTlEPGFog1GZuB6fMI9/CIy0LhxugJxuZkxsNe3Ijh5PHPTpLz9Z6EubNJtYAn8t9r3Mu3kMhWRe0tyJbO3VfftBkp3aqg/Os0iETPdsNTy5UCwzgYKSd2y2nmyHMlNPOdlrobMsoGg/vkIDOWyslma8exvjj8LzFrCriQ6mXE4qfcZU5GSkVxsqCEidlj8Ex7AUJObRNmVn01Q+83O/05/JYipudDG6SsheagsHPpbzI+Nxa5LFE0xyNJk3xRKFUNa0/wr7mKQVYu5UnPiuCIUYIwqK77yu2G5Tcnst/4STc1TyAWeacUmhynTCnF98HIxXrU160HofVO1s7kRBpc01vVM4wc7xrJk78KmjeXtFxuKOBSTVb253Q+k5a0P3oJ3PudQGWgrQKr7HpAbL19C9l+y3tQbSuDCxFZa2vKfYfQ7YwNvTTPbbDwFG6kRAn61hjWRb2Gc1ZuBmNEUtMeVtbGj3Lg2wfM3E5OSB2t7oiL+yOk78tvoPmCsKVtPKjAPoZ7bq9PST/iqaRzbh7FWyo8NRhh/mLP70KnjcT3eB2HCiX/5o/UroweKU7S5lebG1qFGQykgvz01IhGL0dOlsUQY+ZzbLIYciSunCN7GQjAc4yPlrFeaIO3iFu/ZatVasqS97nFz/VuFwCrCemiV+hDoLykFcyhwYQofaFXJ0eTlg92oeu6JkChP9Z6xgcTq5a/IRH+tRFHbQ0UONdPjkZwlkSl6W2VLptkxBTe0FZjXy/SVqhmSXR2PKe9le3a+zBsYlv7eqiDaf7T/ZlWe2AUJFNPtmd+0tLq9L0Wlias3mJb3hcNDw6k9xoSFTFtfbMeUHQhoA8Ae4+hrHJT5kGmqTXdm6G4QkhlswN5HakRESTvXHs7rpI5AlO8suFIxB+QxaeBhBZTJS1Q5K1LlCvC93slnzlg+O3XSX6lGpzNuaTT0pPPL15cdW0i0OpGNQH9rc84N4PXpQcGW1t8Ca0QQnNcip28MfKA64SFLFMHtQqwrrWx7tHJDtPLdOzPeuUHW2JnfyrhZlxQwS70IKJI9J0O3+z8dsLTgxLgfq/7QyOe9qn+9avV2tRReKyZwzU+TDvUaMzVXH8X0GauXO9AMB8s7PkHT1oxxtNtqOYuyleJMM557p14vgGKPBllY/ASNvzDUYja8SBBpxaj6w2KV75LKH0ktIABII8e4G8xADidmJhWD7emoLc7Ho5FIiYqjtyyHNjIXNyChhoHdUHnhqpd7wZ2Dw80hQAUypG1VDhBBRZU/ti1XlfDJ305zt0QeU7e4SM7LIF/5c8OpgvQH6gBz/V2KuKM+qBxyhdq0RJQYkthGjH7n6gDOTflyPSJGLNRToKQQtTGB4jANBgkrBgEEAYI3EQIxADATBgkqhkiG9w0BCRUxBgQEAQAAADBdBgkqhkiG9w0BCRQxUB5OAHQAZQAtAGYAZQA2ADIAMQA5AGQAZgAtADgANwBkAGMALQA0AGEAZQBmAC0AYgA0AGYANgAtADcANwBlADIAZAA0AGIAYwBkAGUANwA1MF0GCSsGAQQBgjcRATFQHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUAIABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIwggP3BgkqhkiG9w0BBwagggPoMIID5AIBADCCA90GCSqGSIb3DQEHATAcBgoqhkiG9w0BDAEDMA4ECGhIHlDjLTyAAgIH0ICCA7CSK4ltfEIhaTytx5Cnz2cQuj0tlB7N54jdmEI8uFsA5kB5yR9bo5RyETfveI+6a+3u5VWCvkyV4b8c8MbED1jpOAmkNZ+wENIre7W5eCGIDxGSZJtaxPlPTLkfT7uxpvOIqWQTpOTATqjfLACTbo7cxitsZFD+Gm5NdqCFkEUAlihC7bvVe5XVxm6M1DSSKxeM1k8uEIXCi0zGc+awEjRNLj9ee2i4oyUNTdNSHIklPuURknEMFItaKsa3hRsaUC7AZzgt03uNV+HEZG1rrqf6qz6J4IQeCC25UzlxM433Nxv92jJkK7tLDgQykDpl6XsXaUi+pZHw9iuLR/lat9RzjhNRv7O5AEQZAEhxVaXE9e2T2ByNvTsiudsS6gwrjq2QSHFTD9LA1iO4/2Zo9ujOCj0OCP5lF8NHWJXA7ove+b683190N52UH3cKi0UFajsgt4Tp3JCyx4sBoBo8vxXGCz/u66oeA81pX/QMkPQxwJeVvnJGLa1MPqkuRVwdby2RjP0hgGudX2/OOj7mtUrJpfG2A+TvEidridpxEN9PsFPS2DXwTc+hn5YFiMJgK3jptkQfQj3Uo/5TWF0Oa58xGZfTVVNgX9QbUSYDKlhA22cyrqySoMhY6y2nqGq4LBSi20pVdPZbEhI2OlWeq7auhxqKAM1iy2cjW8BS4djG9M3YYdXDyO55MziPfDpfQCthNHLqarV4w4M+5OjYggSkUaikc5NFjpXDclzNsvMveyt4cdF8cODjRi9igF88kVYKRzkcHa8Ok64lHtML1P/DWNn3lWdUKKRXtU1LL9+/Adp8JzYeTNUJy/xfd5X4X+Tz6fPkhvjdu/PYrX3vzSUsEhmLywLTe2nyBBuv7XGme8mGupUgaKE6EGECH6JPNFBYaQmV/mwHgQMuLRG8OyvReTt1AMn0cuT4vzqnv8ApwxYMcfwVl23R0tTytbGcbIOlolA7in2LcR5OG9fCgxt6el+pAj0IAtP2Jq4DkXdPX9Ohx9B3Hc+7M9cUCj0oT8WDo3sS57rayy9D5VX4UC7uaGchOrs0TQ6mgdgIvEhXhHj0hqwjQzaW1udEXjbUJN55UxDCQbyiqdpdskV9V1+hnjHQqTLcS4UYqV/ChA7dDoskWA4rUB1/EIo0QIcKDNjMrA67E4gjt+ONlD/p3RMRhiMOtc6T90dR6yiHjF7PFa24xVNpeV1VugC7doZ7MXZsiblgUrT9gg4pO1J8PnOs4TwJb9DGgGBTkQw9AxKP1TA7MB8wBwYFKw4DAhoEFD2xo+0lgWL1jEX5sN5TfTNIdor8BBRtEuUbR/VKBxuoDmnvDwJkV4RNugICB9A=";
        public static string argCertPassword = "password";
        public static string argChallenge = "";
        public static string argConsole = "5";
        public static string argConsoleLimit = "-1";
        public static string argConsoleStatus = "0";
        public static string argConsoleUnique = "Y";
        public static string argDHCPv6 = "N";
        public static string argDHCPv6TTL = "30";
        public static string argDNS = "Y";
        public static string argDNSHost = "";
        public static string argDNSTTL = "30";
        public static string[] argDNSTypes = { "A" };
        public static string[] argDNSSRV = { "LDAP" };
        public static string argDNSSuffix = "";
        public static string argFileOutput = "Y";
        public static string argFileDirectory = Directory.GetCurrentDirectory();
        public static string argFilePrefix = "Inveigh";
        public static string argFileUnique = "Y";
        public static string argHelp = "";
        public static string argHTTP = "Y";
        public static string argHTTPAuth = "NTLM";
        public static string argHTTPRealm = "ADFS";
        public static string[] argHTTPPorts = { "80" };
        public static string argHTTPResponse = "";
        public static string argHTTPS = "N";
        public static string[] argHTTPSPorts = { "443" };
        public static string argICMPv6 = "N";
        public static string argICMPv6Interval = "200";
        public static string argICMPv6TTL = "300";
        public static string argInspect = "N";
        public static string argIPv4 = "Y";
        public static string argIPv6 = "Y";
        public static string argSniffer = "Y";
        public static string argSnifferIP = "";
        public static string argSnifferIPv6 = "";
        public static string argListenerIP = "0.0.0.0";
        public static string argListenerIPv6 = "::";
        public static string argLDAP = "Y";
        public static string[] argLDAPPorts = { "389" };
        public static string argLLMNR = "Y";
        public static string argLLMNRTTL = "30";
        public static string[] argLLMNRTypes = { "A" };
        public static string argLogOutput = "Y";
        public static string argMAC = "";
        public static string argMachineAccount = "Y";
        public static string argMDNS = "N";
        public static string[] argMDNSQuestions = { "QU", "QM" };
        public static string argMDNSTTL = "120";
        public static string[] argMDNSTypes = { "A" };
        public static string argMDNSUnicast = "Y";
        public static string argNBNS = "N";
        public static string argNBNSTTL = "165";
        public static string[] argNBNSTypes = { "00", "20" };
        public static string argProxy = "N";
        public static string argProxyAuth = "NTLM";
        public static string argProxyPort = "8492";
        public static string argRunCount = "0";
        public static string argRunTime = "0";
        public static string argSMB = "Y";
        public static string[] argSMBPorts = { "445" };
        public static string[] argIgnoreAgents = { "Firefox" };
        public static string[] argIgnoreDomains;
        public static string[] argIgnoreIPs;
        public static string[] argIgnoreQueries;
        public static string[] argIgnoreMACs;
        public static string[] argReplyToDomains;
        public static string[] argReplyToQueries;
        public static string[] argReplyToIPs;
        public static string[] argReplyToMACs;
        public static string argSpooferIP = "";        
        public static string argSpooferIPv6 = "";
        public static string argLocal = "N";
        public static string argRepeat = "Y";
        public static string argWebDAV = "Y";
        public static string argWebDAVAuth = "NTLM";
        public static string argWPADAuth = "NTLM";
        public static string argWPADResponse = "";
        //end parameters
        public static ConsoleColor colorPositive = ConsoleColor.Green; // change output colors here
        public static ConsoleColor colorNegative = ConsoleColor.Red;
        public static ConsoleColor colorDisabled = ConsoleColor.DarkGray;
        public static Hashtable smbSessionTable = Hashtable.Synchronized(new Hashtable());
        public static Hashtable httpSessionTable = Hashtable.Synchronized(new Hashtable());
        public static IList<string> outputList = new List<string>();
        public static IList<string> consoleList = new List<string>();
        public static IList<string> logList = new List<string>();
        public static IList<string> logFileList = new List<string>();
        public static IList<string> cleartextList = new List<string>();
        public static IList<string> cleartextFileList = new List<string>();
        public static IList<string> hostList = new List<string>();
        public static IList<string> hostFileList = new List<string>();
        public static IList<string> ntlmv1List = new List<string>();
        public static IList<string> ntlmv2List = new List<string>();
        public static IList<string> ntlmv1UniqueList = new List<string>();
        public static IList<string> ntlmv2UniqueList = new List<string>();
        public static IList<string> ntlmv1FileList = new List<string>();
        public static IList<string> ntlmv2FileList = new List<string>();
        public static IList<string> ntlmv1UsernameList = new List<string>();
        public static IList<string> ntlmv2UsernameList = new List<string>();
        public static IList<string> ntlmv1UsernameFileList = new List<string>();
        public static IList<string> ntlmv2UsernameFileList = new List<string>();
        public static IList<string> dhcpv6List = new List<string>();
        public static IList<string> IPCaptureList = new List<string>();
        public static IList<string> HostCaptureList = new List<string>();
        public static IList<string> commandHistoryList = new List<string>();
        public static bool enabledConsoleOutput = true;     
        public static bool enabledConsoleUnique = false;
        public static bool enabledDHCPv6 = false;
        public static bool enabledDNS = false;
        public static bool enabledElevated = false;
        public static bool enabledFileOutput = false;
        public static bool enabledFileUnique = false;
        public static bool enabledHTTP = false;
        public static bool enabledHTTPS = false;
        public static bool enabledICMPv6 = false;
        public static bool enabledInspect = false;
        public static bool enabledIPv4 = false;
        public static bool enabledIPv6 = false;
        public static bool enabledLDAP = false;
        public static bool enabledLLMNR = false;
        public static bool enabledLocal = false;
        public static bool enabledLogOutput = false;
        public static bool enabledMachineAccountCapture = false;
        public static bool enabledMDNS = false;
        public static bool enabledMDNSUnicast = false;
        public static bool enabledNBNS = false;    
        public static bool enabledProxy = false;
        public static bool enabledRepeat = false;
        public static bool enabledSMB = false;
        public static bool enabledSniffer = false;
        public static bool enabledWebDAV = false;      
        public static bool enabledWindows = true;
        public static bool isRunning = true;
        public static bool isSession = false;
        public static bool isNTLMv1Updated = false;
        public static bool isNTLMv2Updated = false;
        public static bool isCleartextUpdated = false;
        public static bool isNTLMv1UniqueUpdated = false;
        public static bool isNTLMv2UniqueUpdated = false;
        public static bool isCleartextUniqueUpdated = false;
        public static IPAddress listenerIPAddress = IPAddress.Any;
        public static IPAddress listenerIPv6Address = IPAddress.IPv6Any;
        public static int dhcpv6Random = (new Random()).Next(1, 9999);
        public static uint dnsSerial = (uint)(new Random()).Next(1, 9999);
        public static int icmpv6Interval;
        public static int dhcpv6IPIndex = 1;
        public static int console;
        public static int consoleQueueLimit = -1;
        public static int consoleStatus = 0;
        public static int runCount = 0; // todo check
        public static int runTime = 0;
        public static int ntlmv1Count = 0;
        public static int ntlmv2Count = 0;
        public static int cleartextCount = 0;
        public static int ntlmv1UniqueCount = 0;
        public static int ntlmv2UniqueCount = 0;
        public static int cleartextUniqueCount = 0;
        public static int networkInterfaceIndexIPv4 = 0;
        public static int networkInterfaceIndexIPv6 = 0;
        public static string computerName = Environment.MachineName;
        public static string netbiosDomain = Environment.UserDomainName;
        public static string dnsDomain = "";    
        public static ulong smb2Session = 5548434740922023936; // todo check
        public static string version = "2.0.9";

        static void Main(string[] arguments)
        {

#if !NETFRAMEWORK
            if (!System.OperatingSystem.IsWindows())
            {
                enabledWindows = false;
            }
#endif
            bool allValid = true;

            if (arguments.Length > 0)
            {

                foreach (var entry in arguments.Select((value, index) => new { index, value }))
                {
                    string argument = entry.value.ToUpper();

                    try
                    {

                        switch (argument)
                        {

                            case "-CERT":
                            case "/CERT":
                                argCert = arguments[entry.index + 1];
                                break;

                            case "-CERTPASSWORD":
                            case "/CERTPASSWORD":
                                argCertPassword = arguments[entry.index + 1];
                                break;

                            case "-CHALLENGE":
                            case "/CHALLENGE":
                                argChallenge = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-CONSOLE":
                            case "/CONSOLE":
                                argConsole = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-CONSOLELIMIT":
                            case "/CONSOLELIMIT":
                                argConsoleLimit = arguments[entry.index + 1];
                                break;

                            case "-CONSOLESTATUS":
                            case "/CONSOLESTATUS":
                                argConsoleStatus = arguments[entry.index + 1];
                                break;

                            case "-CONSOLEUNIQUE":
                            case "/CONSOLEUNIQUE":
                                argConsoleUnique = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-DHCPV6":
                            case "/DHCPV6":
                                argDHCPv6 = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-DHCPV6TTL":
                            case "/DHCPV6TTL":
                                argDHCPv6TTL = arguments[entry.index + 1];
                                break;

                            case "-DNS":
                            case "/DNS":
                                argDNS = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-DNSHOST":
                            case "/DNSHOST":
                                argDNSHost = arguments[entry.index + 1];
                                break;

                            case "-DNSSUFFIX":
                            case "/DNSSUFFIX":
                                argDNSSuffix = arguments[entry.index + 1];
                                break;

                            case "-DNSSRV":
                            case "/DNSSRV":
                                argDNSSRV = arguments[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-DNSTTL":
                            case "/DNSTTL":
                                argDNSTTL = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-DNSTYPES":
                            case "/DNSTYPES":
                                argDNSTypes = arguments[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-FILEDIRECTORY":
                            case "/FILEDIRECTORY":
                                argFileDirectory = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-FILEOUTPUT":
                            case "/FILEOUTPUT":
                                argFileOutput = arguments[entry.index + 1].ToUpper();
                                break;
                           
                            case "-FILEPREFIX":
                            case "/FILEPREFIX":
                                argFilePrefix = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-FILEUNIQUE":
                            case "/FILEUNIQUE":
                                argFileUnique = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-HTTP":
                            case "/HTTP":
                                argHTTP = arguments[entry.index + 1].ToUpper();
                                break;                            

                            case "-HTTPAUTH":
                            case "/HTTPAUTH":
                                argHTTPAuth = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-HTTPBASICREALM":
                            case "/HTTPBASICREALM":
                                argHTTPRealm = arguments[entry.index + 1];
                                break;

                            case "-HTTPPORTS":
                            case "/HTTPPORTS":
                                argHTTPPorts = arguments[entry.index + 1].Split(',');
                                break;

                            case "-HTTPS":
                            case "/HTTPS":
                                argHTTPS = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-HTTPSPORTS":
                            case "/HTTPSPORTS":
                                argHTTPSPorts = arguments[entry.index + 1].Split(',');
                                break;

                            case "-HTTPRESPONSE":
                            case "/HTTPRESPONSE":
                                argHTTPResponse = arguments[entry.index + 1];
                                break;

                            case "-ICMPV6":
                            case "/ICMPV6":
                                argICMPv6 = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-ICMPV6INTERVAL":
                            case "/ICMPV6INTERVAL":
                                argICMPv6Interval = arguments[entry.index + 1];
                                break;

                            case "-ICMPV6TTL":
                            case "/ICMPV6TTL":
                                argICMPv6TTL = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-IGNOREAGENTS":
                            case "/IGNOREAGENTS":
                                argIgnoreAgents = arguments[entry.index + 1].Split(',');
                                break;

                            case "-IGNOREDOMAINS":
                            case "/IGNOREDOMAINS":
                                argIgnoreDomains = arguments[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-IGNOREIPS":
                            case "/IGNOREIPS":
                                argIgnoreIPs = arguments[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-IGNOREMACS":
                            case "/IGNOREMACS":
                                argIgnoreMACs = arguments[entry.index + 1].ToUpper().Replace(":", "").Replace("-", "").Split(',');
                                break;

                            case "-IGNOREQUERIES":
                            case "/IGNOREQUERIES":
                                argIgnoreQueries = arguments[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-INSPECT":
                            case "/INSPECT":
                                argInspect = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-IPV4":
                            case "/IPV4":
                                argIPv4 = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-IPV6":
                            case "/IPV6":
                                argIPv6 = arguments[entry.index + 1].ToUpper();
                                break;                            

                            case "-LDAP":
                            case "/LDAP":
                                argLDAP = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-LDAPPORTS":
                            case "/LDAPPORTS":
                                argLDAPPorts = arguments[entry.index + 1].Split(',');
                                break;

                            case "-LISTENERIP":
                            case "/LISTENERIP":
                                argListenerIP = arguments[entry.index + 1];
                                break;

                            case "-LISTENERIPV6":
                            case "/LISTENERIPV6":
                                argListenerIPv6 = arguments[entry.index + 1];
                                break;

                            case "-LLMNR":
                            case "/LLMNR":
                                argLLMNR = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-LLMNRTTL":
                            case "/LLMNRTTL":
                                argLLMNRTTL = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-LLMNRTYPES":
                            case "/LLMNRTYPES":
                                argLLMNRTypes = arguments[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-LOCAL":
                            case "/LOCAL":
                                argLocal = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-LOGOUTPUT":
                            case "/LOGOUTPUT":
                                argLogOutput = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-MAC":
                            case "/MAC":
                                argMAC = arguments[entry.index + 1].ToUpper().Replace(":", "").Replace("-", "");
                                break;

                            case "-MACHINEACCOUNT":
                            case "/MACHINEACCOUNT":
                                argMachineAccount = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-MDNS":
                            case "/MDNS":
                                argMDNS = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-MDNSQUESTIONS":
                            case "/MDNSQUESTIONS":
                                argMDNSQuestions = arguments[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-MDNSTTL":
                            case "/MDNSTTL":
                                argMDNSTTL = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-MDNSTYPES":
                            case "/MDNSTYPES":
                                argMDNSTypes = arguments[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-MDNSUNICAST":
                            case "/MDNSUNICAST":
                                argMDNSUnicast = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-NBNS":
                            case "/NBNS":
                                argNBNS = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-NBNSTTL":
                            case "/NBNSTTL":
                                argNBNSTTL = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-NBNSTYPES":
                            case "/NBNSTYPES":
                                argNBNSTypes = arguments[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-PROXY":
                            case "/PROXY":
                                argProxy = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-PROXYPORT":
                            case "/PROXYPORT":
                                argProxyPort = arguments[entry.index + 1];
                                break;

                            case "-RUNCOUNT":
                            case "/RUNCOUNT":
                                argRunCount = arguments[entry.index + 1];
                                break;

                            case "-RUNTIME":
                            case "/RUNTIME":
                                argRunTime = arguments[entry.index + 1];
                                break;

                            case "-SMB":
                            case "/SMB":
                                argSMB = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-SMBPORTS":
                            case "/SMBPORTS":
                                argSMBPorts = arguments[entry.index + 1].Split(',');
                                break;

                            case "-SNIFFER":
                            case "/SNIFFER":
                                argSniffer = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-SNIFFERIP":
                            case "/SNIFFERIP":
                                argSnifferIP = arguments[entry.index + 1];
                                break;

                            case "-SNIFFERIPV6":
                            case "/SNIFFERIPV6":
                                argSnifferIPv6 = arguments[entry.index + 1];
                                break;

                            case "-SPOOFERIP":
                            case "/SPOOFERIP":
                                argSpooferIP = arguments[entry.index + 1];
                                break;

                            case "-SPOOFERIPV6":
                            case "/SPOOFERIPV6":
                                argSpooferIPv6 = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-REPEAT":
                            case "/REPEAT":
                                argRepeat = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-REPLYTODOMAINS":
                            case "/REPLYTODOMAINS":
                                argReplyToDomains = arguments[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-REPLYTOIPS":
                            case "/REPLYTOIPS":
                                argReplyToIPs = arguments[entry.index + 1].ToUpper().Split(',');
                                break;                     

                            case "-REPLYTOMACS":
                            case "/REPLYTOMACS":
                                argReplyToMACs = arguments[entry.index + 1].ToUpper().Replace(":", "").Replace("-", "").Split(',');
                                break;

                            case "-REPLYTOQUERIES":
                            case "/REPLYTOQUERIES":
                                argReplyToQueries = arguments[entry.index + 1].ToUpper().Split(',');
                                break;

                            case "-WEBDAV":
                            case "/WEBDAV":
                                argWebDAV = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-WEBDAVAUTH":
                            case "/WEBDAVAUTH":
                                argWebDAVAuth = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-WPADAUTH":
                            case "/WPADAUTH":
                                argWPADAuth = arguments[entry.index + 1].ToUpper();
                                break;

                            case "-WPADRESPONSE":
                            case "/WPADRESPONSE":
                                argWPADResponse = arguments[entry.index + 1];
                                break;

                            case "-?":
                            case "/?":
                                if (arguments.Length > 1)
                                    argHelp = arguments[entry.index + 1].ToUpper();
                                Output.GetHelp(argHelp);
                                allValid &= false;
                                break;

                            default:
                                if (argument.StartsWith("-") || argument.StartsWith("/"))
                                    throw new ArgumentException(paramName: argument, message: "Invalid Parameter");
                                break;
                        }

                    }
                    catch (Exception ex)
                    {

                        if (ex.Message.Contains("Index was outside the bounds of the array"))
                        {
                            Console.WriteLine("{0} is missing a value", argument);
                        }
                        else
                        {
                            Console.WriteLine("{0} error - {1}", argument, ex.Message);
                        }

                        allValid &= false;
                    }

                }

            }

            allValid &= Arguments.ValidateArguments();

            if (allValid)
            {
                Arguments.ParseArguments();
                Control.ImportSession();
                Output.StartupOutput();
                Control.StartThreads();
                commandHistoryList.Add("");

                while (isRunning)
                {

                    try
                    {
                        Output.OutputLoop();

                        if (isRunning)
                        {
                            Shell.ConsoleLoop();
                        }

                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(outputList.Count);
                        outputList.Add(String.Format("[-] [{0}] Console error detected - {1}", Output.Timestamp(), ex.ToString()));
                    }

                }

            }

        }

    }

}