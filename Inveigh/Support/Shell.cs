using Quiddity.Support;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;

namespace Inveigh
{
    class Shell
    {
        internal static int cursorLength;
        internal static StringBuilder builder = new StringBuilder();

        public static void ConsoleLoop()
        {
            int x = Console.CursorLeft;
            int y = Console.CursorTop;
            Program.enabledConsoleOutput = false;
            ConsolePrompt();

            List<string> commandList = new List<string>
            {
                "get console",
                "get dhcpv6leases",
                "get log",
                "get ntlmv1",
                "get ntlmv2",
                "get ntlmv1unique",
                "get ntlmv2unique",
                "get ntlmv1usernames",
                "get ntlmv2usernames",
                "get cleartext",
                "get cleartextunique",
                "history",
                "resume",
                "stop"
            };

            commandList.Sort();
            ConsoleKeyInfo input = Console.ReadKey(intercept: true);
            int i = 0;

            while (input.Key != ConsoleKey.Enter && input.Key != ConsoleKey.Escape)
            {

                if (input.Key == ConsoleKey.Tab)
                {
                    KeypressTab(builder, commandList, ref input);

                    if (input.Key == ConsoleKey.Enter)
                    {

                        if (builder.Length > 0 && builder.ToString().Replace(" ", "").Length > 0 && commandList.Any(item => item.StartsWith(builder.ToString(), true, CultureInfo.InvariantCulture)))
                        {
                            Program.commandHistoryList.Add(builder.ToString());
                        }

                        Program.isCleartextUpdated = false;
                        Program.isNTLMv1Updated = false;
                        Program.isNTLMv2Updated = false;
                        Program.isCleartextUniqueUpdated = false;
                        Program.isNTLMv1UniqueUpdated = false;
                        Program.isNTLMv2UniqueUpdated = false;

                        ClearCurrentLineFull();
                        break;
                    }

                }
                else if (input.Key == ConsoleKey.DownArrow && Program.commandHistoryList.Count > 0)
                {

                    if (i < 0 || i >= Program.commandHistoryList.Count - 1)
                    {
                        i = 0;
                    }

                    if (Program.commandHistoryList.Count > i && string.Equals(Program.commandHistoryList[i], builder.ToString()))
                    {
                        i++;
                    }

                    if (Program.commandHistoryList.Count > i)
                    {
                        ClearCurrentLine();
                        Console.Write(Program.commandHistoryList[i]);
                        builder = new StringBuilder(Program.commandHistoryList[i]);
                        i++;
                    }


                }
                else if (input.Key == ConsoleKey.UpArrow && Program.commandHistoryList.Count > 0)
                {

                    if (i <= 0)
                    {
                        i = Program.commandHistoryList.Count - 1;
                    }


                    if (i > 0 && Program.commandHistoryList.Count > i && string.Equals(Program.commandHistoryList[i], builder.ToString()))
                    {
                        i--;
                    }

                    if (Program.commandHistoryList.Count > i)
                    {
                        ClearCurrentLine();
                        Console.Write(Program.commandHistoryList[i]);
                        builder = new StringBuilder(Program.commandHistoryList[i]);
                        i--;
                    }

                }
                else
                {
                    Keypress(builder, input);
                }

                input = Console.ReadKey(intercept: true);
            }

            if (input.Key == ConsoleKey.Escape)
            {
                Program.isCleartextUpdated = false;
                Program.isNTLMv1Updated = false;
                Program.isNTLMv2Updated = false;
                Program.isCleartextUniqueUpdated = false;
                Program.isNTLMv1UniqueUpdated = false;
                Program.isNTLMv2UniqueUpdated = false;
                ClearCurrentLineFull();
                Program.enabledConsoleOutput = true;
            }

            if (input.Key == ConsoleKey.Enter)
            {

                if (builder.Length > 0 && builder.ToString().Replace(" ", "").Length > 0 && commandList.Any(item => item.StartsWith(builder.ToString(), true, CultureInfo.InvariantCulture)))
                {
                    Program.commandHistoryList.Remove(builder.ToString());
                    Program.commandHistoryList.Add(builder.ToString());
                }

                Program.isCleartextUpdated = false;
                Program.isNTLMv1Updated = false;
                Program.isNTLMv2Updated = false;
                Program.isCleartextUniqueUpdated = false;
                Program.isNTLMv1UniqueUpdated = false;
                Program.isNTLMv2UniqueUpdated = false;
                ClearCurrentLineFull();
            }

            string inputCommand = builder.ToString();
            Commands(inputCommand);
            Thread.Sleep(5);
        }

        public static void ConsolePrompt()
        {
            cursorLength = 26 + Program.cleartextCount.ToString().Length + Program.cleartextUniqueCount.ToString().Length + Program.ntlmv1UniqueCount.ToString().Length + Program.ntlmv2UniqueCount.ToString().Length + Program.ntlmv1Count.ToString().Length + Program.ntlmv2Count.ToString().Length;
            Console.CursorTop = Console.WindowTop + Console.WindowHeight - 1;
            if (Program.isCleartextUniqueUpdated) Console.ForegroundColor = Program.colorPositive;
            Console.Write("C");
            Console.ResetColor();
            Console.Write("(");
            if (Program.isCleartextUniqueUpdated) Console.ForegroundColor = Program.colorPositive;
            Console.Write(Program.cleartextUniqueCount);
            Console.ResetColor();
            Console.Write(":");
            if (Program.isCleartextUpdated) Console.ForegroundColor = Program.colorPositive;
            Console.Write(Program.cleartextCount);
            Console.ResetColor();
            Console.Write(") ");
            if (Program.isNTLMv1UniqueUpdated || Program.isNTLMv1Updated) Console.ForegroundColor = Program.colorPositive;
            Console.Write("NTLMv1");
            Console.ResetColor();
            Console.Write("(");
            if (Program.isNTLMv1UniqueUpdated) Console.ForegroundColor = Program.colorPositive;
            Console.Write(Program.ntlmv1UniqueCount);
            Console.ResetColor();
            Console.Write(":");
            if (Program.isNTLMv1Updated) Console.ForegroundColor = Program.colorPositive;
            Console.Write(Program.ntlmv1Count);
            Console.ResetColor();
            Console.Write(") ");
            if (Program.isNTLMv2UniqueUpdated || Program.isNTLMv2Updated) Console.ForegroundColor = Program.colorPositive;
            Console.Write("NTLMv2");
            Console.ResetColor();
            Console.Write("(");
            if (Program.isNTLMv2UniqueUpdated) Console.ForegroundColor = Program.colorPositive;
            Console.Write(Program.ntlmv2UniqueCount);
            Console.ResetColor();
            Console.Write(":");
            if (Program.isNTLMv2Updated) Console.ForegroundColor = Program.colorPositive;
            Console.Write(Program.ntlmv2Count);
            Console.ResetColor();
            Console.Write(")> ");
        }

        // https://stackoverflow.com/a/8946847/1188513
        public static void ClearCurrentLine()
        {
            cursorLength = 26 + Program.cleartextCount.ToString().Length + Program.cleartextUniqueCount.ToString().Length + Program.ntlmv1UniqueCount.ToString().Length + Program.ntlmv2UniqueCount.ToString().Length + Program.ntlmv1Count.ToString().Length + Program.ntlmv2Count.ToString().Length;
            int currentLine = Console.CursorTop;
            Console.SetCursorPosition(cursorLength, Console.CursorTop);
            Console.Write(new string(' ', Console.WindowWidth - cursorLength - 1));
            Console.SetCursorPosition(cursorLength, currentLine);
        }

        public static void RefreshCurrentLine()
        {
            cursorLength = 26 + Program.cleartextCount.ToString().Length + Program.cleartextUniqueCount.ToString().Length + Program.ntlmv1UniqueCount.ToString().Length + Program.ntlmv2UniqueCount.ToString().Length + Program.ntlmv1Count.ToString().Length + Program.ntlmv2Count.ToString().Length;
            int currentLine = Console.CursorTop;
            Console.SetCursorPosition(0, Console.CursorTop);
            Console.Write(new string(' ', cursorLength));
            Console.SetCursorPosition(0, currentLine);
            ConsolePrompt();
            Console.SetCursorPosition(cursorLength + builder.Length, currentLine);
        }

        public static void ClearCurrentLineFull()
        {
            var currentLine = Console.CursorTop;
            Console.SetCursorPosition(0, Console.CursorTop);
            Console.Write(new string(' ', Console.WindowWidth - 1));
            Console.SetCursorPosition(0, currentLine);
        }

        // https://codereview.stackexchange.com/questions/139172/autocompleting-console-input
        public static void KeypressTab(StringBuilder builder, List<string> data, ref ConsoleKeyInfo input)
        {
            string currentInput = builder.ToString();
            List<string> matches = data.FindAll(item => item != currentInput && item.StartsWith(currentInput, true, CultureInfo.InvariantCulture));

            if (matches.Count == 0)
            {
                return;
            }

            int i = 0;

            while (input.Key == ConsoleKey.Tab)
            {

                if (!string.IsNullOrEmpty(matches[i]))
                {
                    ClearCurrentLine();
                    builder.Length = 0;
                    Console.Write(matches[i]);
                    builder.Append(matches[i]);
                }

                if (i == matches.Count - 1)
                {
                    i = 0;
                }
                else
                {
                    i++;
                }

                if (input.Key != ConsoleKey.Tab)
                {
                    return;
                }

                input = Console.ReadKey(intercept: true);
            }

        }

        public static void Keypress(StringBuilder builder, ConsoleKeyInfo input)
        {
            string currentInput = builder.ToString();
            int cursorLeft = Console.CursorLeft;

            if (input.Key == ConsoleKey.Backspace)
            {

                if (currentInput.Length > 0)
                {
                    if (cursorLeft < cursorLength + builder.Length)
                    {
                        builder.Remove(cursorLeft - cursorLength + 1, 1);
                        currentInput = builder.ToString();
                    }
                    else
                    {
                        builder.Remove(builder.Length - 1, 1);
                        currentInput = builder.ToString();
                    }

                    ClearCurrentLine();
                    Console.Write(currentInput);
                    Console.SetCursorPosition(cursorLeft - 1, Console.CursorTop);
                }

            }
            else if (input.Key == ConsoleKey.LeftArrow)
            {

                if (cursorLeft > cursorLength)
                {
                    Console.SetCursorPosition(cursorLeft - 1, Console.CursorTop);
                }

            }
            else if (input.Key == ConsoleKey.RightArrow)
            {

                if (cursorLeft < cursorLength + builder.Length)
                {
                    Console.SetCursorPosition(cursorLeft + 1, Console.CursorTop);
                }

            }
            else if (input.Key == ConsoleKey.Delete)
            {

                if (currentInput.Length > 0)
                {
                    if (cursorLeft < cursorLength + builder.Length)
                    {
                        builder.Remove(cursorLeft - cursorLength, 1);
                        currentInput = builder.ToString();
                    }

                    ClearCurrentLine();
                    Console.Write(currentInput);
                    Console.SetCursorPosition(cursorLeft, Console.CursorTop);
                }

            }
            else if (input.Key == ConsoleKey.F5)
            {
                RefreshCurrentLine();
            }
            else
            {
                char key = input.KeyChar;

                if (cursorLeft < builder.Length + cursorLength)
                {
                    builder.Insert(Console.CursorLeft - cursorLength, key.ToString(), 1);
                    currentInput = builder.ToString();
                    ClearCurrentLine();
                    Console.Write(currentInput);
                    Console.SetCursorPosition(cursorLeft, Console.CursorTop);
                }
                else
                {
                    builder.Append(key);
                    Console.Write(key);
                }

            }

        }

        public static void Commands(string inputCommand)
        {
            string[] inputArray = inputCommand.Split(' ');
            string search = "";

            if (!Utilities.ArrayIsNullOrEmpty(inputArray) && inputArray.Length == 3)
            {
                inputCommand = string.Concat(inputArray[0], " ", inputArray[1]);
                search = inputArray[2];
            }

            inputCommand = inputCommand.ToUpper();

            switch (inputCommand)
            {

                case "GET CONSOLE":

                    while (Program.consoleList.Count > 0)
                    {
                        Output.ConsoleOutputFormat(Program.consoleList[0]);
                        Program.consoleList.RemoveAt(0);
                    }

                    break;

                case "GET LOG":

                    foreach (string entry in Program.logList)
                    {
                        Output.ConsoleOutputFormat(entry);
                    }

                    break;

                case "GET CLEARTEXT":
                    GetCleartext(search);
                    break;

                case "GET CLEARTEXTUNIQUE":
                    GetCleartextUnique(search);
                    break;

                case "GET DHCPV6LEASES":
                    GetDHCPv6Leases(search);
                    break;

                case "GET NTLMV1":
                    GetNTLMv1(search);
                    break;

                case "GET NTLMV1UNIQUE":
                    GetNTLMv1Unique(search);
                    break;

                case "GET NTLMV1USERNAMES":
                    GetNTLMv1Usernames(search);
                    break;

                case "GET NTLMV2":
                    GetNTLMv2(search);
                    break;

                case "GET NTLMV2UNIQUE":
                    GetNTLMv2Unique(search);
                    break;

                case "GET NTLMV2USERNAMES":
                    GetNTLMv2Usernames(search);
                    break;

                case "GET SPOOFERReplyToHosts":
                    foreach (string entry in Program.argReplyToHosts)
                        Console.WriteLine(entry);
                    break;

                case "GET SPOOFERHOSTSDENY":
                    foreach (string entry in Program.argIgnoreHosts)
                        Console.WriteLine(entry);
                    break;

                case "GET SPOOFERReplyToIPs":
                    foreach (string entry in Program.argReplyToHosts)
                        Console.WriteLine(entry);
                    break;

                case "GET SPOOFERIPSDENY":
                    foreach (string entry in Program.argIgnoreHosts)
                        Console.WriteLine(entry);
                    break;

                case "?":
                case "HELP":
                    GetHelp();
                    break;

                case "RESUME":
                    Program.enabledConsoleOutput = true;
                    break;

                case "HISTORY":
                    {
                        int index = 1;

                        foreach (string item in Program.commandHistoryList)
                        {
                            if (!string.IsNullOrEmpty(item))
                            {
                                Console.WriteLine(index + " " + item);
                                index++;
                            }
                        }
                    }
                    break;

                case "STOP":
                    ClearCurrentLineFull();
                    Program.isRunning = false;
                    Control.StopInveigh();
                    break;

                case "":
                    break;

                default:
                    Console.WriteLine("Invalid Command");
                    break;
            }

            builder = new StringBuilder();
        }

        public static void GreenBar()
        {
            Console.ForegroundColor = Program.colorPositive;
            Console.Write("|");
            Console.ResetColor();
        }

        public static void GetHelp()
        {
            IList<string> commands = new List<string>();
            string description = "Inveigh Console Commands";
            string[] headings = new string[] { "Command", "Description" };
            commands.Add("GET CONSOLE,get queued console output");
            commands.Add("GET DHCPv6Leases,get DHCPv6 assigned IPv6 addresses");
            commands.Add("GET LOG,get log entries; add search string to filter results");
            commands.Add("GET NTLMV1,get captured NTLMv1 hashes; add search string to filter results");
            commands.Add("GET NTLMV2,get captured NTLMv2 hashes; add search string to filter results");
            commands.Add("GET NTLMV1UNIQUE,get one captured NTLMv1 hash per user; add search string to filter results");
            commands.Add("GET NTLMV2UNIQUE,get one captured NTLMv2 hash per user; add search string to filter results");
            commands.Add("GET NTLMV1USERNAMES,get usernames and source IPs/hostnames for captured NTLMv1 hashes");
            commands.Add("GET NTLMV2USERNAMES,get usernames and source IPs/hostnames for captured NTLMv2 hashes");
            commands.Add("GET CLEARTEXT,get captured cleartext credentials");
            commands.Add("GET CLEARTEXTUNIQUE,get unique captured cleartext credentials");
            commands.Add("HISTORY,get console command history");
            commands.Add("RESUME,resume real time console output");
            commands.Add("STOP,stop Inveigh");
            Output.OutputCommand(description, headings, commands, Program.colorPositive);
        }

        public static IList<string> GetUnique(IList<string> list, bool isNTLM)
        {
            IList<string> unique = new List<string>();
            string[] outputUnique = list.ToArray();
            Array.Sort(outputUnique);
            string uniqueLast = "";

            foreach (string entry in outputUnique)
            {
                string item = entry;

                if (isNTLM)
                {
                    item = entry.Substring(0, entry.IndexOf(":", (entry.IndexOf(":") + 2)));
                }

                if (!string.Equals(item, uniqueLast))
                {
                    unique.Add(item);
                }

                uniqueLast = item;
            }

            return unique;
        }

        public static IList<string> GetUniqueNTLM(IList<string> hashList, IList<string> usernameList)
        {
            IList<string> unique = new List<string>();
            IList<string> uniqueCombined = new List<string>();

            foreach (string entry in usernameList)
            {
                string[] split = entry.Split(',');
                string challenge = ":" + split[3];
                unique = GetResults(challenge, hashList);

                if (unique.Count > 0)
                {
                    uniqueCombined.Add(unique[0]);
                }

            }

            return uniqueCombined;
        }

        public static IList<string> GetResults(string search, IList<string> list)
        {
            return list.Where(element => CultureInfo.CurrentCulture.CompareInfo.IndexOf(element, search, CompareOptions.IgnoreCase) >= 0).ToList();
        }

        public static void GetCleartext(string search)
        {
            string description = "Cleartext Credentials";
            string[] headers = new string[] { "IP Address", "Credentials" };
            IList<string> list = Program.cleartextList;

            if (!string.IsNullOrEmpty(search))
            {
                description = string.Concat(description, " (", search, ")");
                list = GetResults(search, list);
            }

            Output.OutputCommand(description, headers, list, Program.colorPositive);
        }

        public static void GetCleartextUnique(string search)
        {
            string description = "Unique Cleartext Credentials";
            string[] headers = new string[] { "IP Address", "Credentials" };
            IList<string> list = GetUnique(Program.cleartextList, false);

            if (!string.IsNullOrEmpty(search))
            {
                description = string.Concat(description, " (", search, ")");
                list = GetResults(search, list);
            }

            Output.OutputCommand(description, headers, list, Program.colorPositive);
        }

        public static void GetDHCPv6Leases(string search)
        {
            string description = "DHCPv6 Leases";
            string[] headers = new string[] { "Host", "MAC", "Lease IP" };
            IList<string> list = Program.dhcpv6List;

            if (!string.IsNullOrEmpty(search))
            {
                description = string.Concat(description, " (", search, ")");
                list = GetResults(search, list);
            }

            Output.OutputCommand(description, headers, list, Program.colorPositive);
        }

        public static void GetNTLMv1(string search)
        {
            string description = "NTLMv1 Hashes";
            string[] headers = new string[] { "Hashes"  };

            IList<string> list = Program.ntlmv1List;

            if (!string.IsNullOrEmpty(search))
            {
                description = string.Concat(description, " (", search, ")");
                list = GetResults(search, list);
            }

            Output.OutputCommand(description, headers, list, Program.colorPositive);
        }

        public static void GetNTLMv1Unique(string search)
        {
            string description = "Unique NTLMv1 Hashes";
            string[] headers = new string[] { "Hashes" };
            IList<string> list = Program.ntlmv1UniqueList;

            if (!string.IsNullOrEmpty(search))
            {
                description = string.Concat(description, " (", search, ")");
                list = GetResults(search, list);
            }

            Output.OutputCommand(description, headers, list, Program.colorPositive);
        }

        public static void GetNTLMv2(string search)
        {
            string description = "NTLMv2 Hashes";
            string[] headers = new string[] { "Hashes" };
            IList<string> list = Program.ntlmv2List;          

            if (!string.IsNullOrEmpty(search))
            {
                description = string.Concat(description, " (", search, ")");
                list = GetResults(search, list);
            }        
            
            Output.OutputCommand(description, headers, list, Program.colorPositive);
        }

        public static void GetNTLMv2Unique(string search)
        {
            string description = "Unique NTLMv2 Hashes";
            string[] headers = new string[] { "Hashes" };
            IList<string> list = Program.ntlmv2UniqueList;

            if (!string.IsNullOrEmpty(search))
            {
                description = string.Concat(description, " (", search, ")");
                list = GetResults(search, list);
            }
            
            Output.OutputCommand(description, headers, list, Program.colorPositive);
        }

        public static void GetNTLMv1Usernames(string search)
        {
            string description = "NTLMv1 Usernames";
            string[] headers = new string[] { "IP Address", "Host", "Username" };
            IList<string> list = Program.ntlmv1UsernameList;

            if (!string.IsNullOrEmpty(search))
            {
                description = string.Concat(description, " (", search, ")");
                list = GetResults(search, list);
            }

            Output.OutputCommand(description, headers, list, Program.colorPositive);
        }

        public static void GetNTLMv2Usernames(string search)
        {
            string description = "NTLMv2 Usernames";
            string[] headers = new string[] { "IP Address", "Host", "Username", "Challenge" };
            IList<string> list = Program.ntlmv2UsernameList;

            if (!string.IsNullOrEmpty(search))
            {
                description = string.Concat(description, " (", search, ")");
                list = GetResults(search, list);
            }

            Output.OutputCommand(description, headers, list, Program.colorPositive);
        }

        public static void GetSpooferReplyLists()
        {

            if (Program.ntlmv2UsernameList.Count > 0)
            {
                Console.WriteLine(string.Format("[+] [{0}] Current NTLMv2 IP addresses, hostnames, and usernames:", Output.Timestamp()));
                string[] outputNTLMV2Usernames = Program.ntlmv2UsernameList.ToArray();
                foreach (string entry in outputNTLMV2Usernames)
                    Console.WriteLine(entry);
            }
            else
            {
                Console.WriteLine(string.Format("[+] [{0}] NTLMv2 IP address, hostname, and username list is empty", Output.Timestamp()));
            }

        }

        public static void GetSpooferIgnoreLists()
        {

            if (Program.ntlmv2UsernameList.Count > 0)
            {
                Console.WriteLine(string.Format("Current NTLMv2 IP addresses, hostnames, and usernames:", Output.Timestamp()));
                string[] outputNTLMV2Usernames = Program.ntlmv2UsernameList.ToArray();
                foreach (string entry in outputNTLMV2Usernames)
                    Console.WriteLine(entry);
            }
            else
            {
                Console.WriteLine(string.Format("[+] [{0}] NTLMv2 IP address, hostname, and username list is empty", Output.Timestamp()));
            }

        }

    }
}
