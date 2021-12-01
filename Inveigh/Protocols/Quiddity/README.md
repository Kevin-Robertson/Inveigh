# Quiddity# Quiddity

Quiddity is a work in progress C# miscellaneous protocol library meant for infosec testing/defense. The library contains classes for packet segment structures, protocol functions, and listeners. This library is currently being developed as part of Inveigh and other, unreleased projects. It's likely to go through major changes.

## Example Usage

### LLMNR Listener

```
LLMNRListener llmnrListener = new LLMNRListener();
llmnrListener.Start(listenerIP, replyIPv4, replyIPv6);
```
### Parse SMB2 Header
```
SMB2Header smb2Header = new SMB2Header(byteArray);
Console.WriteLine(smb2Header.Command); // output SMB2 command type of parsed header
```