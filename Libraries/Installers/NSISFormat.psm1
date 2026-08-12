# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# Format sources: https://github.com/NSIS-Dev/nsis, https://sourceforge.net/projects/nsisbi/, https://github.com/ip7z/7zip, https://github.com/russellbanks/Komac, https://github.com/electron-userland/electron-builder, https://github.com/tauri-apps/tauri/tree/dev/crates/tauri-bundler/src/bundle/windows/nsis, and https://github.com/Drizin/NsisMultiUser
#
# Binary structure consumed by this parser (archive-relative, LE integers):
#
#   PE stub -> 512-byte-aligned archive (aligned to the file start, or to an
#   embedded stub's start when the installer is nested inside another PE)
#     +00 Flags:u32
#     +04 EF BE AD DE + "NullsoftInst"[12]
#     +14 DecompressedHeaderSize:u32
#     +18 ArchiveSize:u32
#     +1C NSISBI DataBlockLength:u64 (variant)
#     +-- non-solid block
#     |   +00 PackedSize:u32 (bit 31 = compressed, low 31 bits = byte count)
#     |   `-- codec stream -> decompressed logical header
#     +-- raw NSIS BZip2 codec stream (MSB-first bit fields)
#     |   +00 BlockMarker:u8 = 31
#     |   +01 OriginalPointer:u24 BE
#     |   +04 Mapping/Huffman/MTF bit stream
#     |   `-- repeated blocks, terminated by byte 17
#     +-- vendor LZMA2 codec stream
#     |   +00 DictionaryProperty:u8 (0..40)
#     |   +01 Control:u8 + chunk sizes + optional LZMA property + chunk data
#     |   `-- repeated chunks terminated by Control=0
#     +-- NSISBI multithread wrapper (MTW), solid stream
#     |   +00 CompressedBlockSize:u24 LE (zero terminates the stream)
#     |   +03 Independent codec stream -> at most 2 MiB decompressed
#     |   `-- repeated records; Unity currently uses LZMA codec streams
#     `-- logical header -> eight block tables -> 28-byte standard or
#         36-byte NSISBI command entries -> payloads
#
# Payload records referenced by EW_EXTRACTFILE:
#
#   non-solid archive (physical file offsets)
#     DataBlockBase = FirstHeaderEnd + PackedHeaderSizeField + PackedHeaderSize
#     DataBlockBase + Entry.DataOffset
#       +00 PackedSize:u32/u64 (top bit = compressed)
#       +04/+08 StoredData[PackedSize without top bit]
#
#   solid archive (offsets in the decompressed codec stream)
#     +00 HeaderSize:u32/u64
#     +04/+08 LogicalHeader[HeaderSize]
#     +-- DataBlock + Entry.DataOffset
#         +00 UnpackedSize:u32/u64
#         +04/+08 FileData[UnpackedSize]
#
# Archive paths are reconstructed from the compiled command stream:
#
#   initial prefix $INSTDIR
#     SetOutPath -> replace/extend prefix through $OUTDIR or saved $_OUTDIR
#     File name  -> prefix relative names; preserve absolute symbolic variables
#     item path  -> remove the leading virtual $INSTDIR\ root only
#
# This produces stable paths such as $PLUGINSDIR\System.dll, bin\tool.exe, and
# $_17_\payload.dll without resolving variables against the parser host.
#
# A packed-size high bit marks a compressed non-solid block; solid archives start
# directly with one codec stream. Opcode numbering is normalized for NSIS 2/3,
# Unicode/Park, log-enabled, and NSISBI layouts before simulation. Explicit
# EW_WRITEREG commands are authoritative; arbitrary strings are not.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

Import-InstallerArchiveDependency

function Import-NSISBZip2Decoder {
  <#
  .SYNOPSIS
    Load the format-specific raw NSIS BZip2 decoder once per process
  .NOTES
    NSIS omits the standard BZh header, block signatures, and CRC fields, so
    SharpCompress's public standard-BZip2 stream cannot decode this framing.
  #>
  if (([System.Management.Automation.PSTypeName]'Dumplings.InstallerParsers.NSIS.NsisBZip2Stream').Type) { return }

  $SourcePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\Assets\Source\NSIS\NsisBZip2Stream.cs'
  $null = Import-InstallerManagedSource -Path $SourcePath -TypeName 'Dumplings.InstallerParsers.NSIS.NsisBZip2Stream'
}

# Constants
$NSIS_FIRST_HEADER_SIZE = 28
$NSISBI_FIRST_HEADER_SIZE = 36
$NSIS_FIRST_HEADER_SIGNATURE = [byte[]](0xEF, 0xBE, 0xAD, 0xDE, 0x4E, 0x75, 0x6C, 0x6C, 0x73, 0x6F, 0x66, 0x74, 0x49, 0x6E, 0x73, 0x74)
$NSIS_FIRST_HEADER_FLAGS_MASK = [uint32]0x0F
$NSISBI_FIRST_HEADER_FLAGS_MASK = [uint32]0x1FF
$NSISBI_FLAG_LONG_DATA_BLOCK_OFFSET = [uint32]0x10
$NSISBI_FLAG_LARGE_FILE_SOURCE = [uint32]0x20
$NSISBI_FLAG_EXTERNAL_FILE_SUPPORT = [uint32]0x40
$NSISBI_FLAG_HAS_EXTERNAL_FILE = [uint32]0x80
$NSISBI_FLAG_IS_STUB_INSTALLER = [uint32]0x100
$NSIS_ARCHIVE_ALIGNMENT = 512
$NSIS_MAX_BACKWARD_PE_SCAN = 1048576
$NSIS_MAX_FILE_SIZE = [uint64]4294967295
$NSIS_MAX_HEADER_SIZE = 134217728
$NSIS_MAX_ENTRY_COUNT = 33554432
$NSIS_MAX_FULL_SIMULATION_ENTRY_COUNT = 65536
$NSIS_MAX_EXTRACTION_FILE_COUNT = 262144
$NSIS_DEFAULT_MAXIMUM_EXPANDED_BYTES = 1073741824
$NSISBI_MTW_BLOCK_HEADER_SIZE = 3
$NSISBI_MTW_BLOCK_DATA_SIZE = 2097152
$NSISBI_MTW_BLOCK_BUFFER_SIZE = 2307891
$NSIS_HEADER_OFFSET_LANG_TABLE_SIZE = 32
$NSIS_HEADER_OFFSET_CODE_ON_INIT = 40
$NSIS_HEADER_OFFSET_CODE_ON_INST_SUCCESS = 44
$NSIS_HEADER_OFFSET_INSTALL_DIRECTORY = 212
$NSIS_HEADER_OFFSET_INSTALL_DIRECTORY_AUTO_APPEND = 216
$NSIS_BLOCK_HEADER_COUNT = 8
$NSIS_BLOCK_HEADER_SIZE_32 = 8
$NSIS_BLOCK_HEADER_SIZE_64 = 12
$NSIS_ENTRY_SIZE = 28
$NSISBI_ENTRY_SIZE = 36
$NSIS_SECTION_OFFSET_NAME = 0
$NSIS_SECTION_OFFSET_CODE = 12
$NSIS_SECTION_OFFSET_CODE_SIZE = 16
$NSIS_DEFAULT_LANGUAGE = 1033
$NSIS_MAX_WATCHDOG_MULTIPLIER = 2
$NSIS_UNINSTALL_KEY_PATTERN = '(?i)^Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\'
$NSIS_UNPACKED_HEADER_SOLID_FLAG = [uint32]2147483648

$NSIS_PREDEFINED_VAR_CMDLINE = 20
$NSIS_PREDEFINED_VAR_INSTDIR = 21
$NSIS_PREDEFINED_VAR_OUTDIR = 22
$NSIS_PREDEFINED_VAR_EXEDIR = 23
$NSIS_PREDEFINED_VAR_LANGUAGE = 24
$NSIS_PREDEFINED_VAR_TEMP = 25
$NSIS_PREDEFINED_VAR_PLUGINSDIR = 26
$NSIS_PREDEFINED_VAR_EXEPATH = 27
$NSIS_PREDEFINED_VAR_EXEFILE = 28
$NSIS_PREDEFINED_VAR_CLICK = 30
$NSIS_PREDEFINED_VAR__OUTDIR = 31

$NSIS_EXEC_FLAG_SHELL_VAR_CONTEXT = 1
$NSIS_EXEC_FLAG_REG_VIEW = 12

$NSIS_REG_ROOT_SHCTX = [uint32]0
$NSIS_REG_ROOT_HKCR = [uint32]2147483648
$NSIS_REG_ROOT_HKCU = [uint32]2147483649
$NSIS_REG_ROOT_HKLM = [uint32]2147483650
$NSIS_REG_ROOT_HKU = [uint32]2147483651
$NSIS_REG_ROOT_HKCC = [uint32]2147483653

$NSIS_REG_TYPE_STRING = 1
$NSIS_REG_TYPE_EXPAND_STRING = 2
$NSIS_REG_TYPE_DWORD = 4

$NSIS_OPCODE_INVALID = 0
$NSIS_OPCODE_RETURN = 1
$NSIS_OPCODE_JUMP = 2
$NSIS_OPCODE_ABORT = 3
$NSIS_OPCODE_QUIT = 4
$NSIS_OPCODE_CALL = 5
$NSIS_OPCODE_CREATE_DIR = 11
$NSIS_OPCODE_IF_FILE_EXISTS = 12
$NSIS_OPCODE_SET_FLAG = 13
$NSIS_OPCODE_IF_FLAG = 14
$NSIS_OPCODE_GET_FLAG = 15
$NSIS_OPCODE_EXTRACT_FILE = 20
$NSIS_OPCODE_STR_LEN = 24
$NSIS_OPCODE_ASSIGN_VAR = 25
$NSIS_OPCODE_STR_CMP = 26
$NSIS_OPCODE_READ_ENV = 27
$NSIS_OPCODE_INT_CMP = 28
$NSIS_OPCODE_INT_OP = 29
$NSIS_OPCODE_INT_FMT = 30
$NSIS_OPCODE_PUSH_POP = 31
$NSIS_OPCODE_SHELL_EXEC = 40
$NSIS_OPCODE_EXECUTE = 41
$NSIS_OPCODE_DELETE_REG = 50
$NSIS_OPCODE_WRITE_REG = 51
$NSIS_OPCODE_READ_REG = 52
$NSIS_OPCODE_WRITE_UNINSTALLER = 62
$NSIS_OPCODE_SECTION_SET = 63
$NSIS_OPCODE_GET_OS_INFO = 65
$NSIS_OPCODE_RESERVED = 66
$NSIS_OPCODE_FILE_WRITE_UTF16 = 68
$NSIS_OPCODE_FILE_READ_UTF16 = 69
$NSIS_OPCODE_LOG = 70
$NSIS_OPCODE_FIND_PROC = 71
$NSIS_OPCODE_GET_FONT_VERSION = 72
$NSIS_OPCODE_GET_FONT_NAME = 73

$NSIS_OPCODE_REGISTER_DLL = 44
$NSIS_OPCODE_FILE_SEEK = 58
$NSIS_COMMAND_PARAMETER_COUNTS = [int[]]@(
  0, 0, 1, 1, 0, 2, 6, 1, 0, 2, 2, 3, 3, 4, 4, 2,
  4, 3, 2, 2, 6, 2, 6, 2, 2, 4, 5, 3, 6, 4, 4, 6,
  5, 6, 3, 3, 2, 4, 5, 4, 6, 3, 3, 4, 6, 6, 4, 1,
  5, 4, 5, 6, 5, 5, 1, 4, 3, 4, 4, 1, 2, 3, 4, 5,
  4, 6, 2, 1, 4, 4, 2, 2, 2, 2
)

# The simulator returns Continue/0 for most opcodes; reuse immutable results
# instead of allocating a new PSCustomObject for every interpreted command.
$NSIS_CONTINUE_RESULT = [pscustomobject]@{ Action = 'Continue'; Address = 0 }
$NSIS_RETURN_RESULT = [pscustomobject]@{ Action = 'Return'; Address = 0 }
$NSIS_ABORT_RESULT = [pscustomobject]@{ Action = 'Abort'; Address = 0 }
$NSIS_QUIT_RESULT = [pscustomobject]@{ Action = 'Quit'; Address = 0 }

$NSIS_POP_OPERATION = 1
$NSIS_GET_OS_INFO_KNOWN_FOLDER = 0
$NSIS_GET_OS_INFO_READ_MEMORY = 1
$NSIS_FOLDER_ID_USER_PROGRAM_FILES = '{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}'
$NSIS_ABI_OS_INFO_OFFSET = 56
$NSIS_TARGET_WINDOWS_MAJOR = 10
$NSIS_TARGET_WINDOWS_MINOR = 0
$NSIS_TARGET_WINDOWS_BUILD = 17763
$NSIS_TARGET_WINDOWS_PRODUCT = 1
$NSIS_TARGET_WINDOWS_SERVICE_PACK = 0

$NSIS_IMAGE_FILE_MACHINE_I386 = 332
$NSIS_IMAGE_FILE_MACHINE_AMD64 = 34404
$NSIS_IMAGE_FILE_MACHINE_ARM64 = 43620

$NSIS_WINDOWS_DIRECTORY = if ($env:windir) { $env:windir } else { 'C:\Windows' }
$NSIS_SYSTEM_DIRECTORY = Join-Path $Script:NSIS_WINDOWS_DIRECTORY 'System32'

# Deterministic shell folder names adapted to the local machine paths used by task scripts.
$NSIS_SHELL_STRINGS = @(
  'Desktop',
  'Internet',
  'Programs',
  'Controls',
  'Printers',
  'Documents',
  'Favorites',
  'Startup',
  'Recent',
  'SendTo',
  'BitBucket',
  'StartMenu',
  $null,
  'Music',
  'Videos',
  $null,
  'Desktop',
  'Drives',
  'Network',
  'NetHood',
  'Fonts',
  'Templates',
  'StartMenu',
  'Programs',
  'Startup',
  'Desktop',
  $env:APPDATA,
  'PrintHood',
  $env:LOCALAPPDATA,
  'ALTStartUp',
  'ALTStartUp',
  'Favorites',
  'InternetCache',
  'Cookies',
  'History',
  $env:APPDATA,
  $Script:NSIS_WINDOWS_DIRECTORY,
  $Script:NSIS_WINDOWS_DIRECTORY,
  $(if (${env:ProgramW6432}) { ${env:ProgramW6432} } else { $env:ProgramFiles }),
  'Pictures',
  $env:USERPROFILE,
  $Script:NSIS_SYSTEM_DIRECTORY,
  $(if (${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} } else { $env:ProgramFiles }),
  $(if (${env:CommonProgramW6432}) { ${env:CommonProgramW6432} } else { $env:CommonProgramFiles }),
  $(if (${env:CommonProgramFiles(x86)}) { ${env:CommonProgramFiles(x86)} } else { $env:CommonProgramFiles }),
  'Templates',
  'Documents',
  'AdminTools',
  'AdminTools',
  'Connections',
  $null,
  $null,
  $null,
  'Music',
  'Pictures',
  'Videos',
  'Resources',
  'ResourcesLocalized',
  'CommonOEMLinks',
  'CDBurnArea',
  $null,
  'ComputersNearMe'
)

# 7-Zip renders compiled variables and shell-folder control codes symbolically
# when constructing archive item paths. Keep a separate table from the metadata
# resolver above so extraction never embeds paths from the parser host.
$NSIS_SYMBOLIC_VARIABLE_NAMES = @(
  'CMDLINE', 'INSTDIR', 'OUTDIR', 'EXEDIR', 'LANGUAGE', 'TEMP',
  'PLUGINSDIR', 'EXEPATH', 'EXEFILE', 'HWNDPARENT', '_CLICK', '_OUTDIR'
)
$NSIS_SYMBOLIC_SHELL_STRINGS = @(
  'DESKTOP', 'INTERNET', 'SMPROGRAMS', 'CONTROLS', 'PRINTERS', 'DOCUMENTS',
  'FAVORITES', 'SMSTARTUP', 'RECENT', 'SENDTO', 'BITBUCKET', 'STARTMENU',
  $null, 'MUSIC', 'VIDEOS', $null, 'DESKTOP', 'DRIVES', 'NETWORK', 'NETHOOD',
  'FONTS', 'TEMPLATES', 'STARTMENU', 'SMPROGRAMS', 'SMSTARTUP', 'DESKTOP',
  'APPDATA', 'PRINTHOOD', 'LOCALAPPDATA', 'ALTSTARTUP', 'ALTSTARTUP',
  'FAVORITES', 'INTERNET_CACHE', 'COOKIES', 'HISTORY', 'APPDATA', 'WINDIR',
  'SYSDIR', 'PROGRAM_FILES', 'PICTURES', 'PROFILE', 'SYSTEMX86',
  'PROGRAM_FILESX86', 'PROGRAM_FILES_COMMON', 'PROGRAM_FILES_COMMONX8',
  'TEMPLATES', 'DOCUMENTS', 'ADMINTOOLS', 'ADMINTOOLS', 'CONNECTIONS',
  $null, $null, $null, 'MUSIC', 'PICTURES', 'VIDEOS', 'RESOURCES',
  'RESOURCES_LOCALIZED', 'COMMON_OEM_LINKS', 'CDBURN_AREA', $null,
  'COMPUTERSNEARME'
)

function Get-PEInfo {
  <#
  .SYNOPSIS
    Read the PE machine type used to interpret the NSIS block headers
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  $Layout = Get-PELayout -Path $Path
  if (-not $Layout) { throw 'The NSIS stub is not a valid PE image.' }
  [pscustomobject]@{
    Machine = $Layout.Machine; Is64Bit = $Layout.OptionalHeaderMagic -eq 0x20B
    IsArm64 = $Layout.Machine -eq 0xAA64; IsAmd64 = $Layout.Machine -eq 0x8664; IsX86 = $Layout.Machine -eq 0x014C
  }
}

function Get-BytePatternOffset {
  <#
  .SYNOPSIS
    Find the first offset of a byte pattern in a byte array
  .PARAMETER Bytes
    The bytes to search
  .PARAMETER Pattern
    The byte pattern to locate
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The bytes to search')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The byte pattern to locate')]
    [byte[]]$Pattern
  )

  $Offset = @(Find-BinaryPattern -Bytes $Bytes -Pattern $Pattern -Maximum 1)
  if ($Offset.Count -eq 0) { return -1 }
  return [int]$Offset[0]
}

function Test-NSISPEHeaderBeforeArchiveStream {
  <#
  .SYNOPSIS
    Validate a nearby PE stub without buffering the installer
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER FirstHeaderOffset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$FirstHeaderOffset
  )

  # Ordinary installers begin with the PE stub at offset zero. Concatenated
  # launchers are handled by a bounded, 512-byte-aligned backward search.
  if (Get-PELayout -Stream $Stream) { return $true }
  $MinimumOffset = [Math]::Max(0L, $FirstHeaderOffset - $Script:NSIS_MAX_BACKWARD_PE_SCAN)
  $StartOffset = $FirstHeaderOffset - ($FirstHeaderOffset % $Script:NSIS_ARCHIVE_ALIGNMENT)
  for ($Offset = $StartOffset; $Offset -ge $MinimumOffset; $Offset -= $Script:NSIS_ARCHIVE_ALIGNMENT) {
    if ($Offset -eq $FirstHeaderOffset -or $Offset + 64 -gt $Stream.Length) { continue }
    $Candidate = New-BoundedReadStream -Stream $Stream -Offset $Offset -Length ($FirstHeaderOffset - $Offset) -LeaveOpen
    try { if (Get-PELayout -Stream $Candidate) { return $true } } catch { } finally { $Candidate.Dispose() }
  }
  return $false
}

function Test-NSISRelativePEStubStream {
  <#
  .SYNOPSIS
    Validate that a non-file-aligned NSIS archive is aligned relative to a nearby PE stub
  .DESCRIPTION
    An installer embedded inside another executable, for example an NSIS
    installer stored as a resource of an outer launcher, keeps its archive
    512-byte aligned relative to its own stub rather than to the file start.
    The stub start therefore shares the candidate's alignment remainder and is
    found by stepping backward from the candidate in whole alignment blocks.
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER FirstHeaderOffset
    Absolute byte offset of the candidate NSIS first header.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$FirstHeaderOffset
  )

  $MinimumOffset = [Math]::Max(0L, $FirstHeaderOffset - $Script:NSIS_MAX_BACKWARD_PE_SCAN)
  for ($Offset = $FirstHeaderOffset - $Script:NSIS_ARCHIVE_ALIGNMENT; $Offset -ge $MinimumOffset; $Offset -= $Script:NSIS_ARCHIVE_ALIGNMENT) {
    if ($Offset + 64 -gt $Stream.Length) { continue }
    $Candidate = New-BoundedReadStream -Stream $Stream -Offset $Offset -Length ($FirstHeaderOffset - $Offset) -LeaveOpen
    try { if (Get-PELayout -Stream $Candidate) { return $true } } catch { } finally { $Candidate.Dispose() }
  }
  return $false
}

function Test-NSISPEHeaderAtOffset {
  <#
  .SYNOPSIS
    Test whether a byte array contains a valid PE header at the requested offset
  .PARAMETER Bytes
    The installer bytes
  .PARAMETER Offset
    The candidate PE offset
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer bytes')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The candidate PE offset')]
    [int]$Offset
  )

  if ($Offset -lt 0 -or $Offset + 0x40 -gt $Bytes.Length) { return $false }
  if ($Bytes[$Offset] -ne 0x4D -or $Bytes[$Offset + 1] -ne 0x5A) { return $false }

  $PEOffset = [int][System.BitConverter]::ToUInt32($Bytes, $Offset + 0x3C)
  if ($PEOffset -lt 0x40 -or $PEOffset -gt 0x1000 -or ($PEOffset -band 7) -ne 0) { return $false }

  $PEAbsoluteOffset = $Offset + $PEOffset
  if ($PEAbsoluteOffset + 24 -gt $Bytes.Length) { return $false }
  if ([System.BitConverter]::ToUInt32($Bytes, $PEAbsoluteOffset) -ne 0x00004550) { return $false }

  $OptionalHeaderSize = [System.BitConverter]::ToUInt16($Bytes, $PEAbsoluteOffset + 20)
  return $OptionalHeaderSize -ge 96
}

function Test-NSISPEHeaderBeforeArchive {
  <#
  .SYNOPSIS
    Validate that an NSIS archive header belongs to a nearby PE stub
  .PARAMETER Bytes
    The installer bytes
  .PARAMETER FirstHeaderOffset
    The candidate NSIS first-header offset
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer bytes')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The candidate NSIS first-header offset')]
    [int]$FirstHeaderOffset
  )

  if (Test-NSISPEHeaderAtOffset -Bytes $Bytes -Offset 0) { return $true }

  $MinimumOffset = [Math]::Max(0, $FirstHeaderOffset - $Script:NSIS_MAX_BACKWARD_PE_SCAN)
  $StartOffset = $FirstHeaderOffset - ($FirstHeaderOffset % $Script:NSIS_ARCHIVE_ALIGNMENT)
  for ($Offset = $StartOffset; $Offset -ge $MinimumOffset; $Offset -= $Script:NSIS_ARCHIVE_ALIGNMENT) {
    if ($Offset -eq $FirstHeaderOffset) { continue }
    if (Test-NSISPEHeaderAtOffset -Bytes $Bytes -Offset $Offset) { return $true }
  }

  return $false
}

function Get-NSISFirstHeaderCandidate {
  <#
  .SYNOPSIS
    Locate a source-compatible NSIS first header by scanning aligned archive starts
  .DESCRIPTION
    Archives are normally 512-byte aligned to the file start. An installer
    embedded inside another executable, such as an NSIS payload stored as a PE
    resource, is instead aligned relative to its own stub and is accepted only
    when a bounded backward search finds that stub.
  .PARAMETER Bytes
    The installer bytes
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Bytes', HelpMessage = 'The installer bytes')][byte[]]$Bytes,
    [Parameter(Mandatory, ParameterSetName = 'Stream', HelpMessage = 'The installer stream')][System.IO.Stream]$Stream
  )

  if ($PSCmdlet.ParameterSetName -eq 'Stream') {
    $SearchStart = 0L
    $SearchWindowSize = 16777216L

    # Search overlapping windows so a NullsoftInst signature crossing a window
    # boundary is seen once, then derive the first-header start four bytes earlier.
    while ($SearchStart -lt $Stream.Length) {
      $SearchLength = [Math]::Min($SearchWindowSize, $Stream.Length - $SearchStart)
      foreach ($SignatureOffset in @(Find-BinaryPattern -Stream $Stream -Pattern $Script:NSIS_FIRST_HEADER_SIGNATURE -StartOffset $SearchStart -Length $SearchLength -Maximum 256)) {
        $Offset = $SignatureOffset - 4
        if ($Offset -lt 0 -or $Offset + $Script:NSIS_FIRST_HEADER_SIZE -gt $Stream.Length) { continue }
        $IsFileAligned = ($Offset % $Script:NSIS_ARCHIVE_ALIGNMENT) -eq 0
        $Header = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count $Script:NSIS_FIRST_HEADER_SIZE
        $Flags = [BitConverter]::ToUInt32($Header, 0)

        # Reject unknown flag bits and impossible declared ranges before testing
        # the more expensive nearby-PE invariant.
        $InvalidFlagMask = [uint32]([uint64]4294967295 - [uint64]$Script:NSISBI_FIRST_HEADER_FLAGS_MASK)
        if (($Flags -band $InvalidFlagMask) -ne 0) { continue }
        $IsNsisBi = ($Flags -band (-bnot $Script:NSIS_FIRST_HEADER_FLAGS_MASK)) -ne 0
        $FirstHeaderSize = if (($Flags -band $Script:NSISBI_FLAG_EXTERNAL_FILE_SUPPORT) -ne 0) { $Script:NSISBI_FIRST_HEADER_SIZE } else { $Script:NSIS_FIRST_HEADER_SIZE }
        if ($Offset + $FirstHeaderSize -gt $Stream.Length) { continue }
        $LengthOfHeader = [BitConverter]::ToUInt32($Header, 20)
        $LengthOfFollowingData = [BitConverter]::ToUInt32($Header, 24)
        if ($LengthOfHeader -le 0 -or $LengthOfHeader -gt $Script:NSIS_MAX_HEADER_SIZE) { continue }
        if ($LengthOfFollowingData -le $FirstHeaderSize -or $LengthOfFollowingData -gt $Stream.Length - $Offset) { continue }
        # A file-aligned archive belongs to the outer PE stub. A non-aligned
        # archive is accepted only when it is aligned relative to an embedded
        # stub found by the bounded backward search, such as an NSIS payload
        # stored as a resource of an outer launcher.
        if ($IsFileAligned) {
          if (-not (Test-NSISPEHeaderBeforeArchiveStream -Stream $Stream -FirstHeaderOffset $Offset)) { continue }
        } else {
          if (-not (Test-NSISRelativePEStubStream -Stream $Stream -FirstHeaderOffset $Offset)) { continue }
        }
        $DataBlockLength = if ($FirstHeaderSize -eq $Script:NSISBI_FIRST_HEADER_SIZE) {
          [BitConverter]::ToUInt64((Read-BinaryBytes -Stream $Stream -Offset ($Offset + 28) -Count 8), 0)
        } else {
          [uint64]0
        }
        return [pscustomobject]@{
          Offset                  = $Offset
          Flags                   = $Flags
          FirstHeaderSize         = $FirstHeaderSize
          IsNsisBi                = $IsNsisBi
          HasLongDataBlockOffsets = ($Flags -band $Script:NSISBI_FLAG_LONG_DATA_BLOCK_OFFSET) -ne 0
          HasLargeFileSource      = ($Flags -band $Script:NSISBI_FLAG_LARGE_FILE_SOURCE) -ne 0
          SupportsExternalFiles   = ($Flags -band $Script:NSISBI_FLAG_EXTERNAL_FILE_SUPPORT) -ne 0
          HasExternalFile         = ($Flags -band $Script:NSISBI_FLAG_HAS_EXTERNAL_FILE) -ne 0
          IsStubInstaller         = ($Flags -band $Script:NSISBI_FLAG_IS_STUB_INSTALLER) -ne 0
          DataBlockLength         = $DataBlockLength
          LengthOfHeader          = $LengthOfHeader
          LengthOfFollowingData   = $LengthOfFollowingData
        }
      }
      if ($SearchLength -eq $Stream.Length - $SearchStart) { break }
      $SearchStart += $SearchLength - ($Script:NSIS_FIRST_HEADER_SIGNATURE.Length - 1)
    }
    return $null
  }

  # The byte-array path is retained for synthetic fixtures and follows the same
  # aligned signature, flag, size, archive-bound, and PE-stub validation order.
  for ($Offset = 0; $Offset + $Script:NSIS_FIRST_HEADER_SIZE -le $Bytes.Length; $Offset += $Script:NSIS_ARCHIVE_ALIGNMENT) {
    $Matched = $true
    for ($Index = 0; $Index -lt $Script:NSIS_FIRST_HEADER_SIGNATURE.Length; $Index++) {
      if ($Bytes[$Offset + 4 + $Index] -ne $Script:NSIS_FIRST_HEADER_SIGNATURE[$Index]) {
        $Matched = $false
        break
      }
    }
    if (-not $Matched) { continue }

    $Flags = [System.BitConverter]::ToUInt32($Bytes, $Offset)
    $InvalidFlagMask = [uint32]([uint64]4294967295 - [uint64]$Script:NSISBI_FIRST_HEADER_FLAGS_MASK)
    if (($Flags -band $InvalidFlagMask) -ne 0) { continue }

    $IsNsisBi = ($Flags -band (-bnot $Script:NSIS_FIRST_HEADER_FLAGS_MASK)) -ne 0
    $FirstHeaderSize = if (($Flags -band $Script:NSISBI_FLAG_EXTERNAL_FILE_SUPPORT) -ne 0) { $Script:NSISBI_FIRST_HEADER_SIZE } else { $Script:NSIS_FIRST_HEADER_SIZE }
    if ($Offset + $FirstHeaderSize -gt $Bytes.Length) { continue }

    $LengthOfHeader = [System.BitConverter]::ToUInt32($Bytes, $Offset + 20)
    $LengthOfFollowingData = [System.BitConverter]::ToUInt32($Bytes, $Offset + 24)
    if ($LengthOfHeader -le 0 -or $LengthOfHeader -gt $Script:NSIS_MAX_HEADER_SIZE) { continue }
    if ($LengthOfFollowingData -le $FirstHeaderSize -or $LengthOfFollowingData -gt $Bytes.Length - $Offset) { continue }
    if (-not (Test-NSISPEHeaderBeforeArchive -Bytes $Bytes -FirstHeaderOffset $Offset)) { continue }

    return [pscustomobject]@{
      Offset                  = $Offset
      Flags                   = $Flags
      FirstHeaderSize         = $FirstHeaderSize
      IsNsisBi                = $IsNsisBi
      HasLongDataBlockOffsets = ($Flags -band $Script:NSISBI_FLAG_LONG_DATA_BLOCK_OFFSET) -ne 0
      HasLargeFileSource      = ($Flags -band $Script:NSISBI_FLAG_LARGE_FILE_SOURCE) -ne 0
      SupportsExternalFiles   = ($Flags -band $Script:NSISBI_FLAG_EXTERNAL_FILE_SUPPORT) -ne 0
      HasExternalFile         = ($Flags -band $Script:NSISBI_FLAG_HAS_EXTERNAL_FILE) -ne 0
      IsStubInstaller         = ($Flags -band $Script:NSISBI_FLAG_IS_STUB_INSTALLER) -ne 0
      DataBlockLength         = if ($FirstHeaderSize -eq $Script:NSISBI_FIRST_HEADER_SIZE) { [BitConverter]::ToUInt64($Bytes, $Offset + 28) } else { [uint64]0 }
      LengthOfHeader          = $LengthOfHeader
      LengthOfFollowingData   = $LengthOfFollowingData
    }
  }

  return $null
}

function Test-NSISLzmaHeader {
  <#
  .SYNOPSIS
    Test whether a byte slice begins with the raw NSIS LZMA header form
  .PARAMETER Bytes
    The candidate header bytes
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate header bytes')]
    [byte[]]$Bytes
  )

  return $Bytes.Length -ge 7 -and $Bytes[0] -eq 0x5D -and $Bytes[1] -eq 0x00 -and $Bytes[2] -eq 0x00 -and $Bytes[5] -eq 0x00 -and (($Bytes[6] -band 0x80) -eq 0)
}

function Get-NSISLzmaFilterLength {
  <#
  .SYNOPSIS
    Get the optional NSIS LZMA filter marker length
  .PARAMETER Bytes
    The candidate header bytes
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate header bytes')]
    [byte[]]$Bytes
  )

  if (Test-NSISLzmaHeader -Bytes $Bytes) { return 0 }
  if ($Bytes.Length -ge 8 -and $Bytes[0] -le 1 -and (Test-NSISLzmaHeader -Bytes $Bytes[1..($Bytes.Length - 1)])) { return 1 }
  return -1
}

function Test-NSISLzma2Header {
  <#
  .SYNOPSIS
    Test whether a compressed NSIS block begins with an LZMA2 property and chunk
  .PARAMETER Bytes
    The candidate bytes beginning with the one-byte LZMA2 dictionary property
  .PARAMETER CompressedSize
    The complete compressed NSIS block size, including the property byte
  .PARAMETER ExpectedUncompressedSize
    The expected decompressed NSIS header size
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate bytes beginning with the one-byte LZMA2 dictionary property')]
    [byte[]]$Bytes,

    [Parameter(HelpMessage = 'The complete compressed NSIS block size, including the property byte')]
    [long]$CompressedSize = -1,

    [Parameter(HelpMessage = 'The expected decompressed NSIS header size')]
    [long]$ExpectedUncompressedSize = -1
  )

  # The LZMA2 SDK accepts dictionary-property values 0 through 40. A property
  # byte is followed by a control byte; 0 ends the stream, 1/2 introduce an
  # uncompressed chunk, and 0x80..0xFF introduce a compressed chunk.
  if ($Bytes.Length -lt 4 -or $Bytes[0] -gt 40) { return $false }
  $Control = $Bytes[1]
  if ($Control -eq 0 -or ($Control -gt 2 -and $Control -lt 0x80)) { return $false }

  if ($Control -le 2) {
    $UnpackedSize = (([int]$Bytes[2] -shl 8) -bor [int]$Bytes[3]) + 1
    $RecordSize = 3L + $UnpackedSize
  } else {
    if ($Bytes.Length -lt 6) { return $false }
    $UnpackedSize = (([int]$Control -band 0x1F) -shl 16) -bor ([int]$Bytes[2] -shl 8) -bor [int]$Bytes[3]
    $UnpackedSize += 1
    $PackedSize = (([int]$Bytes[4] -shl 8) -bor [int]$Bytes[5]) + 1
    $PropertySize = if ($Control -ge 0xC0) { 1 } else { 0 }
    if ($PropertySize -and ($Bytes.Length -lt 7 -or $Bytes[6] -ge (9 * 5 * 5))) { return $false }
    $RecordSize = 5L + $PropertySize + $PackedSize
  }

  # Reject impossible first chunks before constructing a decoder. Multi-chunk
  # streams are allowed, so the first unpacked chunk may be smaller than the
  # complete NSIS header and the first record may leave bytes for later chunks.
  if ($CompressedSize -ge 0 -and (1L + $RecordSize) -gt $CompressedSize) { return $false }
  if ($ExpectedUncompressedSize -ge 0 -and $UnpackedSize -gt $ExpectedUncompressedSize) { return $false }
  return $true
}

function Test-NSISBZip2Header {
  <#
  .SYNOPSIS
    Test whether a byte slice begins with the raw NSIS BZip2 header form
  .PARAMETER Bytes
    The candidate header bytes
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate header bytes')]
    [byte[]]$Bytes
  )

  return $Bytes.Length -ge 2 -and $Bytes[0] -eq 0x31 -and $Bytes[1] -lt 14
}

function Test-NSISZlibHeader {
  <#
  .SYNOPSIS
    Test whether a byte slice begins with a zlib-wrapped DEFLATE header
  .PARAMETER Bytes
    The candidate header bytes
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate header bytes')]
    [byte[]]$Bytes
  )

  if ($Bytes.Length -lt 2) { return $false }
  if (($Bytes[0] -band 0x0F) -ne 8) { return $false }
  if (($Bytes[0] -band 0xF0) -gt 0x70) { return $false }

  $Header = ([int]$Bytes[0] -shl 8) -bor [int]$Bytes[1]
  return ($Header % 31) -eq 0
}

function Get-NSISMtwCompressionCandidate {
  <#
  .SYNOPSIS
    Identify the codec inside an NSISBI multithread-wrapper record
  .PARAMETER Bytes
    Candidate bytes beginning with the three-byte MTW record length
  .PARAMETER CompressedSize
    Available bytes in the enclosing NSIS payload
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [long]$CompressedSize = -1
  )

  if ($Bytes.Length -lt ($Script:NSISBI_MTW_BLOCK_HEADER_SIZE + 2)) { return @() }
  $BlockLength = [int]$Bytes[0] -bor ([int]$Bytes[1] -shl 8) -bor ([int]$Bytes[2] -shl 16)
  if ($BlockLength -le 0 -or $BlockLength -gt $Script:NSISBI_MTW_BLOCK_BUFFER_SIZE) { return @() }
  if ($CompressedSize -ge 0 -and ($Script:NSISBI_MTW_BLOCK_HEADER_SIZE + [long]$BlockLength) -gt $CompressedSize) { return @() }

  # A three-byte integer alone is weak evidence. Require the first wrapped
  # block to expose a source-backed codec signature before classifying MTW.
  $InnerBytes = $Bytes[$Script:NSISBI_MTW_BLOCK_HEADER_SIZE..($Bytes.Length - 1)]
  # NSISBI initializes every MTW LZMA worker with MTW_BLOCK_BUF_SIZE as its
  # dictionary. Unlike ordinary NSIS LZMA, that size is not a power of two.
  if ($InnerBytes.Length -ge 5 -and $InnerBytes[0] -lt (9 * 5 * 5) -and
    [BitConverter]::ToUInt32($InnerBytes, 1) -eq $Script:NSISBI_MTW_BLOCK_BUFFER_SIZE) { return @('Lzma') }
  if (Test-NSISBZip2Header -Bytes $InnerBytes) { return @('BZip2') }
  if (Test-NSISZlibHeader -Bytes $InnerBytes) { return @('Zlib', 'Deflate') }
  return @()
}

function Test-NSISMtwHeader {
  <#
  .SYNOPSIS
    Test whether bytes begin with a structurally supported NSISBI MTW record
  .PARAMETER Bytes
    Candidate bytes beginning with a three-byte MTW record length
  .PARAMETER CompressedSize
    Available bytes in the enclosing NSIS payload
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [long]$CompressedSize = -1
  )

  return (Get-NSISMtwCompressionCandidate -Bytes $Bytes -CompressedSize $CompressedSize).Count -gt 0
}

function Read-NSISMtwBlock {
  <#
  .SYNOPSIS
    Decode one independently compressed NSISBI multithread-wrapper record
  .PARAMETER Stream
    Seekable stream containing only the MTW payload. The caller owns the stream.
  .PARAMETER RecordOffset
    Zero-based offset of the three-byte record header in the MTW stream.
  .PARAMETER Compression
    Codec selected by an earlier record, or null to probe the first record.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$RecordOffset,
    [AllowNull()][string]$Compression
  )

  if (-not $Stream.CanSeek) { throw 'NSISBI MTW decoding requires a seekable bounded stream' }
  if ($RecordOffset + $Script:NSISBI_MTW_BLOCK_HEADER_SIZE -gt $Stream.Length) {
    throw 'The NSISBI MTW block header is truncated'
  }

  $RecordHeader = Read-BinaryBytes -Stream $Stream -Offset $RecordOffset -Count $Script:NSISBI_MTW_BLOCK_HEADER_SIZE
  $CompressedBlockSize = [int]$RecordHeader[0] -bor ([int]$RecordHeader[1] -shl 8) -bor ([int]$RecordHeader[2] -shl 16)
  if ($CompressedBlockSize -eq 0) {
    return [pscustomobject]@{
      Bytes       = [byte[]]::new(0)
      Compression = $Compression
      NextOffset  = $RecordOffset + $Script:NSISBI_MTW_BLOCK_HEADER_SIZE
      IsEnd       = $true
    }
  }
  if ($CompressedBlockSize -gt $Script:NSISBI_MTW_BLOCK_BUFFER_SIZE) { throw 'The NSISBI MTW block exceeds the format limit' }

  $BlockOffset = $RecordOffset + $Script:NSISBI_MTW_BLOCK_HEADER_SIZE
  if ($BlockOffset + $CompressedBlockSize -gt $Stream.Length) { throw 'The NSISBI MTW block data is truncated' }
  $ProbeLength = [int][Math]::Min(24L, [long]$CompressedBlockSize)
  $Probe = Read-BinaryBytes -Stream $Stream -Offset $RecordOffset -Count ($Script:NSISBI_MTW_BLOCK_HEADER_SIZE + $ProbeLength)
  $Candidates = if ([string]::IsNullOrWhiteSpace($Compression)) {
    @(Get-NSISMtwCompressionCandidate -Bytes $Probe -CompressedSize ($Stream.Length - $RecordOffset))
  } else {
    @($Compression)
  }
  if ($Candidates.Count -eq 0) { throw 'The NSISBI MTW block uses an unsupported or unrecognized compression method' }

  $DecodedBlock = $null
  $SelectedCompression = $null
  $LastError = $null
  foreach ($Candidate in $Candidates) {
    $CompressedBlock = New-BoundedReadStream -Stream $Stream -Offset $BlockOffset -Length $CompressedBlockSize -LeaveOpen
    $Decoder = $null
    $BlockOutput = [System.IO.MemoryStream]::new($Script:NSISBI_MTW_BLOCK_DATA_SIZE)
    try {
      $InnerProbe = $Probe[$Script:NSISBI_MTW_BLOCK_HEADER_SIZE..($Probe.Length - 1)]
      $LzmaFilterLength = if ($Candidate -eq 'Lzma') { Get-NSISLzmaFilterLength -Bytes $InnerProbe } else { -1 }
      $Decoder = New-NSISDecoder -Compression $Candidate -PayloadStream $CompressedBlock `
        -LzmaFilterLength $LzmaFilterLength -ExpectedOutputBytes $Script:NSISBI_MTW_BLOCK_DATA_SIZE
      $null = Copy-BoundedStream -Source $Decoder -Destination $BlockOutput -MaximumBytes $Script:NSISBI_MTW_BLOCK_DATA_SIZE
      if ($BlockOutput.Length -eq 0) { throw 'The NSISBI MTW block did not produce output' }
      $DecodedBlock = $BlockOutput.ToArray()
      $SelectedCompression = $Candidate
      break
    } catch {
      $LastError = $_
    } finally {
      if ($Decoder -is [System.IDisposable]) { $Decoder.Dispose() }
      $BlockOutput.Dispose()
      $CompressedBlock.Dispose()
    }
  }
  if (-not $DecodedBlock) { throw "Failed to decode the NSISBI MTW block: $($LastError.Exception.Message)" }

  return [pscustomobject]@{
    Bytes       = $DecodedBlock
    Compression = $SelectedCompression
    NextOffset  = $BlockOffset + $CompressedBlockSize
    IsEnd       = $false
  }
}

function Read-NSISMtwHeaderData {
  <#
  .SYNOPSIS
    Decode the bounded logical-header prefix from an NSISBI MTW stream
  .PARAMETER Stream
    Seekable bounded stream positioned over the MTW payload. The caller owns it;
    this function uses relative random-access reads and leaves it open.
  .PARAMETER ExpectedOutputBytes
    Exact number of decompressed bytes needed for the embedded size and header
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(1, 134217728)][int]$ExpectedOutputBytes
  )

  if (-not $Stream.CanSeek) { throw 'NSISBI MTW decoding requires a seekable bounded stream' }
  $Output = [System.IO.MemoryStream]::new($ExpectedOutputBytes)
  $RecordOffset = 0L
  $SelectedCompression = $null
  $BlockCount = 0
  try {
    while ($Output.Length -lt $ExpectedOutputBytes) {
      $Block = Read-NSISMtwBlock -Stream $Stream -RecordOffset $RecordOffset -Compression $SelectedCompression
      if ($Block.IsEnd) { throw 'The NSISBI MTW stream ended before the logical header was complete' }
      $SelectedCompression = $Block.Compression

      # The final block can contain archive data beyond the logical header. Copy
      # only the requested prefix so the parser never buffers the full payload.
      $Remaining = $ExpectedOutputBytes - [int]$Output.Length
      $Output.Write($Block.Bytes, 0, [Math]::Min($Remaining, $Block.Bytes.Length))
      $RecordOffset = $Block.NextOffset
      $BlockCount++
    }

    return [pscustomobject]@{
      Bytes       = $Output.ToArray()
      Compression = $SelectedCompression
      BlockCount  = $BlockCount
    }
  } finally {
    $Output.Dispose()
  }
}

function New-NSISBcjDecoderStream {
  <#
  .SYNOPSIS
    Wrap an LZMA decoder with the NSIS x86 BCJ post-filter
  .PARAMETER Stream
    The decoded LZMA stream. Ownership transfers to the returned filter stream.
  #>
  [OutputType([System.IO.Stream])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decoded LZMA stream to post-process')]
    [System.IO.Stream]$Stream
  )

  # SharpCompress exposes the filter internally for its XZ implementation. Use
  # the same pinned assembly already required by InstallerParsers rather than
  # copying another branch-conversion implementation into this GPL module.
  $Assembly = [SharpCompress.Archives.IArchive].Assembly
  $FilterType = $Assembly.GetType('SharpCompress.Compressors.Filters.BCJFilter', $true)
  $Constructor = $FilterType.GetConstructor(
    [Reflection.BindingFlags]'Instance,Public,NonPublic',
    $null,
    [type[]]@([bool], [System.IO.Stream]),
    $null
  )
  if (-not $Constructor) { throw 'The bundled SharpCompress assembly does not expose the expected BCJ decoder constructor' }
  return [System.IO.Stream]$Constructor.Invoke([object[]]@($false, $Stream))
}

function Get-NSISCompressionCandidates {
  <#
  .SYNOPSIS
    Get the ordered list of decoder candidates for a compressed NSIS header
  .PARAMETER Bytes
    The candidate compressed header bytes
  .PARAMETER CompressedSize
    The complete compressed NSIS block size
  .PARAMETER ExpectedUncompressedSize
    The expected decompressed NSIS header size
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate compressed header bytes')]
    [byte[]]$Bytes,

    [Parameter(HelpMessage = 'The complete compressed NSIS block size')]
    [long]$CompressedSize = -1,

    [Parameter(HelpMessage = 'The expected decompressed NSIS header size')]
    [long]$ExpectedUncompressedSize = -1
  )

  $LzmaFilterLength = Get-NSISLzmaFilterLength -Bytes $Bytes
  if ($LzmaFilterLength -ge 0) { return @('Lzma') }
  if (Test-NSISBZip2Header -Bytes $Bytes) { return @('BZip2') }

  # Some vendor NSIS stubs use an LZMA2 SDK decoder. Their non-solid block is:
  # packed-size prefix, one dictionary-property byte, then raw LZMA2 records.
  # Keep DEFLATE fallbacks because a short raw stream can coincidentally satisfy
  # the first-record checks; exact decompressed header validation selects it.
  if (Test-NSISLzma2Header -Bytes $Bytes -CompressedSize $CompressedSize -ExpectedUncompressedSize $ExpectedUncompressedSize) {
    return @('Lzma2', 'Deflate', 'Zlib')
  }

  # Recent KDE/Prowise NSIS stubs store the payload as raw DEFLATE without the RFC1950 zlib wrapper.
  if (Test-NSISZlibHeader -Bytes $Bytes) {
    $Candidates = @('Zlib', 'Deflate')
  } else {
    $Candidates = @('Deflate', 'Zlib')
  }
  return $Candidates
}

function New-NSISDecoder {
  <#
  .SYNOPSIS
    Create a decoder stream for a compressed NSIS header payload
  .PARAMETER Compression
    The NSIS compression format
  .PARAMETER PayloadStream
    The compressed header payload stream
  .PARAMETER LzmaFilterLength
    The optional NSIS LZMA filter marker length
  .PARAMETER ExpectedOutputBytes
    The exact decompressed header bytes required by the caller
  #>
  [OutputType([System.IDisposable])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The NSIS compression format')]
    [ValidateSet('None', 'Lzma', 'Lzma2', 'BZip2', 'Zlib', 'Deflate')]
    [string]$Compression,

    [Parameter(Mandatory, HelpMessage = 'The compressed header payload stream')]
    [System.IO.Stream]$PayloadStream,

    [Parameter(HelpMessage = 'The optional NSIS LZMA filter marker length')]
    [int]$LzmaFilterLength = -1,

    [Parameter(HelpMessage = 'The expected decompressed bytes, or -1 when a payload record carries no unpacked-size metadata')]
    [ValidateRange(-1, [long]::MaxValue)]
    [long]$ExpectedOutputBytes = -1
  )

  switch ($Compression) {
    'Lzma' {
      $UseBcjFilter = $false
      if ($LzmaFilterLength -gt 0) {
        $FilterFlag = $PayloadStream.ReadByte()
        if ($FilterFlag -lt 0 -or $FilterFlag -gt 1) { throw 'The NSIS LZMA filter flag is invalid' }
        $UseBcjFilter = $FilterFlag -eq 1
      }
      $Properties = New-Object 'byte[]' 5
      if ($PayloadStream.Read($Properties, 0, $Properties.Length) -ne $Properties.Length) { throw 'The NSIS LZMA properties are truncated' }
      $Decoder = New-InstallerDecompressionStream -Algorithm Lzma -Stream $PayloadStream -Properties $Properties -LeaveOpen
      if ($UseBcjFilter) { return New-NSISBcjDecoderStream -Stream $Decoder }
      return $Decoder
    }
    'Lzma2' {
      $Property = $PayloadStream.ReadByte()
      if ($Property -lt 0 -or $Property -gt 40) { throw 'The NSIS LZMA2 dictionary property is invalid' }
      $RemainingBytes = if ($PayloadStream.CanSeek) { $PayloadStream.Length - $PayloadStream.Position } else { -1 }
      return New-InstallerDecompressionStream -Algorithm Lzma2 -Stream $PayloadStream -Properties ([byte[]]@($Property)) `
        -CompressedSize $RemainingBytes -UncompressedSize $ExpectedOutputBytes -LeaveOpen
    }
    'BZip2' {
      # NSIS uses a reduced BZip2 framing that is incompatible with ordinary
      # BZh streams. Keep the caller-owned bounded payload stream open.
      Import-NSISBZip2Decoder
      return [Dumplings.InstallerParsers.NSIS.NsisBZip2Stream]::Create($PayloadStream, $true)
    }
    'Zlib' { return New-InstallerDecompressionStream -Algorithm Zlib -Stream $PayloadStream -LeaveOpen }
    'Deflate' { return New-InstallerDecompressionStream -Algorithm Deflate -Stream $PayloadStream -LeaveOpen }
    'None' { return $PayloadStream }
    default { throw "Unsupported NSIS compression format: $Compression" }
  }
}

function Get-NSISHeaderData {
  <#
  .SYNOPSIS
    Locate and decompress the NSIS installer header without invoking external tools
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  $InstallerPath = (Get-Item -Path $Path -Force).FullName
  $InstallerItem = Get-Item -LiteralPath $InstallerPath -Force
  if ([uint64]$InstallerItem.Length -gt $Script:NSIS_MAX_FILE_SIZE) { throw 'The NSIS installer exceeds the supported 4 GiB executable size' }
  $InstallerStream = [IO.File]::Open($InstallerPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $FirstHeader = Get-NSISFirstHeaderCandidate -Stream $InstallerStream
    if (-not $FirstHeader) { throw 'The NSIS installer header could not be located at a valid aligned archive start' }

    $FirstHeaderOffset = $FirstHeader.Offset
    $LengthOfHeader = $FirstHeader.LengthOfHeader
    $LengthOfFollowingData = $FirstHeader.LengthOfFollowingData

    $PayloadOffset = $FirstHeaderOffset + $FirstHeader.FirstHeaderSize
    $PayloadLength = [long]$LengthOfFollowingData - $FirstHeader.FirstHeaderSize
    $PackedSizeWidth = if ($FirstHeader.HasLongDataBlockOffsets) { 8 } else { 4 }
    # Keep the comparison in Int64: large NSIS archives can legitimately carry
    # a payload whose declared length is greater than Int32.MaxValue.
    $ProbeLength = [int][Math]::Min(24L, [long]$PayloadLength)
    if ($ProbeLength -lt ($PackedSizeWidth + 8) -or $PayloadOffset + $PayloadLength -gt $InstallerStream.Length) { throw 'The NSIS compressed header is truncated' }
    $Signature = Read-BinaryBytes -Stream $InstallerStream -Offset $PayloadOffset -Count $ProbeLength

    $PackedHeaderSize = if ($PackedSizeWidth -eq 8) {
      [System.BitConverter]::ToUInt64($Signature, 0)
    } else {
      [uint64][System.BitConverter]::ToUInt32($Signature, 0)
    }
    $CompressedSizeMask = if ($PackedSizeWidth -eq 8) { [uint64]0x7FFFFFFFFFFFFFFF } else { [uint64]0x7FFFFFFF }
    $CompressedHeaderSize = $PackedHeaderSize -band $CompressedSizeMask
    $IsSolid = $true
    $CompressionCandidates = @()
    $CandidateHeader = $Signature
    $LzmaFilterLength = Get-NSISLzmaFilterLength -Bytes $Signature
    $IsMtw = Test-NSISMtwHeader -Bytes $Signature -CompressedSize $PayloadLength

    # Distinguish stored non-solid, solid codec streams, and packed-size-prefixed
    # non-solid headers using the exact first bytes consumed by the NSIS stub.
    if ($IsMtw) {
      $CompressionCandidates = @('Mtw')
    } elseif ($PackedHeaderSize -eq $LengthOfHeader) {
      $IsSolid = $false
      $CompressionCandidates = @('None')
    } elseif ($LzmaFilterLength -ge 0) {
      $CompressionCandidates = @('Lzma')
    } elseif (Test-NSISBZip2Header -Bytes $Signature) {
      $CompressionCandidates = @('BZip2')
    } elseif (Test-NSISZlibHeader -Bytes $Signature) {
      $CompressionCandidates = @('Zlib', 'Deflate')
    } elseif ($Signature[$PackedSizeWidth - 1] -eq 0x80) {
      $IsSolid = $false
      if ($CompressedHeaderSize -eq 0 -or $CompressedHeaderSize -gt $PayloadLength - $PackedSizeWidth) { throw 'The NSIS packed header size is outside the archive data range' }
      $CandidateHeader = $Signature[$PackedSizeWidth..($Signature.Length - 1)]
      $CompressionCandidates = Get-NSISCompressionCandidates -Bytes $CandidateHeader -CompressedSize $CompressedHeaderSize -ExpectedUncompressedSize $LengthOfHeader
    } else {
      $CompressionCandidates = Get-NSISCompressionCandidates -Bytes $CandidateHeader -CompressedSize $PayloadLength -ExpectedUncompressedSize ($LengthOfHeader + 4)
    }

    # The solid form starts directly with the codec stream. Non-solid installers prefix it with a 32- or 64-bit packed size.
    $PayloadDataOffset = $PayloadOffset + $(if ($IsSolid) { 0 } else { $PackedSizeWidth })
    $AvailablePayloadDataLength = $PayloadOffset + $PayloadLength - $PayloadDataOffset
    $PayloadDataLength = if (-not $IsSolid) { [long]$CompressedHeaderSize } else { $AvailablePayloadDataLength }
    if ($PayloadDataLength -le 0 -or $PayloadDataLength -gt $AvailablePayloadDataLength) { throw 'The NSIS compressed header data range is invalid' }
    $LastError = $null

    # Ambiguous DEFLATE framing is resolved by bounded decode plus exact header
    # length validation; a codec is accepted only when it produces the full header.
    foreach ($Compression in $CompressionCandidates) {
      $PayloadStream = New-BoundedReadStream -Stream $InstallerStream -Offset $PayloadDataOffset -Length $PayloadDataLength -LeaveOpen
      $LzmaFilterLength = if ($Compression -eq 'Lzma') { Get-NSISLzmaFilterLength -Bytes $CandidateHeader } else { -1 }
      $Decoder = $null

      try {
        $EmbeddedSizeWidth = if ($IsSolid -and $Compression -ne 'None') { $PackedSizeWidth } else { 0 }
        $RequiredOutputBytes = [int]$LengthOfHeader + $EmbeddedSizeWidth
        $EffectiveCompression = $Compression
        $MtwBlockCount = 0
        if ($Compression -eq 'Mtw') {
          $MtwResult = Read-NSISMtwHeaderData -Stream $PayloadStream -ExpectedOutputBytes $RequiredOutputBytes
          $Decoder = [System.IO.MemoryStream]::new($MtwResult.Bytes, $false)
          $EffectiveCompression = "Mtw-$($MtwResult.Compression)"
          $MtwBlockCount = $MtwResult.BlockCount
        } else {
          $Decoder = New-NSISDecoder -Compression $Compression -PayloadStream $PayloadStream -LzmaFilterLength $LzmaFilterLength -ExpectedOutputBytes $RequiredOutputBytes
        }

        if ($IsSolid -and $Compression -ne 'None') {
          $HeaderSizeBytes = New-Object 'byte[]' $PackedSizeWidth
          if ($Decoder.Read($HeaderSizeBytes, 0, $HeaderSizeBytes.Length) -ne $HeaderSizeBytes.Length) { throw 'The NSIS solid header length is truncated' }
          $EmbeddedHeaderLength = if ($PackedSizeWidth -eq 8) {
            [System.BitConverter]::ToUInt64($HeaderSizeBytes, 0)
          } else {
            [uint64][System.BitConverter]::ToUInt32($HeaderSizeBytes, 0)
          }
          if ($EmbeddedHeaderLength -ne $LengthOfHeader) { throw 'The NSIS solid header length does not match the first header' }
        }

        $HeaderBytes = New-Object 'byte[]' ([int]$LengthOfHeader)
        $Read = 0
        while ($Read -lt $HeaderBytes.Length) {
          $ChunkSize = $Decoder.Read($HeaderBytes, $Read, $HeaderBytes.Length - $Read)
          if ($ChunkSize -le 0) { break }
          $Read += $ChunkSize
        }
        if ($Read -ne $HeaderBytes.Length) { throw 'The NSIS header stream is truncated' }

        return [pscustomobject]@{
          Path                    = $InstallerPath
          FirstHeaderOffset       = $FirstHeaderOffset
          FirstHeaderFlags        = $FirstHeader.Flags
          FirstHeaderSize         = $FirstHeader.FirstHeaderSize
          IsNsisBi                = $FirstHeader.IsNsisBi
          HasLongDataBlockOffsets = $FirstHeader.HasLongDataBlockOffsets
          HasLargeFileSource      = $FirstHeader.HasLargeFileSource
          SupportsExternalFiles   = $FirstHeader.SupportsExternalFiles
          HasExternalFile         = $FirstHeader.HasExternalFile
          IsStubInstaller         = $FirstHeader.IsStubInstaller
          DataBlockLength         = $FirstHeader.DataBlockLength
          ArchiveSize             = $LengthOfFollowingData
          HeaderSize              = $LengthOfHeader
          PayloadOffset           = $PayloadOffset
          PayloadLength           = $PayloadLength
          PayloadDataOffset       = $PayloadDataOffset
          PayloadDataLength       = $PayloadDataLength
          PackedSizeWidth         = $PackedSizeWidth
          CompressedHeaderSize    = $CompressedHeaderSize
          Compression             = $EffectiveCompression
          MtwBlockCount           = $MtwBlockCount
          IsSolid                 = $IsSolid
          HeaderBytes             = $HeaderBytes
          PEInfo                  = Get-PEInfo -Path $InstallerPath
        }
      } catch {
        $LastError = $_
      } finally {
        if ($Decoder -is [System.IDisposable]) { $Decoder.Dispose() }
        $PayloadStream.Dispose()
      }
    }

    throw "Failed to decode the NSIS header using $($CompressionCandidates -join ', '): $($LastError.Exception.Message)"
  } finally {
    $InstallerStream.Dispose()
  }
}

function Get-NSISBlockHeaders {
  <#
  .SYNOPSIS
    Read the NSIS block table from the decompressed header
  .PARAMETER HeaderBytes
    The decompressed NSIS header bytes
  .PARAMETER Is64Bit
    Whether the PE stub uses 64-bit NSIS block offsets
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header bytes')]
    [byte[]]$HeaderBytes,

    [Parameter(Mandatory, HelpMessage = 'Whether the PE stub uses 64-bit NSIS block offsets')]
    [bool]$Is64Bit
  )

  # The common flags word is stored before the block table in the decompressed header stream.
  $Offset = 4
  $BlockHeaders = [System.Collections.Generic.List[object]]::new()

  for ($Index = 0; $Index -lt $Script:NSIS_BLOCK_HEADER_COUNT; $Index++) {
    $BlockOffset = if ($Is64Bit) {
      [System.BitConverter]::ToUInt64($HeaderBytes, $Offset)
    } else {
      [uint64][System.BitConverter]::ToUInt32($HeaderBytes, $Offset)
    }

    $CountOffset = if ($Is64Bit) { $Offset + 8 } else { $Offset + 4 }
    $BlockCount = [System.BitConverter]::ToUInt32($HeaderBytes, $CountOffset)

    $BlockHeaders.Add([pscustomobject]@{
        Index  = $Index
        Offset = $BlockOffset
        Count  = $BlockCount
      })

    $Offset += if ($Is64Bit) { $Script:NSIS_BLOCK_HEADER_SIZE_64 } else { $Script:NSIS_BLOCK_HEADER_SIZE_32 }
  }

  return $BlockHeaders.ToArray()
}

function Get-NSISHeaderLayout {
  <#
  .SYNOPSIS
    Get the important NSIS header pointers that drive static metadata parsing
  .PARAMETER HeaderBytes
    The decompressed NSIS header bytes
  .PARAMETER Is64Bit
    Whether the PE stub uses 64-bit NSIS block offsets
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header bytes')]
    [byte[]]$HeaderBytes,

    [Parameter(Mandatory, HelpMessage = 'Whether the PE stub uses 64-bit NSIS block offsets')]
    [bool]$Is64Bit
  )

  $BlockHeaderSize = if ($Is64Bit) { $Script:NSIS_BLOCK_HEADER_SIZE_64 } else { $Script:NSIS_BLOCK_HEADER_SIZE_32 }
  $HeaderOffset = 4 + ($BlockHeaderSize * $Script:NSIS_BLOCK_HEADER_COUNT)

  return [pscustomobject]@{
    HeaderOffset               = $HeaderOffset
    LanguageTableSize          = [System.BitConverter]::ToInt32($HeaderBytes, $HeaderOffset + $Script:NSIS_HEADER_OFFSET_LANG_TABLE_SIZE)
    CodeOnInit                 = [System.BitConverter]::ToInt32($HeaderBytes, $HeaderOffset + $Script:NSIS_HEADER_OFFSET_CODE_ON_INIT)
    CodeOnInstSuccess          = [System.BitConverter]::ToInt32($HeaderBytes, $HeaderOffset + $Script:NSIS_HEADER_OFFSET_CODE_ON_INST_SUCCESS)
    InstallDirectoryPointer    = [System.BitConverter]::ToInt32($HeaderBytes, $HeaderOffset + $Script:NSIS_HEADER_OFFSET_INSTALL_DIRECTORY)
    InstallDirectoryAutoAppend = [System.BitConverter]::ToInt32($HeaderBytes, $HeaderOffset + $Script:NSIS_HEADER_OFFSET_INSTALL_DIRECTORY_AUTO_APPEND)
  }
}

function Get-NSISBlockBytes {
  <#
  .SYNOPSIS
    Slice a named NSIS block from the decompressed header
  .PARAMETER HeaderBytes
    The decompressed NSIS header bytes
  .PARAMETER BlockHeaders
    The parsed NSIS block headers
  .PARAMETER Index
    The block index
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header bytes')]
    [byte[]]$HeaderBytes,

    [Parameter(Mandatory, HelpMessage = 'The parsed NSIS block headers')]
    [pscustomobject[]]$BlockHeaders,

    [Parameter(Mandatory, HelpMessage = 'The block index')]
    [int]$Index
  )

  $Start = [int]$BlockHeaders[$Index].Offset
  if ($Start -lt 0 -or $Start -gt $HeaderBytes.Length) { return , ([byte[]]::new(0)) }

  $End = $HeaderBytes.Length
  foreach ($BlockHeader in $BlockHeaders | Select-Object -Skip ($Index + 1)) {
    if ($BlockHeader.Offset -gt 0) {
      $End = [int]$BlockHeader.Offset
      break
    }
  }

  if ($End -le $Start) { return , ([byte[]]::new(0)) }

  $Length = $End - $Start
  $BlockBytes = [byte[]]::new($Length)

  # PowerShell array slicing widens byte[] to object[], which makes downstream BitConverter reads extremely slow.
  [System.Buffer]::BlockCopy($HeaderBytes, $Start, $BlockBytes, 0, $Length)
  return , $BlockBytes
}

function Get-NSISLanguageTable {
  <#
  .SYNOPSIS
    Read every compiled NSIS language table used for localized string resolution
  .PARAMETER HeaderBytes
    The decompressed NSIS header bytes
  .PARAMETER BlockHeaders
    The parsed NSIS block headers
  .PARAMETER Layout
    The parsed NSIS header layout
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header bytes')]
    [byte[]]$HeaderBytes,

    [Parameter(Mandatory, HelpMessage = 'The parsed NSIS block headers')]
    [pscustomobject[]]$BlockHeaders,

    [Parameter(Mandatory, HelpMessage = 'The parsed NSIS header layout')]
    [pscustomobject]$Layout
  )

  # Block 4 is an array of fixed-size language records. Its layout-derived width
  # prevents string offsets from one record spilling into the next.
  $LanguageTableBytes = Get-NSISBlockBytes -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Index 4
  if ($LanguageTableBytes.Length -eq 0 -or $Layout.LanguageTableSize -le 0) { return $null }

  $CandidateTables = [System.Collections.Generic.List[object]]::new()
  for ($Offset = 0; $Offset + $Layout.LanguageTableSize -le $LanguageTableBytes.Length; $Offset += $Layout.LanguageTableSize) {
    $LanguageId = [System.BitConverter]::ToUInt16($LanguageTableBytes, $Offset)
    $StringOffsets = [System.Collections.Generic.List[int]]::new()

    for ($StringOffset = $Offset + 10; $StringOffset + 4 -le $Offset + $Layout.LanguageTableSize; $StringOffset += 4) {
      $StringOffsets.Add([System.BitConverter]::ToInt32($LanguageTableBytes, $StringOffset))
    }

    $CandidateTables.Add([pscustomobject]@{
        LanguageId    = $LanguageId
        DialogOffset  = [System.BitConverter]::ToUInt32($LanguageTableBytes, $Offset + 2)
        RightToLeft   = [System.BitConverter]::ToUInt32($LanguageTableBytes, $Offset + 6) -ne 0
        StringOffsets = $StringOffsets.ToArray()
      })
  }

  return $CandidateTables.ToArray()
}

function ConvertFrom-NSISBiOpcode {
  <#
  .SYNOPSIS
    Normalize NSISBI opcodes that follow its two external-file commands
  .PARAMETER Opcode
    The raw NSISBI command opcode
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The raw NSISBI command opcode')]
    [uint32]$Opcode
  )

  if ($Opcode -le $Script:NSIS_OPCODE_EXTRACT_FILE) { return [int]$Opcode }
  if ($Opcode -le ($Script:NSIS_OPCODE_EXTRACT_FILE + 2)) { return [int]::MaxValue }
  return [int]$Opcode - 2
}

function Get-NSISVersionInfo {
  <#
  .SYNOPSIS
    Detect the NSIS string and command layout used by a compiled installer
  .PARAMETER StringsBlock
    The decompressed NSIS strings block
  .PARAMETER Entries
    The raw NSIS command entries
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS strings block')]
    [byte[]]$StringsBlock,

    [Parameter(HelpMessage = 'The raw NSIS command entries')]
    [pscustomobject[]]$Entries = @(),

    [Parameter(HelpMessage = 'Whether the command records use the NSISBI layout')]
    [bool]$IsNsisBi = $false
  )

  # NSIS encodes variable/language escape opcodes differently across ANSI,
  # Unicode, NSIS 2/3, and Park forks. Count only escape codes after NUL string
  # boundaries so ordinary payload bytes do not influence generation detection.
  $Unicode = $StringsBlock.Length -ge 2 -and $StringsBlock[0] -eq 0x00 -and $StringsBlock[1] -eq 0x00
  $NSIS2Count = 0
  $NSIS3Count = 0
  $ParkCount = 0
  $StrongNSIS3 = $false

  if ($Unicode) {
    for ($Index = 2; $Index + 3 -lt $StringsBlock.Length; $Index += 2) {
      if ($StringsBlock[$Index] -eq 0x00) {
        $Code = [System.BitConverter]::ToUInt16($StringsBlock, $Index + 2)
        switch ($Code) {
          1 { $NSIS3Count++ }
          2 { $NSIS3Count++ }
          3 {
            $NSIS3Count++
            if ($Index + 5 -lt $StringsBlock.Length -and (([System.BitConverter]::ToUInt16($StringsBlock, $Index + 4) -band 0x8080) -eq 0x8080)) {
              $StrongNSIS3 = $true
            }
          }
          4 { $NSIS3Count++ }
          252 { $NSIS2Count++ }
          253 { $NSIS2Count++ }
          254 { $NSIS2Count++ }
          255 { $NSIS2Count++ }
          0xE000 { $ParkCount++ }
          0xE001 { $ParkCount++ }
          0xE002 { $ParkCount++ }
          0xE003 { $ParkCount++ }
        }
      }
    }
  } else {
    for ($Index = 0; $Index + 1 -lt $StringsBlock.Length; $Index++) {
      if ($StringsBlock[$Index] -eq 0x00) {
        switch ($StringsBlock[$Index + 1]) {
          1 { $NSIS3Count++ }
          2 { $NSIS3Count++ }
          3 {
            $NSIS3Count++
            if ($Index + 2 -lt $StringsBlock.Length -and (($StringsBlock[$Index + 2] -band 0x80) -ne 0)) {
              $StrongNSIS3 = $true
            }
          }
          4 { $NSIS3Count++ }
          252 { $NSIS2Count++ }
          253 { $NSIS2Count++ }
          254 { $NSIS2Count++ }
          255 { $NSIS2Count++ }
        }
      }
    }
  }

  # Strong escape evidence constrains candidates; ambiguous blocks retain a
  # deterministic fallback order that is scored against actual commands below.
  $StrongPark = $Unicode -and -not $StrongNSIS3 -and ($ParkCount -gt 0 -or $NSIS3Count -eq 0)
  $CandidateTypes = if ($StrongNSIS3) {
    @('NSIS3')
  } elseif ($StrongPark) {
    @('Park1', 'Park2', 'Park3')
  } elseif ($NSIS3Count -gt $NSIS2Count) {
    @('NSIS3', 'NSIS2')
  } else {
    @('NSIS2', 'NSIS3')
  }

  $Candidates = [System.Collections.Generic.List[object]]::new()
  $Priority = 0
  foreach ($Type in $CandidateTypes) {
    foreach ($LogCmdIsEnabled in @($false, $true)) {
      $Candidates.Add([pscustomobject]@{
          Type            = $Type
          LogCmdIsEnabled = $LogCmdIsEnabled
          Priority        = $Priority
        })
      $Priority++
    }
  }

  # Log-enabled builds insert command-layout slots. Select the variant producing
  # the fewest impossible opcodes instead of assuming the upstream default.
  $BestCandidate = $Candidates[0]
  if ($Entries.Count -gt 0) {
    $BestCandidate = @($Candidates | ForEach-Object {
        [pscustomobject]@{
          Type            = $_.Type
          LogCmdIsEnabled = $_.LogCmdIsEnabled
          Priority        = $_.Priority
          BadCommandCount = Measure-NSISCommandLayoutCandidate -Entries $Entries -Type $_.Type -Unicode $Unicode -LogCmdIsEnabled $_.LogCmdIsEnabled
        }
      } | Sort-Object -Property BadCommandCount, Priority | Select-Object -First 1)[0]
  } else {
    $BestCandidate | Add-Member -NotePropertyName BadCommandCount -NotePropertyValue 0 -Force
  }

  return [pscustomobject]@{
    Unicode          = $Unicode
    Type             = $BestCandidate.Type
    IsV3             = $BestCandidate.Type -eq 'NSIS3'
    IsPark           = $BestCandidate.Type -like 'Park*'
    IsNsisBi         = $IsNsisBi
    LogCmdIsEnabled  = [bool]$BestCandidate.LogCmdIsEnabled
    BadCommandCount  = [int]$BestCandidate.BadCommandCount
    StringCodeCounts = [pscustomobject]@{
      NSIS2 = $NSIS2Count
      NSIS3 = $NSIS3Count
      Park  = $ParkCount
    }
  }
}

function Get-NSISNormalizedOpcode {
  <#
  .SYNOPSIS
    Normalize a raw compiled opcode to the NSIS 3 command layout used by the simulator
  .PARAMETER Opcode
    The raw command opcode
  .PARAMETER Type
    The detected NSIS command layout type
  .PARAMETER Unicode
    Whether the installer stores Unicode strings
  .PARAMETER LogCmdIsEnabled
    Whether a log opcode was inserted before section commands
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The raw command opcode')]
    [uint32]$Opcode,

    [Parameter(Mandatory, HelpMessage = 'The detected NSIS command layout type')]
    [string]$Type,

    [Parameter(Mandatory, HelpMessage = 'Whether the installer stores Unicode strings')]
    [bool]$Unicode,

    [Parameter(Mandatory, HelpMessage = 'Whether a log opcode was inserted before section commands')]
    [bool]$LogCmdIsEnabled
  )

  $Value = [int]$Opcode

  # Official NSIS layouts either insert LOG before section commands or, in Park
  # variants, insert additional opcodes that shift later command numbers.
  if ($Type -notlike 'Park*') {
    if (-not $LogCmdIsEnabled) { return $Value }
    if ($Value -lt $Script:NSIS_OPCODE_SECTION_SET) { return $Value }
    if ($Value -eq $Script:NSIS_OPCODE_SECTION_SET) { return $Script:NSIS_OPCODE_LOG }
    return $Value - 1
  }

  if ($Value -lt $Script:NSIS_OPCODE_REGISTER_DLL) { return $Value }
  if ($Type -in @('Park2', 'Park3')) {
    if ($Value -eq $Script:NSIS_OPCODE_REGISTER_DLL) { return $Script:NSIS_OPCODE_GET_FONT_VERSION }
    $Value--
  }
  if ($Type -eq 'Park3') {
    if ($Value -eq $Script:NSIS_OPCODE_REGISTER_DLL) { return $Script:NSIS_OPCODE_GET_FONT_NAME }
    $Value--
  }
  if ($Value -ge $Script:NSIS_OPCODE_FILE_SEEK) {
    if ($Unicode) {
      if ($Value -eq $Script:NSIS_OPCODE_FILE_SEEK) { return $Script:NSIS_OPCODE_FILE_WRITE_UTF16 }
      if ($Value -eq ($Script:NSIS_OPCODE_FILE_SEEK + 1)) { return $Script:NSIS_OPCODE_FILE_READ_UTF16 }
      $Value -= 2
    }

    if ($Value -ge $Script:NSIS_OPCODE_SECTION_SET -and $LogCmdIsEnabled) {
      if ($Value -eq $Script:NSIS_OPCODE_SECTION_SET) { return $Script:NSIS_OPCODE_LOG }
      return $Value - 1
    }
    if ($Value -eq $Script:NSIS_OPCODE_FILE_WRITE_UTF16) { return $Script:NSIS_OPCODE_FIND_PROC }
  }

  return $Value
}

function Measure-NSISCommandLayoutCandidate {
  <#
  .SYNOPSIS
    Score a candidate NSIS command layout by counting impossible commands
  .PARAMETER Entries
    The raw NSIS command entries
  .PARAMETER Type
    The candidate NSIS command layout type
  .PARAMETER Unicode
    Whether the installer stores Unicode strings
  .PARAMETER LogCmdIsEnabled
    Whether a log opcode was inserted before section commands
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The raw NSIS command entries')]
    [pscustomobject[]]$Entries,

    [Parameter(Mandatory, HelpMessage = 'The candidate NSIS command layout type')]
    [string]$Type,

    [Parameter(Mandatory, HelpMessage = 'Whether the installer stores Unicode strings')]
    [bool]$Unicode,

    [Parameter(Mandatory, HelpMessage = 'Whether a log opcode was inserted before section commands')]
    [bool]$LogCmdIsEnabled
  )

  $BadCommandCount = 0

  # Score a layout by impossible opcode values and nonzero parameters beyond the
  # source-defined arity. The lowest score selects the command normalization.
  foreach ($Entry in $Entries) {
    $Opcode = Get-NSISNormalizedOpcode -Opcode $Entry.LayoutOpcode -Type $Type -Unicode $Unicode -LogCmdIsEnabled $LogCmdIsEnabled
    if ($Opcode -lt 0 -or $Opcode -ge $Script:NSIS_COMMAND_PARAMETER_COUNTS.Count) {
      $BadCommandCount++
      continue
    }

    if ($Type -eq 'NSIS3') {
      if ($Opcode -eq $Script:NSIS_OPCODE_RESERVED) {
        $BadCommandCount++
        continue
      }
    } elseif ($Opcode -eq $Script:NSIS_OPCODE_RESERVED -or $Opcode -eq $Script:NSIS_OPCODE_GET_OS_INFO) {
      $BadCommandCount++
      continue
    }

    $LastNonZeroParameter = 0
    for ($Index = 6; $Index -ge 1; $Index--) {
      if ($Entry.Raw[$Index] -ne 0) {
        $LastNonZeroParameter = $Index
        break
      }
    }
    if ($Script:NSIS_COMMAND_PARAMETER_COUNTS[$Opcode] -lt $LastNonZeroParameter) {
      $BadCommandCount++
    }
  }

  return $BadCommandCount
}

function ConvertTo-NSISExtractionRelativePath {
  <#
  .SYNOPSIS
    Project a compiled NSIS output name into a safe extraction-relative path
  .PARAMETER Path
    The filename resolved from the EW_EXTRACTFILE string operand.
  .PARAMETER DataOffset
    Data-block offset used to create a deterministic fallback name.
  #>
  [OutputType([string])]
  param (
    [AllowEmptyString()]
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][uint64]$DataOffset
  )

  $Candidate = $Path.Trim().Trim('"').Replace('/', '\')
  if ([string]::IsNullOrWhiteSpace($Candidate)) { return ('payload-{0:X}.bin' -f $DataOffset) }

  # Absolute install paths and expanded shell variables must never recreate host
  # directory trees under the extraction root. Their leaf still identifies the
  # payload deterministically for static analysis.
  if ([IO.Path]::IsPathRooted($Candidate) -or $Candidate -match '^[A-Za-z]:') {
    $Candidate = [IO.Path]::GetFileName($Candidate.TrimEnd('\'))
  }

  $InvalidCharacters = [System.Collections.Generic.HashSet[char]]::new([IO.Path]::GetInvalidFileNameChars())
  $Segments = [System.Collections.Generic.List[string]]::new()
  foreach ($RawSegment in $Candidate.Split('\', [StringSplitOptions]::RemoveEmptyEntries)) {
    if ($RawSegment -eq '.') { continue }
    if ($RawSegment -eq '..') { $RawSegment = '_' }
    $Builder = [Text.StringBuilder]::new($RawSegment.Length)
    foreach ($Character in $RawSegment.ToCharArray()) {
      $null = $Builder.Append($(if ($InvalidCharacters.Contains($Character)) { '_' } else { $Character }))
    }
    $Segment = $Builder.ToString().TrimEnd(' ', '.')
    if ([string]::IsNullOrWhiteSpace($Segment)) { $Segment = '_' }
    if ($Segment -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$') { $Segment = "_$Segment" }
    $Segments.Add($Segment)
  }

  if ($Segments.Count -eq 0) { return ('payload-{0:X}.bin' -f $DataOffset) }
  return [string]::Join([IO.Path]::DirectorySeparatorChar, $Segments)
}

function Join-NSISArchivePath {
  <#
  .SYNOPSIS
    Join two symbolic NSIS path fragments without consulting host path semantics
  .PARAMETER Prefix
    Current compiled SetOutPath prefix.
  .PARAMETER Path
    Relative compiled File operand or SetOutPath suffix.
  #>
  [OutputType([string])]
  param (
    [AllowEmptyString()][Parameter(Mandatory)][string]$Prefix,
    [AllowEmptyString()][Parameter(Mandatory)][string]$Path
  )

  $Left = $Prefix.Replace('/', '\').TrimEnd('\')
  $Right = $Path.Replace('/', '\').TrimStart('\')
  if ([string]::IsNullOrEmpty($Left)) { return $Right }
  if ([string]::IsNullOrEmpty($Right)) { return $Left }
  return $Left + '\' + $Right
}

function Test-NSISAbsoluteArchivePath {
  <#
  .SYNOPSIS
    Test whether a compiled File operand bypasses the active SetOutPath prefix
  .PARAMETER Path
    Symbolically decoded compiled File operand.
  #>
  [OutputType([bool])]
  param (
    [AllowEmptyString()][Parameter(Mandatory)][string]$Path
  )

  # 7-Zip treats these four predefined variables as absolute path sources. Shell
  # folder controls are not included here because they can also establish the
  # active SetOutPath and must follow the compiled command sequence.
  return $Path -match '^(?i:\$(?:INSTDIR|EXEDIR|TEMP|PLUGINSDIR))(?=\\|$)' -or
  $Path -match '^[A-Za-z]:' -or $Path.StartsWith('\\')
}

function Resolve-NSISArchiveOutputPrefix {
  <#
  .SYNOPSIS
    Resolve a symbolic SetOutPath operand against current and saved output paths
  .PARAMETER Path
    Symbolically decoded SetOutPath operand.
  .PARAMETER CurrentPrefix
    Output prefix active before this command.
  .PARAMETER SavedPrefix
    Prefix saved by the compiler-private _OUTDIR variable.
  #>
  [OutputType([string])]
  param (
    [AllowEmptyString()][Parameter(Mandatory)][string]$Path,
    [AllowEmptyString()][Parameter(Mandatory)][string]$CurrentPrefix,
    [AllowEmptyString()][Parameter(Mandatory)][string]$SavedPrefix
  )

  $Candidate = $Path.Replace('/', '\')
  foreach ($Variable in @(
      [pscustomobject]@{ Name = '$_OUTDIR'; Value = $SavedPrefix },
      [pscustomobject]@{ Name = '$OUTDIR'; Value = $CurrentPrefix }
    )) {
    if ($Candidate.Equals($Variable.Name, [StringComparison]::OrdinalIgnoreCase)) { return $Variable.Value }
    if ($Candidate.StartsWith($Variable.Name + '\', [StringComparison]::OrdinalIgnoreCase)) {
      return Join-NSISArchivePath -Prefix $Variable.Value -Path $Candidate.Substring($Variable.Name.Length + 1)
    }
  }
  return $Candidate
}

function Get-NSISReducedArchivePath {
  <#
  .SYNOPSIS
    Combine a File operand with SetOutPath and remove 7-Zip's virtual $INSTDIR root
  .PARAMETER SourcePath
    Symbolically decoded EW_EXTRACTFILE filename operand.
  .PARAMETER OutputPrefix
    Active symbolic output prefix at the command position.
  #>
  [OutputType([string])]
  param (
    [AllowEmptyString()][Parameter(Mandatory)][string]$SourcePath,
    [AllowEmptyString()][Parameter(Mandatory)][string]$OutputPrefix
  )

  $Path = $SourcePath.Replace('/', '\')
  if (-not (Test-NSISAbsoluteArchivePath -Path $Path)) {
    $Path = Join-NSISArchivePath -Prefix $OutputPrefix -Path $Path
  }

  # The archive browser presents $INSTDIR as its virtual root. Other symbolic
  # variables remain visible so architecture/scope-dependent destinations do not
  # collapse into one flat directory.
  if ($Path.Equals('$INSTDIR', [StringComparison]::OrdinalIgnoreCase)) { return '' }
  if ($Path.StartsWith('$INSTDIR\', [StringComparison]::OrdinalIgnoreCase)) {
    return $Path.Substring('$INSTDIR\'.Length)
  }
  return $Path
}

function Skip-NSISSequentialBytes {
  <#
  .SYNOPSIS
    Consume an exact number of bytes from a decoded NSIS stream
  .PARAMETER Stream
    Sequential decoded stream. The caller owns it and its position advances.
  .PARAMETER Count
    Exact number of bytes to discard.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Count
  )

  if ($Count -eq 0) { return }
  $null = Copy-BoundedStream -Source $Stream -Destination ([System.IO.Stream]::Null) -MaximumBytes $Count -ExpectedBytes $Count
}

function New-NSISExtractionOutputMap {
  <#
  .SYNOPSIS
    Assign collision-safe output paths to selected NSIS payload records
  .PARAMETER Payload
    Selected EW_EXTRACTFILE payload records.
  .PARAMETER DestinationPath
    Validated extraction root.
  .PARAMETER CollisionAction
    Behavior when payload destinations collide with existing or selected paths.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][pscustomobject[]]$Payload,
    [Parameter(Mandatory)][string]$DestinationPath,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Rename'
  )

  $ReservedPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Mapped = [System.Collections.Generic.List[object]]::new()
  foreach ($Item in $Payload) {
    # Repeated command entries frequently reference the same plugin data and
    # destination. Emit that physical file once while preserving aliases that
    # use distinct compiled paths.
    $OriginalPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Item.RelativePath
    $Identity = "$OriginalPath`0$($Item.DataOffset)"
    if (-not $Seen.Add($Identity)) { continue }
    $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Item.RelativePath `
      -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
    if (-not $Target.ShouldWrite) { continue }
    $Item | Add-Member -NotePropertyName OutputPath -NotePropertyValue $Target.Path
    $Mapped.Add($Item)
  }
  return $Mapped.ToArray()
}

function Set-NSISExtractedFileTime {
  <#
  .SYNOPSIS
    Apply a compiled EW_EXTRACTFILE modification time when it is defined
  .PARAMETER Path
    Extracted file path.
  .PARAMETER TimeLow
    Low uint32 of the Windows FILETIME.
  .PARAMETER TimeHigh
    High uint32 of the Windows FILETIME.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][uint32]$TimeLow,
    [Parameter(Mandatory)][uint32]$TimeHigh
  )

  if (($TimeLow -eq [uint32]::MaxValue -and $TimeHigh -eq [uint32]::MaxValue) -or ($TimeLow -eq 0 -and $TimeHigh -eq 0)) { return }
  $RawTime = [uint64]$TimeLow -bor ([uint64]$TimeHigh -shl 32)
  if ($RawTime -gt [long]::MaxValue) { return }
  try { [IO.File]::SetLastWriteTimeUtc($Path, [DateTime]::FromFileTimeUtc([long]$RawTime)) } catch { }
}

function Write-NSISPayloadStream {
  <#
  .SYNOPSIS
    Atomically write one bounded decoded payload stream to disk
  .PARAMETER Stream
    Sequential source stream positioned at the payload body.
  .PARAMETER OutputPath
    Safe absolute output path.
  .PARAMETER MaximumBytes
    Hard maximum bytes accepted for this payload.
  .PARAMETER ExpectedBytes
    Exact payload size when the record provides one, or -1 for compressed non-solid data.
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$MaximumBytes,
    [Parameter(Mandatory)][ValidateRange(-1, [long]::MaxValue)][long]$ExpectedBytes
  )

  $Directory = Split-Path -Path $OutputPath -Parent
  $null = New-Item -Path $Directory -ItemType Directory -Force
  $PartialPath = Join-Path $Directory ('.' + [IO.Path]::GetFileName($OutputPath) + '.partial-' + [Guid]::NewGuid().ToString('N'))
  $Output = [IO.File]::Open($PartialPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try {
    $CopyArguments = @{ Source = $Stream; Destination = $Output; MaximumBytes = $MaximumBytes }
    if ($ExpectedBytes -ge 0) { $CopyArguments.ExpectedBytes = $ExpectedBytes }
    $null = Copy-BoundedStream @CopyArguments
  } catch {
    $Output.Dispose()
    Remove-Item -LiteralPath $PartialPath -Force -ErrorAction SilentlyContinue
    throw
  } finally {
    if ($Output) { $Output.Dispose() }
  }
  [IO.File]::Move($PartialPath, $OutputPath, $true)
  return Get-Item -LiteralPath $OutputPath -Force
}

function Copy-NSISPayloadAliases {
  <#
  .SYNOPSIS
    Copy one decoded payload to additional compiled output names
  .PARAMETER SourcePath
    Already extracted source path.
  .PARAMETER Payload
    Payload records sharing the same NSIS data offset.
  .PARAMETER MaximumExpandedBytes
    Remaining total output budget including alias copies.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][string]$SourcePath,
    [Parameter(Mandatory)][pscustomobject[]]$Payload,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$MaximumExpandedBytes
  )

  $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
  $Length = (Get-Item -LiteralPath $SourcePath -Force).Length
  $AliasCount = [Math]::Max(0, $Payload.Count - 1)
  if ($Length -gt 0 -and $AliasCount -gt [Math]::Floor($MaximumExpandedBytes / $Length)) {
    throw 'The selected NSIS payload aliases exceed the maximum expanded-byte limit'
  }
  foreach ($Alias in $Payload) {
    if ($Alias.OutputPath -ceq $SourcePath) { continue }
    $InputStream = [IO.File]::Open($SourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
      $File = Write-NSISPayloadStream -Stream $InputStream -OutputPath $Alias.OutputPath -MaximumBytes $Length -ExpectedBytes $Length
    } finally {
      $InputStream.Dispose()
    }
    Set-NSISExtractedFileTime -Path $File.FullName -TimeLow $Alias.TimeLow -TimeHigh $Alias.TimeHigh
    $Result.Add($File)
  }
  return $Result.ToArray()
}

function Expand-NSISNonSolidPayloads {
  <#
  .SYNOPSIS
    Extract selected independently framed payload records from a non-solid NSIS archive
  .PARAMETER Stream
    Installer stream opened once by the public extractor. The caller owns it.
  .PARAMETER HeaderData
    Validated archive and codec layout.
  .PARAMETER Payload
    Selected payload records with safe output paths.
  .PARAMETER MaximumExpandedBytes
    Hard total output limit across payloads and aliases.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][pscustomobject]$HeaderData,
    [Parameter(Mandatory)][pscustomobject[]]$Payload,
    [Parameter(Mandatory)][long]$MaximumExpandedBytes
  )

  $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
  $ExpandedBytes = 0L
  $ArchiveEnd = $HeaderData.FirstHeaderOffset + $HeaderData.ArchiveSize
  $DataBlockOffset = $HeaderData.PayloadOffset + $HeaderData.PackedSizeWidth + $HeaderData.CompressedHeaderSize
  $Groups = $Payload | Group-Object -Property DataOffset | Sort-Object { [uint64]$_.Name }
  foreach ($Group in $Groups) {
    $Items = [pscustomobject[]]@($Group.Group)
    $RecordOffset = $DataBlockOffset + [uint64]$Items[0].DataOffset
    if ($RecordOffset -gt [long]::MaxValue -or $RecordOffset + $HeaderData.PackedSizeWidth -gt $ArchiveEnd) {
      throw "The NSIS payload record offset is outside the archive: $($Items[0].DataOffset)"
    }

    $PackedValue = [uint64](Read-BinaryInteger -Stream $Stream -Offset ([long]$RecordOffset) -Size $HeaderData.PackedSizeWidth)
    $CompressedMask = if ($HeaderData.PackedSizeWidth -eq 8) { [uint64]::Parse('9223372036854775808') } else { [uint64]2147483648 }
    $LengthMask = if ($HeaderData.PackedSizeWidth -eq 8) { [uint64]9223372036854775807 } else { [uint64]2147483647 }
    $PackedLength = $PackedValue -band $LengthMask
    $IsCompressed = ($PackedValue -band $CompressedMask) -ne 0
    $BodyOffset = $RecordOffset + $HeaderData.PackedSizeWidth
    if ($PackedLength -gt [long]::MaxValue -or $BodyOffset + $PackedLength -gt $ArchiveEnd) {
      throw "The NSIS payload body is outside the archive: $($Items[0].SourcePath)"
    }

    $Remaining = $MaximumExpandedBytes - $ExpandedBytes
    $PerOutputLimit = [long][Math]::Floor($Remaining / $Items.Count)
    $Body = New-BoundedReadStream -Stream $Stream -Offset ([long]$BodyOffset) -Length ([long]$PackedLength) -LeaveOpen
    $Decoder = $null
    try {
      $Source = $Body
      $ExpectedBytes = [long]$PackedLength
      if ($IsCompressed) {
        $Probe = Read-BinaryBytes -Stream $Body -Offset 0 -Count ([int][Math]::Min(24L, [long]$PackedLength))
        $LzmaFilterLength = if ($HeaderData.Compression -eq 'Lzma') { Get-NSISLzmaFilterLength -Bytes $Probe } else { -1 }
        $Decoder = New-NSISDecoder -Compression $HeaderData.Compression -PayloadStream $Body `
          -LzmaFilterLength $LzmaFilterLength -ExpectedOutputBytes -1
        $Source = $Decoder
        $ExpectedBytes = -1
      }
      $File = Write-NSISPayloadStream -Stream $Source -OutputPath $Items[0].OutputPath -MaximumBytes $PerOutputLimit -ExpectedBytes $ExpectedBytes
    } finally {
      if ($Decoder -is [System.IDisposable]) { $Decoder.Dispose() }
      $Body.Dispose()
    }

    Set-NSISExtractedFileTime -Path $File.FullName -TimeLow $Items[0].TimeLow -TimeHigh $Items[0].TimeHigh
    $Result.Add($File)
    $ExpandedBytes += $File.Length
    $Aliases = Copy-NSISPayloadAliases -SourcePath $File.FullName -Payload $Items -MaximumExpandedBytes ($MaximumExpandedBytes - $ExpandedBytes)
    foreach ($Alias in $Aliases) { $Result.Add($Alias); $ExpandedBytes += $Alias.Length }
  }
  return $Result.ToArray()
}

function Expand-NSISSolidPayloads {
  <#
  .SYNOPSIS
    Extract selected records while advancing once through a solid NSIS codec stream
  .PARAMETER Stream
    Installer stream opened once by the public extractor. The caller owns it.
  .PARAMETER HeaderData
    Validated archive and codec layout.
  .PARAMETER Payload
    Selected payload records with safe output paths.
  .PARAMETER MaximumExpandedBytes
    Hard total output limit across payloads and aliases.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][pscustomobject]$HeaderData,
    [Parameter(Mandatory)][pscustomobject[]]$Payload,
    [Parameter(Mandatory)][long]$MaximumExpandedBytes
  )

  $PayloadRange = New-BoundedReadStream -Stream $Stream -Offset $HeaderData.PayloadDataOffset -Length $HeaderData.PayloadDataLength -LeaveOpen
  $Decoder = $null
  $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
  $ExpandedBytes = 0L
  $LogicalPosition = 0L
  try {
    $Probe = Read-BinaryBytes -Stream $PayloadRange -Offset 0 -Count ([int][Math]::Min(24L, $PayloadRange.Length))
    $LzmaFilterLength = if ($HeaderData.Compression -eq 'Lzma') { Get-NSISLzmaFilterLength -Bytes $Probe } else { -1 }
    $Decoder = New-NSISDecoder -Compression $HeaderData.Compression -PayloadStream $PayloadRange `
      -LzmaFilterLength $LzmaFilterLength -ExpectedOutputBytes -1

    $Groups = $Payload | Group-Object -Property DataOffset | Sort-Object { [uint64]$_.Name }
    foreach ($Group in $Groups) {
      $Items = [pscustomobject[]]@($Group.Group)
      $RecordPosition = [uint64]$HeaderData.PackedSizeWidth + [uint64]$HeaderData.HeaderSize + [uint64]$Items[0].DataOffset
      if ($RecordPosition -gt [long]::MaxValue -or [long]$RecordPosition -lt $LogicalPosition) {
        throw "The NSIS solid payload offsets overlap or exceed the supported range: $($Items[0].DataOffset)"
      }
      Skip-NSISSequentialBytes -Stream $Decoder -Count ([long]$RecordPosition - $LogicalPosition)
      $LogicalPosition = [long]$RecordPosition

      try {
        $UnpackedLength = [uint64](Read-BinarySequentialInteger -Stream $Decoder -Size $HeaderData.PackedSizeWidth)
      } catch {
        throw 'The NSIS payload length field is truncated'
      }
      $LogicalPosition += $HeaderData.PackedSizeWidth
      $CompressedMask = if ($HeaderData.PackedSizeWidth -eq 8) { [uint64]::Parse('9223372036854775808') } else { [uint64]2147483648 }
      if (($UnpackedLength -band $CompressedMask) -ne 0 -or $UnpackedLength -gt [long]::MaxValue) {
        throw "The NSIS solid payload length is invalid: $($Items[0].SourcePath)"
      }

      $Remaining = $MaximumExpandedBytes - $ExpandedBytes
      if ($UnpackedLength -gt [Math]::Floor($Remaining / $Items.Count)) {
        throw 'The selected NSIS payloads exceed the maximum expanded-byte limit'
      }
      $File = Write-NSISPayloadStream -Stream $Decoder -OutputPath $Items[0].OutputPath `
        -MaximumBytes ([long]$UnpackedLength) -ExpectedBytes ([long]$UnpackedLength)
      $LogicalPosition += [long]$UnpackedLength
      Set-NSISExtractedFileTime -Path $File.FullName -TimeLow $Items[0].TimeLow -TimeHigh $Items[0].TimeHigh
      $Result.Add($File)
      $ExpandedBytes += $File.Length
      $Aliases = Copy-NSISPayloadAliases -SourcePath $File.FullName -Payload $Items -MaximumExpandedBytes ($MaximumExpandedBytes - $ExpandedBytes)
      foreach ($Alias in $Aliases) { $Result.Add($Alias); $ExpandedBytes += $Alias.Length }
    }
  } finally {
    if ($Decoder -is [System.IDisposable]) { $Decoder.Dispose() }
    $PayloadRange.Dispose()
  }
  return $Result.ToArray()
}

function Expand-NSISMtwPayloads {
  <#
  .SYNOPSIS
    Extract selected NSISBI MTW records through a bounded spill file
  .PARAMETER Stream
    Installer stream opened once by the public extractor. The caller owns it.
  .PARAMETER HeaderData
    Validated NSISBI archive and MTW layout.
  .PARAMETER Payload
    Selected payload records with safe output paths.
  .PARAMETER MaximumExpandedBytes
    Hard total output limit across payloads and aliases.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][pscustomobject]$HeaderData,
    [Parameter(Mandatory)][pscustomobject[]]$Payload,
    [Parameter(Mandatory)][long]$MaximumExpandedBytes
  )

  $PayloadRange = New-BoundedReadStream -Stream $Stream -Offset $HeaderData.PayloadDataOffset -Length $HeaderData.PayloadDataLength -LeaveOpen
  $SpillPath = [IO.Path]::GetTempFileName()
  $Spill = [IO.File]::Open($SpillPath, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  $RecordOffset = 0L
  $Compression = ($HeaderData.Compression -replace '^Mtw-', '')
  $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
  $ExpandedBytes = 0L
  try {
    $Groups = $Payload | Group-Object -Property DataOffset | Sort-Object { [uint64]$_.Name }
    foreach ($Group in $Groups) {
      $Items = [pscustomobject[]]@($Group.Group)
      $LogicalRecordOffset = [uint64]$HeaderData.PackedSizeWidth + [uint64]$HeaderData.HeaderSize + [uint64]$Items[0].DataOffset
      if ($LogicalRecordOffset -gt [long]::MaxValue) { throw 'The NSISBI solid payload offset exceeds the supported stream range' }

      # MTW blocks are independently compressed and can be decoded only in block
      # order. Spill the minimum prefix needed for each selected record so large
      # Unity-style archives do not become one in-memory byte array.
      while ($Spill.Length -lt [long]$LogicalRecordOffset + $HeaderData.PackedSizeWidth) {
        $Block = Read-NSISMtwBlock -Stream $PayloadRange -RecordOffset $RecordOffset -Compression $Compression
        if ($Block.IsEnd) { throw 'The NSISBI MTW stream ended before the selected payload record' }
        $Compression = $Block.Compression
        $Spill.Position = $Spill.Length
        $Spill.Write($Block.Bytes, 0, $Block.Bytes.Length)
        $RecordOffset = $Block.NextOffset
      }

      $UnpackedLength = [uint64](Read-BinaryInteger -Stream $Spill -Offset ([long]$LogicalRecordOffset) -Size $HeaderData.PackedSizeWidth)
      $CompressedMask = if ($HeaderData.PackedSizeWidth -eq 8) { [uint64]::Parse('9223372036854775808') } else { [uint64]2147483648 }
      if (($UnpackedLength -band $CompressedMask) -ne 0 -or $UnpackedLength -gt [long]::MaxValue) {
        throw "The NSISBI solid payload length is invalid: $($Items[0].SourcePath)"
      }
      $BodyEnd = [uint64]$LogicalRecordOffset + [uint64]$HeaderData.PackedSizeWidth + $UnpackedLength
      if ($BodyEnd -gt [long]::MaxValue) { throw 'The NSISBI solid payload range exceeds the supported stream range' }
      while ($Spill.Length -lt [long]$BodyEnd) {
        $Block = Read-NSISMtwBlock -Stream $PayloadRange -RecordOffset $RecordOffset -Compression $Compression
        if ($Block.IsEnd) { throw 'The NSISBI MTW stream ended inside the selected payload body' }
        $Spill.Position = $Spill.Length
        $Spill.Write($Block.Bytes, 0, $Block.Bytes.Length)
        $RecordOffset = $Block.NextOffset
      }

      $Remaining = $MaximumExpandedBytes - $ExpandedBytes
      if ($UnpackedLength -gt [Math]::Floor($Remaining / $Items.Count)) { throw 'The selected NSIS payloads exceed the maximum expanded-byte limit' }
      $Body = New-BoundedReadStream -Stream $Spill -Offset ([long]$LogicalRecordOffset + $HeaderData.PackedSizeWidth) -Length ([long]$UnpackedLength) -LeaveOpen
      try {
        $File = Write-NSISPayloadStream -Stream $Body -OutputPath $Items[0].OutputPath `
          -MaximumBytes ([long]$UnpackedLength) -ExpectedBytes ([long]$UnpackedLength)
      } finally {
        $Body.Dispose()
      }
      Set-NSISExtractedFileTime -Path $File.FullName -TimeLow $Items[0].TimeLow -TimeHigh $Items[0].TimeHigh
      $Result.Add($File)
      $ExpandedBytes += $File.Length
      $Aliases = Copy-NSISPayloadAliases -SourcePath $File.FullName -Payload $Items -MaximumExpandedBytes ($MaximumExpandedBytes - $ExpandedBytes)
      foreach ($Alias in $Aliases) { $Result.Add($Alias); $ExpandedBytes += $Alias.Length }
    }
  } finally {
    $Spill.Dispose()
    $PayloadRange.Dispose()
    Remove-Item -LiteralPath $SpillPath -Force -ErrorAction SilentlyContinue
  }
  return $Result.ToArray()
}

function Expand-NSISPayload {
  <#
  .SYNOPSIS
    Extract selected embedded files from an NSIS installer without executing it
  .PARAMETER Path
    Path to the NSIS installer.
  .PARAMETER DestinationPath
    Extraction directory. A unique temporary directory is created when omitted.
  .PARAMETER Name
    Wildcard matched against compiled payload paths and base filenames. The default extracts all EW_EXTRACTFILE payloads.
  .PARAMETER MaximumExpandedBytes
    Maximum total bytes written, including aliases that share one data record.
  .PARAMETER CollisionAction
    Behavior when a payload path already exists or multiple File commands resolve to the same path.
  .PARAMETER StateInitializer
    Facade-owned callback that creates the simulator state used to resolve compiled payload paths.
  .PARAMETER PayloadSelector
    Facade-owned callback that projects simulated File commands into extraction records.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,
    [Parameter(HelpMessage = 'The directory where selected payloads should be written')]
    [string]$DestinationPath,
    [Parameter(HelpMessage = 'The payload path or wildcard pattern to extract')]
    [ValidateNotNullOrEmpty()][string]$Name = '*',
    [Parameter(HelpMessage = 'The maximum total number of extracted bytes')]
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = $Script:NSIS_DEFAULT_MAXIMUM_EXPANDED_BYTES,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [Parameter(Mandatory)][scriptblock]$StateInitializer,
    [Parameter(Mandatory)][scriptblock]$PayloadSelector
  )

  process {
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $ResolvedDestinationPath = $DestinationPath
    if ([string]::IsNullOrWhiteSpace($ResolvedDestinationPath)) {
      $ResolvedDestinationPath = Join-Path ([IO.Path]::GetTempPath()) ('Dumplings-NSIS-' + [Guid]::NewGuid().ToString('N'))
    }
    $ResolvedDestinationPath = Resolve-InstallerFileSystemPath -Path $ResolvedDestinationPath -AllowNonexistent
    $ResolvedDestinationPath = (New-Item -Path $ResolvedDestinationPath -ItemType Directory -Force).FullName

    $HeaderData = Get-NSISHeaderData -Path $InstallerPath
    if ($HeaderData.HasExternalFile) {
      throw 'The NSISBI installer references an external payload sidecar; embedded-only extraction would be incomplete'
    }
    $Initialized = & $StateInitializer $HeaderData
    $Selected = & $PayloadSelector $Initialized.State $HeaderData $Name
    if ($Selected.Count -eq 0) { throw "No NSIS payload matched '$Name'" }
    $Mapped = New-NSISExtractionOutputMap -Payload $Selected -DestinationPath $ResolvedDestinationPath -CollisionAction $CollisionAction
    if ($Mapped.Count -eq 0) { return }

    $InstallerStream = [IO.File]::Open($InstallerPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      if (-not $HeaderData.IsSolid) {
        return Expand-NSISNonSolidPayloads -Stream $InstallerStream -HeaderData $HeaderData -Payload $Mapped -MaximumExpandedBytes $MaximumExpandedBytes
      }
      if ($HeaderData.Compression -like 'Mtw-*') {
        return Expand-NSISMtwPayloads -Stream $InstallerStream -HeaderData $HeaderData -Payload $Mapped -MaximumExpandedBytes $MaximumExpandedBytes
      }
      return Expand-NSISSolidPayloads -Stream $InstallerStream -HeaderData $HeaderData -Payload $Mapped -MaximumExpandedBytes $MaximumExpandedBytes
    } finally {
      $InstallerStream.Dispose()
    }
  }
}

# Internal format functions and constants are exported for the simulation and facade modules.
Export-ModuleMember -Function * -Variable 'NSIS*'
