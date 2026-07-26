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
# A packed-size high bit marks a compressed non-solid block; solid archives start
# directly with one codec stream. Opcode numbering is normalized for NSIS 2/3,
# Unicode/Park, log-enabled, and NSISBI layouts before simulation. Explicit
# EW_WRITEREG commands are authoritative; arbitrary strings are not.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

function Get-Assembly {
  <#
  .SYNOPSIS
    Get a managed compression assembly used for static installer parsing
  .PARAMETER Name
    The assembly file name under Modules\InstallerParsers\Assets
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The assembly file name under Modules\InstallerParsers\Assets')]
    [string]$Name
  )

  $AssetsPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Assets'
  if (Test-Path -Path ($Path = Join-Path -Path $AssetsPath -ChildPath $Name)) {
    return Get-Item -Path $Path -Force
  } else {
    throw "The $Name assembly could not be found"
  }
}

function Import-Assembly {
  <#
  .SYNOPSIS
    Load the managed compression assemblies used for NSIS parsing
  #>

  Import-InstallerArchiveDependency
}

Import-Assembly

function Import-NSISBZip2Decoder {
  <#
  .SYNOPSIS
    Load the format-specific raw NSIS BZip2 decoder once per process
  .NOTES
    NSIS omits the standard BZh header, block signatures, and CRC fields, so
    SharpCompress's public standard-BZip2 stream cannot decode this framing.
  #>
  if (([System.Management.Automation.PSTypeName]'Dumplings.InstallerParsers.NSIS.NsisBZip2Stream').Type) { return }

  Use-InstallerRuntimeLoadLock {
    # Recheck after acquiring the process-wide loader lock because another
    # parser runspace may have compiled the type while this runspace waited.
    if (([System.Management.Automation.PSTypeName]'Dumplings.InstallerParsers.NSIS.NsisBZip2Stream').Type) { return }
    $SourcePath = Join-Path -Path $PSScriptRoot -ChildPath '..\Assets\NsisBZip2Stream.cs'
    if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) {
      throw "The NSIS raw BZip2 decoder source is missing: $SourcePath"
    }
    $null = Add-Type -Path $SourcePath -ErrorAction Stop
  }
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

function Get-NSISStringCodeKind {
  <#
  .SYNOPSIS
    Resolve an NSIS control code kind for the active installer version
  .PARAMETER Character
    The candidate control code
  .PARAMETER IsV3
    Whether the installer uses NSIS v3 control codes
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate control code')]
    [uint16]$Character,

    [Parameter(Mandatory, HelpMessage = 'Whether the installer uses NSIS v3 control codes')]
    [bool]$IsV3,

    [Parameter(HelpMessage = 'The detected NSIS command layout type')]
    [string]$Type = $(if ($IsV3) { 'NSIS3' } else { 'NSIS2' })
  )

  if ($Type -like 'Park*') {
    switch ($Character) {
      0xE003 { return 'Lang' }
      0xE002 { return 'Shell' }
      0xE001 { return 'Var' }
      0xE000 { return 'Skip' }
      default { return $null }
    }
  } elseif ($IsV3) {
    switch ($Character) {
      1 { return 'Lang' }
      2 { return 'Shell' }
      3 { return 'Var' }
      4 { return 'Skip' }
      default { return $null }
    }
  } else {
    switch ($Character) {
      252 { return 'Skip' }
      253 { return 'Var' }
      254 { return 'Shell' }
      255 { return 'Lang' }
      default { return $null }
    }
  }
}

function ConvertFrom-NSISPackedNumber {
  <#
  .SYNOPSIS
    Decode the packed 15-bit NSIS number embedded in a string control code payload
  .PARAMETER Character
    The raw 16-bit control code payload
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The raw 16-bit control code payload')]
    [uint16]$Character,

    [Parameter(HelpMessage = 'The detected NSIS command layout type')]
    [string]$Type = 'NSIS3'
  )

  if ($Type -like 'Park*') { return [int]($Character -band 0x7FFF) }

  $MaskedCharacter = $Character -band 0x7F7F
  $Bytes = [System.BitConverter]::GetBytes($MaskedCharacter)
  return [int]($Bytes[0] -bor ($Bytes[1] -shl 7))
}

function Get-NSISVariableValue {
  <#
  .SYNOPSIS
    Resolve a compiled NSIS variable reference
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Index
    The compiled variable index
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled variable index')]
    [int]$Index
  )

  if ($State.Variables.ContainsKey($Index)) { return [string]$State.Variables[$Index] }

  switch ($Index) {
    $Script:NSIS_PREDEFINED_VAR_CMDLINE { return '' }
    $Script:NSIS_PREDEFINED_VAR_EXEDIR { return Split-Path -Path $State.Path -Parent }
    $Script:NSIS_PREDEFINED_VAR_LANGUAGE { return [string]$State.LanguageTable.LanguageId }
    $Script:NSIS_PREDEFINED_VAR_TEMP { return [System.IO.Path]::GetTempPath().TrimEnd('\') }
    $Script:NSIS_PREDEFINED_VAR_PLUGINSDIR { return Join-Path ([System.IO.Path]::GetTempPath().TrimEnd('\')) 'NSIS' }
    $Script:NSIS_PREDEFINED_VAR_EXEPATH { return $State.Path }
    $Script:NSIS_PREDEFINED_VAR_EXEFILE { return Split-Path -Path $State.Path -Leaf }
    $Script:NSIS_PREDEFINED_VAR_CLICK { return 'Click Next to continue.' }
    default { return '' }
  }
}

function Set-NSISVariableValue {
  <#
  .SYNOPSIS
    Update a compiled NSIS variable and keep the derived install paths in sync
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Index
    The compiled variable index
  .PARAMETER Value
    The resolved string value
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled variable index')]
    [int]$Index,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The resolved string value')]
    [string]$Value
  )

  $State.Variables[$Index] = $Value

  switch ($Index) {
    $Script:NSIS_PREDEFINED_VAR_INSTDIR {
      $State.Variables[$Script:NSIS_PREDEFINED_VAR_OUTDIR] = $Value
      $State.Variables[$Script:NSIS_PREDEFINED_VAR__OUTDIR] = $Value
      if (-not [string]::IsNullOrWhiteSpace($Value)) { $State.Metadata.DefaultInstallLocation = $Value }
    }
    $Script:NSIS_PREDEFINED_VAR_OUTDIR { $State.Variables[$Script:NSIS_PREDEFINED_VAR__OUTDIR] = $Value }
    $Script:NSIS_PREDEFINED_VAR__OUTDIR { $State.Variables[$Script:NSIS_PREDEFINED_VAR_OUTDIR] = $Value }
    default { }
  }
}

function Resolve-NSISShellValue {
  <#
  .SYNOPSIS
    Resolve a compiled NSIS shell-folder control code
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Character
    The raw 16-bit shell payload
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The raw 16-bit shell payload')]
    [uint16]$Character
  )

  # NSIS packs two shell-folder indexes or an indirect string reference into one
  # 16-bit control payload. Decode both bytes without consulting the host shell.
  $Bytes = [System.BitConverter]::GetBytes($Character)
  $Index1 = $Bytes[0]
  $Index2 = $Bytes[1]

  # The high bit selects an indirect registry-name string; bit 6 distinguishes
  # 64-bit Program Files/Common Files from their 32-bit counterparts.
  if (($Index1 -band 0x80) -ne 0) {
    $StringOffset = $Index1 -band 0x3F
    $Is64BitFolder = ($Index1 -band 0x40) -ne 0
    $ShellString = Get-NSISString -State $State -RelativeOffset $StringOffset

    switch ($ShellString) {
      'ProgramFilesDir' {
        if ($Is64BitFolder) {
          return $(if (${env:ProgramW6432}) { ${env:ProgramW6432} } else { $env:ProgramFiles })
        } else {
          return $(if (${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} } else { $env:ProgramFiles })
        }
      }
      'CommonFilesDir' {
        if ($Is64BitFolder) {
          return $(if (${env:CommonProgramW6432}) { ${env:CommonProgramW6432} } else { $env:CommonProgramFiles })
        } else {
          return $(if (${env:CommonProgramFiles(x86)}) { ${env:CommonProgramFiles(x86)} } else { $env:CommonProgramFiles })
        }
      }
      default { return $ShellString }
    }
  }

  # Ordinary payloads carry primary/fallback CSIDL indexes. Return the first
  # mapped deterministic path and leave unknown identifiers unresolved.
  if ($Index1 -lt $Script:NSIS_SHELL_STRINGS.Count -and $Script:NSIS_SHELL_STRINGS[$Index1]) { return [string]$Script:NSIS_SHELL_STRINGS[$Index1] }
  if ($Index2 -lt $Script:NSIS_SHELL_STRINGS.Count -and $Script:NSIS_SHELL_STRINGS[$Index2]) { return [string]$Script:NSIS_SHELL_STRINGS[$Index2] }
  return ''
}

function Get-NSISString {
  <#
  .SYNOPSIS
    Decode a compiled NSIS string from the strings block
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER RelativeOffset
    The compiled relative string offset
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled relative string offset')]
    [int]$RelativeOffset
  )

  if ($RelativeOffset -lt 0) {
    # Negative offsets encode language-table indices rather than byte positions.
    $LanguageIndex = [Math]::Abs($RelativeOffset + 1)
    if (-not $State.LanguageTable -or $LanguageIndex -ge $State.LanguageTable.StringOffsets.Count) { return '' }
    $ResolvedOffset = $State.LanguageTable.StringOffsets[$LanguageIndex]
    if ($ResolvedOffset -eq 0) { return '' }
    return Get-NSISString -State $State -RelativeOffset $ResolvedOffset
  }

  $Multiplier = if ($State.VersionInfo.Unicode) { 2 } else { 1 }
  $Offset = $RelativeOffset * $Multiplier
  if ($Offset -lt 0 -or $Offset -ge $State.StringsBlock.Length) { return '' }

  if ($State.VersionInfo.Unicode) {
    # Decode the bounded NUL-terminated UTF-16LE or ANSI code-unit sequence first;
    # control-code expansion is performed in a second pass below.
    $EndOffset = $Offset
    while ($EndOffset + 1 -lt $State.StringsBlock.Length -and -not ($State.StringsBlock[$EndOffset] -eq 0x00 -and $State.StringsBlock[$EndOffset + 1] -eq 0x00)) { $EndOffset += 2 }
    if ($EndOffset -le $Offset) { return '' }
    $Characters = [uint16[]]::new(($EndOffset - $Offset) / 2)
    [Buffer]::BlockCopy($State.StringsBlock, $Offset, $Characters, 0, $EndOffset - $Offset)
  } else {
    $EndOffset = $Offset
    while ($EndOffset -lt $State.StringsBlock.Length -and $State.StringsBlock[$EndOffset] -ne 0x00) { $EndOffset++ }
    if ($EndOffset -le $Offset) { return '' }
    $Characters = [uint16[]]::new($EndOffset - $Offset)
    for ($CharacterIndex = 0; $CharacterIndex -lt $Characters.Length; $CharacterIndex++) {
      $Characters[$CharacterIndex] = $State.StringsBlock[$Offset + $CharacterIndex]
    }
  }

  $Builder = [System.Text.StringBuilder]::new()
  $Index = 0

  # Expand variable, shell-folder, and language indirections while preserving
  # escaped control characters. Truncated control payloads terminate safely.
  while ($Index -lt $Characters.Count) {
    $Current = $Characters[$Index]
    $CodeKind = Get-NSISStringCodeKind -Character $Current -IsV3 $State.VersionInfo.IsV3 -Type $State.VersionInfo.Type

    if ($CodeKind) {
      if ($Index + 1 -ge $Characters.Count) { break }

      if ($CodeKind -eq 'Skip') {
        $Current = $Characters[$Index + 1]
        $Index++
      } else {
        if ($State.VersionInfo.Unicode) {
          $Payload = $Characters[$Index + 1]
          $Index++
        } else {
          if ($Index + 2 -ge $Characters.Count) { break }
          $Payload = [uint16]($Characters[$Index + 1] -bor ($Characters[$Index + 2] -shl 8))
          $Index += 2
        }

        switch ($CodeKind) {
          'Var' { $null = $Builder.Append((Get-NSISVariableValue -State $State -Index (ConvertFrom-NSISPackedNumber -Character $Payload -Type $State.VersionInfo.Type))) }
          'Shell' { $null = $Builder.Append((Resolve-NSISShellValue -State $State -Character $Payload)) }
          'Lang' {
            $LanguageIndex = ConvertFrom-NSISPackedNumber -Character $Payload -Type $State.VersionInfo.Type
            if ($State.LanguageTable -and $LanguageIndex -lt $State.LanguageTable.StringOffsets.Count) {
              $StringOffset = $State.LanguageTable.StringOffsets[$LanguageIndex]
              if ($StringOffset -ne 0) { $null = $Builder.Append((Get-NSISString -State $State -RelativeOffset $StringOffset)) }
            }
          }
        }

        $Index++
        continue
      }
    }

    $null = $Builder.Append([char]$Current)
    $Index++
  }

  return $Builder.ToString()
}

function Get-NSISStringVariableIndex {
  <#
  .SYNOPSIS
    Read the variable references encoded in one compiled NSIS string
  .PARAMETER State
    The mutable NSIS execution state containing the strings block
  .PARAMETER RelativeOffset
    The string-table offset, measured in characters for Unicode installers
  #>
  [OutputType([int[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled relative string offset')]
    [int]$RelativeOffset
  )

  if ($RelativeOffset -lt 0) { return [int[]]@() }
  $Multiplier = if ($State.VersionInfo.Unicode) { 2 } else { 1 }
  $Offset = $RelativeOffset * $Multiplier
  if ($Offset -lt 0 -or $Offset -ge $State.StringsBlock.Length) { return [int[]]@() }

  $Indexes = [System.Collections.Generic.HashSet[int]]::new()
  while ($Offset -lt $State.StringsBlock.Length) {
    if ($State.VersionInfo.Unicode) {
      if ($Offset + 1 -ge $State.StringsBlock.Length) { break }
      $Character = [System.BitConverter]::ToUInt16($State.StringsBlock, $Offset)
      $Offset += 2
    } else {
      $Character = [uint16]$State.StringsBlock[$Offset]
      $Offset++
    }
    if ($Character -eq 0) { break }

    $CodeKind = Get-NSISStringCodeKind -Character $Character -IsV3 $State.VersionInfo.IsV3 -Type $State.VersionInfo.Type
    if (-not $CodeKind) { continue }
    if ($State.VersionInfo.Unicode) {
      if ($Offset + 1 -ge $State.StringsBlock.Length) { break }
      $Payload = [System.BitConverter]::ToUInt16($State.StringsBlock, $Offset)
      $Offset += 2
    } else {
      if ($Offset + 1 -ge $State.StringsBlock.Length) { break }
      $Payload = [uint16]($State.StringsBlock[$Offset] -bor ($State.StringsBlock[$Offset + 1] -shl 8))
      $Offset += 2
    }

    if ($CodeKind -eq 'Var') {
      $null = $Indexes.Add((ConvertFrom-NSISPackedNumber -Character $Payload -Type $State.VersionInfo.Type))
    }
  }

  return [int[]]@($Indexes)
}

function Resolve-NSISDirectString {
  <#
  .SYNOPSIS
    Resolve a direct registry string using nearby compiled StrCpy assignments
  .DESCRIPTION
    A direct uninstall-write scan does not follow control flow. Resolve only the
    nearest lexical assignments needed by the registry operand so unrelated
    plug-in stack values cannot leak into ARP paths.
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER RelativeOffset
    The compiled string-table offset to resolve
  .PARAMETER EntryIndex
    The zero-based command index containing the string operand
  .PARAMETER VisitedVariables
    Variable indexes already being resolved, used to stop assignment cycles
  .PARAMETER Depth
    The current bounded recursive-resolution depth
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled string-table offset')]
    [int]$RelativeOffset,

    [Parameter(Mandatory, HelpMessage = 'The command index containing the string operand')]
    [int]$EntryIndex,

    [Parameter(HelpMessage = 'Variable indexes already being resolved')]
    [System.Collections.Generic.HashSet[int]]$VisitedVariables,

    [Parameter(HelpMessage = 'The current recursive-resolution depth')]
    [int]$Depth = 0
  )

  if ($Depth -ge 16) { return Get-NSISString -State $State -RelativeOffset $RelativeOffset }
  if (-not $VisitedVariables) { $VisitedVariables = [System.Collections.Generic.HashSet[int]]::new() }

  $SavedVariables = [System.Collections.Generic.List[object]]::new()
  try {
    foreach ($VariableIndex in @(Get-NSISStringVariableIndex -State $State -RelativeOffset $RelativeOffset)) {
      # Predefined runtime paths are established by initialization and must not
      # be replaced by unrelated lexical assignments from other code segments.
      if ($VariableIndex -ge $Script:NSIS_PREDEFINED_VAR_CMDLINE -and $VariableIndex -le $Script:NSIS_PREDEFINED_VAR__OUTDIR) { continue }
      if (-not $VisitedVariables.Add($VariableIndex)) { continue }

      $Assignment = $null
      for ($Index = [Math]::Min($EntryIndex - 1, $State.Entries.Count - 1); $Index -ge 0; $Index--) {
        $Candidate = $State.Entries[$Index]
        if ($Candidate.Opcode -eq $Script:NSIS_OPCODE_ASSIGN_VAR -and [Math]::Abs($Candidate.Values[1]) -eq $VariableIndex) {
          $Assignment = [pscustomobject]@{ Entry = $Candidate; Index = $Index }
          break
        }
      }
      if (-not $Assignment) {
        $null = $VisitedVariables.Remove($VariableIndex)
        continue
      }

      $HadValue = $State.Variables.ContainsKey($VariableIndex)
      $SavedVariables.Add([pscustomobject]@{
          Index    = $VariableIndex
          HadValue = $HadValue
          Value    = if ($HadValue) { $State.Variables[$VariableIndex] } else { $null }
        })
      $ResolvedValue = Resolve-NSISDirectString -State $State -RelativeOffset $Assignment.Entry.Values[2] -EntryIndex $Assignment.Index -VisitedVariables $VisitedVariables -Depth ($Depth + 1)
      $State.Variables[$VariableIndex] = $ResolvedValue
      $null = $VisitedVariables.Remove($VariableIndex)
    }

    return Get-NSISString -State $State -RelativeOffset $RelativeOffset
  } finally {
    # Temporary data-flow values must not alter later control-flow simulation.
    for ($Index = $SavedVariables.Count - 1; $Index -ge 0; $Index--) {
      $Saved = $SavedVariables[$Index]
      if ($Saved.HadValue) {
        $State.Variables[$Saved.Index] = $Saved.Value
      } else {
        $null = $State.Variables.Remove($Saved.Index)
      }
    }
  }
}

function Get-NSISInt {
  <#
  .SYNOPSIS
    Resolve a compiled NSIS string operand into an integer
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER RelativeOffset
    The compiled relative string offset
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled relative string offset')]
    [int]$RelativeOffset
  )

  $Value = (Get-NSISString -State $State -RelativeOffset $RelativeOffset).Trim()
  if ([string]::IsNullOrWhiteSpace($Value)) { return 0 }

  if ($Value.StartsWith('0x', [System.StringComparison]::OrdinalIgnoreCase)) {
    return [int]::Parse($Value.Substring(2), [System.Globalization.NumberStyles]::HexNumber, [System.Globalization.CultureInfo]::InvariantCulture)
  }

  $ParsedValue = 0
  if ([int]::TryParse($Value, [ref]$ParsedValue)) {
    return $ParsedValue
  } else {
    return 0
  }
}

function Resolve-NSISAddress {
  <#
  .SYNOPSIS
    Resolve an NSIS jump address, including the negative address indirection form
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Address
    The compiled jump address
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled jump address')]
    [int]$Address
  )

  if ($Address -ge 0) { return $Address }

  $Index = [Math]::Abs($Address) - 1
  $VariableValue = Get-NSISVariableValue -State $State -Index $Index
  $ResolvedAddress = 0
  if ([int]::TryParse($VariableValue, [ref]$ResolvedAddress)) {
    return $ResolvedAddress
  } else {
    return 0
  }
}

function Add-NSISDirectory {
  <#
  .SYNOPSIS
    Record a directory in the simulated NSIS file system
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Path
    The directory path
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The directory path')]
    [string]$Path
  )

  if (-not [string]::IsNullOrWhiteSpace($Path)) { $null = $State.Directories.Add($Path.TrimEnd('\')) }
}

function Add-NSISFile {
  <#
  .SYNOPSIS
    Record a file in the simulated NSIS file system
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Path
    The file path
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The file path')]
    [string]$Path
  )

  if (-not [string]::IsNullOrWhiteSpace($Path)) { $null = $State.Files.Add($Path) }
}

function Test-NSISPathExists {
  <#
  .SYNOPSIS
    Test whether a simulated NSIS path exists
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Path
    The file or directory path
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The file or directory path')]
    [string]$Path
  )

  $NormalizedPath = $Path.TrimEnd('\')
  if ($NormalizedPath.EndsWith('\*.*', [System.StringComparison]::OrdinalIgnoreCase)) {
    return $State.Directories.Contains($NormalizedPath.Substring(0, $NormalizedPath.Length - 4).TrimEnd('\'))
  }

  return $State.Directories.Contains($NormalizedPath) -or $State.Files.Contains($Path)
}

function Resolve-NSISRegistryRoot {
  <#
  .SYNOPSIS
    Resolve an NSIS registry root to a deterministic logical hive
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Root
    The compiled NSIS registry root value
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled NSIS registry root value')]
    [uint32]$Root
  )

  switch ($Root) {
    $Script:NSIS_REG_ROOT_HKCR { return 'HKCR' }
    $Script:NSIS_REG_ROOT_HKCU { return 'HKCU' }
    $Script:NSIS_REG_ROOT_HKLM { return 'HKLM' }
    $Script:NSIS_REG_ROOT_HKU { return 'HKU' }
    $Script:NSIS_REG_ROOT_HKCC { return 'HKCC' }
    $Script:NSIS_REG_ROOT_SHCTX {
      if ($State.ShellVarContext) { return $State.ShellVarContext }

      $InstallLocation = $State.Metadata.DefaultInstallLocation
      if ($InstallLocation -and (
          $InstallLocation.StartsWith($env:ProgramFiles, [System.StringComparison]::OrdinalIgnoreCase) -or
          (${env:ProgramFiles(x86)} -and $InstallLocation.StartsWith(${env:ProgramFiles(x86)}, [System.StringComparison]::OrdinalIgnoreCase))
        )) {
        return 'HKLM'
      }

      return 'HKCU'
    }
    default { return 'HKCU' }
  }
}

function Set-NSISRegistryValue {
  <#
  .SYNOPSIS
    Store a registry value in the simulated NSIS registry and update uninstall metadata
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Root
    The registry root
  .PARAMETER Key
    The registry key path
  .PARAMETER Name
    The registry value name
  .PARAMETER Value
    The registry value data
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The registry root')]
    [string]$Root,

    [Parameter(Mandatory, HelpMessage = 'The registry key path')]
    [string]$Key,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The registry value name')]
    [string]$Name,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The registry value data')]
    [string]$Value
  )

  # The simulated registry exists only to make later ReadReg/branch operations
  # deterministic; it never reads from or writes to the host registry.
  if (-not $State.Registry.ContainsKey($Root)) { $State.Registry[$Root] = @{} }
  if (-not $State.Registry[$Root].ContainsKey($Key)) { $State.Registry[$Root][$Key] = @{} }
  $State.Registry[$Root][$Key][$Name] = $Value

  # Only explicit writes beneath the Windows uninstall path become ARP evidence.
  # SystemComponent=1 hides the otherwise-created entry from WinGet matching.
  if ($Key -match $Script:NSIS_UNINSTALL_KEY_PATTERN) {
    $State.Metadata.ProductCode = Split-Path -Path $Key -Leaf
    $State.Metadata.Scope = if ($Root -eq 'HKLM') { 'machine' } elseif ($Root -eq 'HKCU') { 'user' } else { $State.Metadata.Scope }
    $State.Metadata.RegistryValues[$Name] = $Value
    $State.Metadata.WritesAppsAndFeaturesEntry = $true

    switch ($Name) {
      'DisplayName' { $State.Metadata.DisplayName = $Value }
      'DisplayVersion' { $State.Metadata.DisplayVersion = $Value }
      'Publisher' { $State.Metadata.Publisher = $Value }
      'InstallLocation' { $State.Metadata.DefaultInstallLocation = $Value.Trim('"') }
      'UninstallString' { $State.Metadata.UninstallString = $Value }
      'QuietUninstallString' { $State.Metadata.QuietUninstallString = $Value }
      'DisplayIcon' { $State.Metadata.DisplayIcon = $Value }
      'SystemComponent' {
        $State.Metadata.SystemComponent = $Value
        if ($Value -eq '1' -or $Value -eq '0x00000001') { $State.Metadata.WritesAppsAndFeaturesEntry = $false }
      }
      default { }
    }
  }
}

function Get-NSISRegistryWriteFromEntry {
  <#
  .SYNOPSIS
    Convert a normalized EW_WRITEREG command into explicit registry-write evidence
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Entry
    The normalized NSIS command entry
  .PARAMETER EntryIndex
    Optional command index used to resolve nearby StrCpy assignments during a direct scan
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The normalized NSIS command entry')]
    [pscustomobject]$Entry,

    [Parameter(HelpMessage = 'The command index used for direct lexical data-flow')]
    [int]$EntryIndex = -1
  )

  if ($Entry.Opcode -ne $Script:NSIS_OPCODE_WRITE_REG) { return $null }

  # EW_WRITEREG operand positions differ for NSISBI's expanded records. Decode
  # type fields from the detected layout instead of the obsolete fake opcode map.
  $IsNsisBi = $State.VersionInfo.PSObject.Properties.Name -contains 'IsNsisBi' -and $State.VersionInfo.IsNsisBi
  $TypeIndex = if ($IsNsisBi) { 6 } else { 5 }
  $RegistryTypeIndex = if ($IsNsisBi) { 7 } else { 6 }
  $Type = [uint32]$Entry.Raw[$TypeIndex]
  $RegistryType = [uint32]$Entry.Raw[$RegistryTypeIndex]
  $RegistryKind = switch ($Type) {
    $Script:NSIS_REG_TYPE_DWORD { 'REG_DWORD'; break }
    $Script:NSIS_REG_TYPE_EXPAND_STRING { 'REG_EXPAND_SZ'; break }
    $Script:NSIS_REG_TYPE_STRING {
      if ($RegistryType -eq $Script:NSIS_REG_TYPE_EXPAND_STRING) { 'REG_EXPAND_SZ' } else { 'REG_SZ' }
      break
    }
    default {
      switch ($RegistryType) {
        $Script:NSIS_REG_TYPE_DWORD { 'REG_DWORD'; break }
        $Script:NSIS_REG_TYPE_EXPAND_STRING { 'REG_EXPAND_SZ'; break }
        default { 'REG_SZ' }
      }
    }
  }

  # String operands pass through the NSIS string decoder so variable and language
  # references resolve using the same state as simulated execution.
  $Root = Resolve-NSISRegistryRoot -State $State -Root $Entry.Raw[1]
  $Key = if ($EntryIndex -ge 0) {
    Resolve-NSISDirectString -State $State -RelativeOffset $Entry.Values[2] -EntryIndex $EntryIndex
  } else {
    Get-NSISString -State $State -RelativeOffset $Entry.Values[2]
  }
  $Name = if ($EntryIndex -ge 0) {
    Resolve-NSISDirectString -State $State -RelativeOffset $Entry.Values[3] -EntryIndex $EntryIndex
  } else {
    Get-NSISString -State $State -RelativeOffset $Entry.Values[3]
  }
  $Value = if ($RegistryKind -eq 'REG_DWORD') {
    [string](Get-NSISInt -State $State -RelativeOffset $Entry.Values[4])
  } elseif ($EntryIndex -ge 0) {
    Resolve-NSISDirectString -State $State -RelativeOffset $Entry.Values[4] -EntryIndex $EntryIndex
  } else {
    Get-NSISString -State $State -RelativeOffset $Entry.Values[4]
  }

  return [pscustomobject]@{
    Root           = $Root
    Key            = $Key
    Name           = $Name
    Value          = $Value
    Type           = $RegistryKind
    RawType        = $Type
    RegistryType   = $RegistryType
    IsUninstallKey = $Key -match $Script:NSIS_UNINSTALL_KEY_PATTERN
    Opcode         = $Entry.Opcode
    RawOpcode      = $Entry.RawOpcode
  }
}

function Add-NSISRegistryWrite {
  <#
  .SYNOPSIS
    Store source-accurate EW_WRITEREG evidence and apply it to simulated registry state
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Entry
    The normalized NSIS command entry
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The normalized NSIS command entry')]
    [pscustomobject]$Entry
  )

  $Write = Get-NSISRegistryWriteFromEntry -State $State -Entry $Entry
  if (-not $Write) { return }

  $State.RegistryWrites.Add($Write)
  Set-NSISRegistryValue -State $State -Root $Write.Root -Key $Write.Key -Name $Write.Name -Value $Write.Value
}

function Add-NSISExecutedPayload {
  <#
  .SYNOPSIS
    Record static evidence that NSIS runs a nested payload
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Command
    The executed command or file
  .PARAMETER Parameters
    Optional command-line parameters
  .PARAMETER Kind
    The NSIS execution command kind
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The executed command or file')]
    [string]$Command,

    [AllowEmptyString()]
    [Parameter(HelpMessage = 'Optional command-line parameters')]
    [string]$Parameters = '',

    [Parameter(Mandatory, HelpMessage = 'The NSIS execution command kind')]
    [string]$Kind
  )

  if ([string]::IsNullOrWhiteSpace($Command)) { return }
  $State.ExecutedPayloads.Add([pscustomobject]@{
      Kind       = $Kind
      Command    = $Command
      Parameters = $Parameters
    })
}

function Get-NSISRegistryValue {
  <#
  .SYNOPSIS
    Read a value from the simulated NSIS registry
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Root
    The registry root
  .PARAMETER Key
    The registry key path
  .PARAMETER Name
    The registry value name
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The registry root')]
    [string]$Root,

    [Parameter(Mandatory, HelpMessage = 'The registry key path')]
    [string]$Key,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The registry value name')]
    [string]$Name
  )

  if ($State.Registry.ContainsKey($Root) -and $State.Registry[$Root].ContainsKey($Key) -and $State.Registry[$Root][$Key].ContainsKey($Name)) {
    return [string]$State.Registry[$Root][$Key][$Name]
  }

  return ''
}

function Remove-NSISRegistryValue {
  <#
  .SYNOPSIS
    Remove a value or key from the simulated NSIS registry
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Root
    The registry root
  .PARAMETER Key
    The registry key path
  .PARAMETER Name
    The registry value name, or an empty string to remove the whole key
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The registry root')]
    [string]$Root,

    [Parameter(Mandatory, HelpMessage = 'The registry key path')]
    [string]$Key,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The registry value name, or an empty string to remove the whole key')]
    [string]$Name
  )

  if (-not ($State.Registry.ContainsKey($Root) -and $State.Registry[$Root].ContainsKey($Key))) { return }

  if ([string]::IsNullOrEmpty($Name)) {
    $null = $State.Registry[$Root].Remove($Key)
  } else {
    $null = $State.Registry[$Root][$Key].Remove($Name)
  }
}

function Get-NSISEntries {
  <#
  .SYNOPSIS
    Parse the NSIS opcode table from the decompressed header
  .PARAMETER HeaderBytes
    The decompressed NSIS header bytes
  .PARAMETER BlockHeaders
    The parsed NSIS block headers
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header bytes')]
    [byte[]]$HeaderBytes,

    [Parameter(Mandatory, HelpMessage = 'The parsed NSIS block headers')]
    [pscustomobject[]]$BlockHeaders,

    [Parameter(HelpMessage = 'The detected command layout')]
    [pscustomobject]$VersionInfo,

    [Parameter(HelpMessage = 'Whether the entry table uses eight NSISBI operands')]
    [bool]$IsNsisBi = $false
  )

  # Block 2 is the compiled command table. Its declared count and generation-
  # specific record width must fit before any operand is read.
  $EntryBlock = Get-NSISBlockBytes -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Index 2
  if ($BlockHeaders[2].Count -gt $Script:NSIS_MAX_ENTRY_COUNT) { throw 'The NSIS entry table exceeds the supported parser limit' }
  $EntryCount = [int]$BlockHeaders[2].Count
  $EntrySize = if ($IsNsisBi) { $Script:NSISBI_ENTRY_SIZE } else { $Script:NSIS_ENTRY_SIZE }
  $ValueCount = if ($IsNsisBi) { 9 } else { 7 }
  if ($EntryBlock.Length -lt ($EntryCount * $EntrySize)) { throw 'The NSIS entry table is truncated' }

  $Entries = [System.Collections.Generic.List[object]]::new()

  for ($EntryIndex = 0; $EntryIndex -lt $EntryCount; $EntryIndex++) {
    $Offset = $EntryIndex * $EntrySize
    $Raw = New-Object 'uint32[]' $ValueCount
    $Values = New-Object 'int[]' $ValueCount

    for ($ValueIndex = 0; $ValueIndex -lt $ValueCount; $ValueIndex++) {
      $ValueOffset = $Offset + ($ValueIndex * 4)
      $Raw[$ValueIndex] = [System.BitConverter]::ToUInt32($EntryBlock, $ValueOffset)
      $Values[$ValueIndex] = [System.BitConverter]::ToInt32($EntryBlock, $ValueOffset)
    }

    # Retain raw operands for source-accurate registry decoding while exposing a
    # normalized opcode for the static simulator.
    $LayoutOpcode = if ($IsNsisBi) { ConvertFrom-NSISBiOpcode -Opcode $Raw[0] } else { [int]$Raw[0] }
    $Opcode = if ($VersionInfo) {
      Get-NSISNormalizedOpcode -Opcode $LayoutOpcode -Type $VersionInfo.Type -Unicode $VersionInfo.Unicode -LogCmdIsEnabled $VersionInfo.LogCmdIsEnabled
    } else {
      $LayoutOpcode
    }

    $Entries.Add([pscustomobject]@{
        Opcode       = $Opcode
        RawOpcode    = $Raw[0]
        LayoutOpcode = $LayoutOpcode
        Raw          = $Raw
        Values       = $Values
      })
  }

  return $Entries.ToArray()
}

function Get-NSISSections {
  <#
  .SYNOPSIS
    Parse the NSIS section table so install sections can be simulated in order
  .PARAMETER HeaderBytes
    The decompressed NSIS header bytes
  .PARAMETER BlockHeaders
    The parsed NSIS block headers
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header bytes')]
    [byte[]]$HeaderBytes,

    [Parameter(Mandatory, HelpMessage = 'The parsed NSIS block headers')]
    [pscustomobject[]]$BlockHeaders
  )

  $SectionBlock = Get-NSISBlockBytes -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Index 1
  $SectionCount = [int]$BlockHeaders[1].Count
  if ($SectionCount -eq 0 -or $SectionBlock.Length -eq 0) { return @() }

  $SectionSize = [int]($SectionBlock.Length / $SectionCount)
  $Sections = [System.Collections.Generic.List[object]]::new()

  for ($SectionIndex = 0; $SectionIndex -lt $SectionCount; $SectionIndex++) {
    $Offset = $SectionIndex * $SectionSize
    $Sections.Add([pscustomobject]@{
        NameOffset = [System.BitConverter]::ToInt32($SectionBlock, $Offset + $Script:NSIS_SECTION_OFFSET_NAME)
        CodeOffset = [System.BitConverter]::ToInt32($SectionBlock, $Offset + $Script:NSIS_SECTION_OFFSET_CODE)
      })
  }

  return $Sections.ToArray()
}

function Initialize-NSISState {
  <#
  .SYNOPSIS
    Build the mutable execution state used for deterministic NSIS metadata parsing
  .PARAMETER HeaderData
    The decompressed NSIS header data
  .PARAMETER Architecture
    The target Windows architecture used to resolve source-backed runtime architecture checks
  .PARAMETER Scope
    The target installation scope used to resolve compiled MultiUser scope setters
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header data')]
    [pscustomobject]$HeaderData,

    [Parameter(HelpMessage = 'The target Windows architecture used to resolve runtime architecture checks')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [Parameter(HelpMessage = 'The target installation scope used to resolve runtime scope checks')]
    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  $HeaderBytes = $HeaderData.HeaderBytes
  $BlockHeaders = Get-NSISBlockHeaders -HeaderBytes $HeaderBytes -Is64Bit $HeaderData.PEInfo.Is64Bit
  $Layout = Get-NSISHeaderLayout -HeaderBytes $HeaderBytes -Is64Bit $HeaderData.PEInfo.Is64Bit
  $StringsBlock = Get-NSISBlockBytes -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Index 3
  $LanguageTables = @(Get-NSISLanguageTable -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Layout $Layout)
  $LanguageTable = @($LanguageTables.Where({ $_.LanguageId -eq $Script:NSIS_DEFAULT_LANGUAGE }, 'First'))[0]
  if (-not $LanguageTable) { $LanguageTable = $LanguageTables | Select-Object -First 1 }
  $Entries = Get-NSISEntries -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -IsNsisBi $HeaderData.IsNsisBi
  $VersionInfo = Get-NSISVersionInfo -StringsBlock $StringsBlock -Entries $Entries -IsNsisBi $HeaderData.IsNsisBi
  $VersionInfo | Add-Member -NotePropertyName FirstHeaderFlags -NotePropertyValue $HeaderData.FirstHeaderFlags
  $VersionInfo | Add-Member -NotePropertyName HasLongDataBlockOffsets -NotePropertyValue $HeaderData.HasLongDataBlockOffsets
  $VersionInfo | Add-Member -NotePropertyName HasLargeFileSource -NotePropertyValue $HeaderData.HasLargeFileSource
  $VersionInfo | Add-Member -NotePropertyName SupportsExternalFiles -NotePropertyValue $HeaderData.SupportsExternalFiles
  $VersionInfo | Add-Member -NotePropertyName HasExternalFile -NotePropertyValue $HeaderData.HasExternalFile
  $VersionInfo | Add-Member -NotePropertyName IsStubInstaller -NotePropertyValue $HeaderData.IsStubInstaller
  foreach ($Entry in $Entries) {
    $Entry.Opcode = Get-NSISNormalizedOpcode -Opcode $Entry.LayoutOpcode -Type $VersionInfo.Type -Unicode $VersionInfo.Unicode -LogCmdIsEnabled $VersionInfo.LogCmdIsEnabled
  }

  $State = [pscustomobject]@{
    Path                = $HeaderData.Path
    Entries             = $Entries
    Sections            = Get-NSISSections -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders
    StringsBlock        = $StringsBlock
    LanguageTable       = $LanguageTable
    LanguageTables      = $LanguageTables
    VersionInfo         = $VersionInfo
    Variables           = @{}
    Registry            = @{}
    RegistryWrites      = [System.Collections.Generic.List[object]]::new()
    ExecutedPayloads    = [System.Collections.Generic.List[object]]::new()
    Warnings            = [System.Collections.Generic.List[string]]::new()
    Stack               = [System.Collections.Generic.List[string]]::new()
    SystemVariableStack = [System.Collections.Generic.List[object]]::new()
    Directories         = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Files               = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    ExecFlags           = @{}
    LastExecFlags       = @{}
    ShellVarContext     = $null
    TargetArchitecture  = $Architecture
    TargetScope         = $Scope
    Metadata            = [ordered]@{
      Path                               = $HeaderData.Path
      InstallerType                      = 'Nullsoft'
      TargetArchitecture                 = $Architecture
      HasArchitectureRuntimeCheck        = $false
      TargetScope                        = $Scope
      HasScopeRuntimeCheck               = $false
      SupportedScopes                    = [string[]]@()
      RequestedExecutionLevel            = $null
      IsTauri                            = $false
      TauriInstallerMode                 = $null
      TauriEvidence                      = [string[]]@()
      IsPortable                         = $false
      PortableEvidence                   = [string[]]@()
      ProductCode                        = $null
      UpgradeCode                        = $null
      DisplayName                        = $null
      DisplayVersion                     = $null
      Publisher                          = $null
      Scope                              = $null
      DefaultInstallLocation             = $null
      WritesAppsAndFeaturesEntry         = $false
      AppsAndFeaturesProductCode         = $null
      AppsAndFeaturesInstallerType       = $null
      Warnings                           = [string[]]@()
      UnresolvedFields                   = [string[]]@()
      UninstallString                    = $null
      QuietUninstallString               = $null
      DisplayIcon                        = $null
      SystemComponent                    = $null
      RegistryValues                     = @{}
      RegistryWrites                     = @()
      AppsAndFeaturesEntries             = @()
      AppsAndFeaturesEntryEvidence       = @()
      HasLocalizedAppsAndFeaturesEntries = $false
      Notices                            = [string[]]@()
      ExtractedFiles                     = @()
      ExecutedPayloads                   = @()
      ParserVersionInfo                  = $null
    }
  }

  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_EXEPATH -Value $HeaderData.Path
  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_EXEDIR -Value (Split-Path -Path $HeaderData.Path -Parent)
  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_EXEFILE -Value (Split-Path -Path $HeaderData.Path -Leaf)
  $LanguageId = if ($LanguageTable) { $LanguageTable.LanguageId } else { $Script:NSIS_DEFAULT_LANGUAGE }
  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_LANGUAGE -Value ([string]$LanguageId)
  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_TEMP -Value ([System.IO.Path]::GetTempPath().TrimEnd('\'))

  if ($HeaderData.IsNsisBi) {
    $State.Warnings.Add('The installer uses the NSISBI large-installer format; metadata was parsed from its expanded first-header and command layouts.')
  }
  if ($HeaderData.HasExternalFile) {
    $State.Warnings.Add('The NSISBI installer references an external payload file; embedded script metadata is available, but payload evidence may be incomplete without the sidecar file.')
  }

  # InstallDir and its auto-append suffix are stored as header pointers instead of script directives.
  if ($Layout.InstallDirectoryPointer -ne 0) {
    $InstallDirectory = Get-NSISString -State $State -RelativeOffset $Layout.InstallDirectoryPointer
    $AutoAppend = if ($Layout.InstallDirectoryAutoAppend -ne 0) { Get-NSISString -State $State -RelativeOffset $Layout.InstallDirectoryAutoAppend } else { '' }

    if (-not [string]::IsNullOrWhiteSpace($AutoAppend) -and -not $InstallDirectory.EndsWith($AutoAppend, [System.StringComparison]::OrdinalIgnoreCase)) {
      $InstallDirectory = Join-Path $InstallDirectory $AutoAppend
    }

    Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_INSTDIR -Value $InstallDirectory
    Add-NSISDirectory -State $State -Path $InstallDirectory
  }

  return [pscustomobject]@{
    State        = $State
    Layout       = $Layout
    BlockHeaders = $BlockHeaders
  }
}

function Pop-NSISStackValue {
  <#
  .SYNOPSIS
    Remove and return the value at the top of the simulated NSIS stack
  .PARAMETER State
    The mutable NSIS execution state that owns the stack
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  if ($State.Stack.Count -eq 0) { return '' }
  $Index = $State.Stack.Count - 1
  $Value = [string]$State.Stack[$Index]
  $State.Stack.RemoveAt($Index)
  return $Value
}

function Get-NSISNativeMachineValue {
  <#
  .SYNOPSIS
    Convert a WinGet architecture into the IMAGE_FILE_MACHINE value returned by Windows
  .PARAMETER Architecture
    The target Windows architecture
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The target Windows architecture')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  switch ($Architecture) {
    'x86' { return $Script:NSIS_IMAGE_FILE_MACHINE_I386 }
    'x64' { return $Script:NSIS_IMAGE_FILE_MACHINE_AMD64 }
    'arm64' { return $Script:NSIS_IMAGE_FILE_MACHINE_ARM64 }
  }
}

function Resolve-NSISKnownFolderPath {
  <#
  .SYNOPSIS
    Resolve a compiled Windows known-folder identifier without querying the parser host shell
  .DESCRIPTION
    NSIS 3 GetKnownFolderPath and older System plug-in macros carry the same
    canonical GUID. Only installer-related folders derived from stable Windows
    environment roots are resolved. Redirectable content folders such as
    Desktop, Documents, and Downloads remain unresolved because synthesizing
    them below the parser host's profile would contradict the target machine's
    SHGetKnownFolderPath result. Unknown identifiers return an empty string,
    matching the NSIS runtime's failed-call destination.
  .PARAMETER FolderId
    The brace-delimited known-folder GUID compiled into the NSIS string table
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The brace-delimited Windows known-folder GUID')]
    [string]$FolderId
  )

  $ParsedFolderId = [guid]::Empty
  if (-not [guid]::TryParse($FolderId, [ref]$ParsedFolderId)) { return '' }
  $CanonicalFolderId = $ParsedFolderId.ToString('B').ToUpperInvariant()

  # Resolve from well-known environment roots so paths are deterministic and
  # ConvertTo-NSISManifestPath can normalize them without retaining a username
  # or drive letter. Do not call SHGetKnownFolderPath on the parser host.
  $WindowsDirectory = $Script:NSIS_WINDOWS_DIRECTORY
  $SystemDirectory = $Script:NSIS_SYSTEM_DIRECTORY
  $SystemX86Directory = if ([Environment]::Is64BitOperatingSystem) { Join-Path $WindowsDirectory 'SysWOW64' } else { $SystemDirectory }
  $ProgramFiles64 = if (${env:ProgramW6432}) { ${env:ProgramW6432} } else { $env:ProgramFiles }
  $ProgramFilesX86 = if (${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} } else { $ProgramFiles64 }
  $CommonProgramFiles64 = if (${env:CommonProgramW6432}) { ${env:CommonProgramW6432} } else { $env:CommonProgramFiles }
  $CommonProgramFilesX86 = if (${env:CommonProgramFiles(x86)}) { ${env:CommonProgramFiles(x86)} } else { $CommonProgramFiles64 }
  $UserStartMenu = if ($env:APPDATA) { Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu' } else { $null }
  $CommonStartMenu = if ($env:ProgramData) { Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu' } else { $null }

  switch ($CanonicalFolderId) {
    # Application-data and machine-data roots.
    '{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}' { return [string]$env:LOCALAPPDATA } # FOLDERID_LocalAppData
    '{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}' { return [string]$env:APPDATA } # FOLDERID_RoamingAppData
    '{A520A1A4-1780-4FF6-BD18-167343C5AF16}' { return $(if ($env:USERPROFILE) { Join-Path $env:USERPROFILE 'AppData\LocalLow' } else { '' }) } # FOLDERID_LocalAppDataLow
    '{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}' { return [string]$env:ProgramData } # FOLDERID_ProgramData
    '{5E6C858F-0E22-4760-9AFE-EA3317B67173}' { return [string]$env:USERPROFILE } # FOLDERID_Profile

    # Windows and system roots.
    '{F38BF404-1D43-42F2-9305-67DE0B28FC23}' { return $WindowsDirectory } # FOLDERID_Windows
    '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}' { return $SystemDirectory } # FOLDERID_System
    '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}' { return $SystemX86Directory } # FOLDERID_SystemX86
    '{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}' { return Join-Path $WindowsDirectory 'Fonts' } # FOLDERID_Fonts

    # Program Files and Common Files variants. Generic IDs use the native
    # Program Files roots, while explicit X86/X64 IDs retain their bitness.
    '{905E63B6-C1BF-494E-B29C-65B732D3D21A}' { return [string]$ProgramFiles64 } # FOLDERID_ProgramFiles
    '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}' { return [string]$ProgramFilesX86 } # FOLDERID_ProgramFilesX86
    '{6D809377-6AF0-444B-8957-A3773F02200E}' { return [string]$ProgramFiles64 } # FOLDERID_ProgramFilesX64
    '{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}' { return [string]$CommonProgramFiles64 } # FOLDERID_ProgramFilesCommon
    '{DE974D24-D9C6-4D3E-BF91-F4455120B917}' { return [string]$CommonProgramFilesX86 } # FOLDERID_ProgramFilesCommonX86
    '{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}' { return [string]$CommonProgramFiles64 } # FOLDERID_ProgramFilesCommonX64
    $Script:NSIS_FOLDER_ID_USER_PROGRAM_FILES { return $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Programs' } else { '' }) }
    '{BCBD3057-CA5C-4622-B42D-BC56DB0AE516}' { return $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Programs\Common' } else { '' }) } # FOLDERID_UserProgramFilesCommon

    # Per-user Start Menu folders.
    '{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}' { return [string]$UserStartMenu } # FOLDERID_StartMenu
    '{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}' { return $(if ($UserStartMenu) { Join-Path $UserStartMenu 'Programs' } else { '' }) } # FOLDERID_Programs
    '{B97D20BB-F46A-4C97-BA10-5E3608430854}' { return $(if ($UserStartMenu) { Join-Path $UserStartMenu 'Programs\Startup' } else { '' }) } # FOLDERID_Startup
    '{724EF170-A42D-4FEF-9F26-B60E846FBA4F}' { return $(if ($UserStartMenu) { Join-Path $UserStartMenu 'Programs\Administrative Tools' } else { '' }) } # FOLDERID_AdminTools

    # All-users Start Menu folders.
    '{A4115719-D62E-491D-AA7C-E74B8BE3B067}' { return [string]$CommonStartMenu } # FOLDERID_CommonStartMenu
    '{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}' { return $(if ($CommonStartMenu) { Join-Path $CommonStartMenu 'Programs' } else { '' }) } # FOLDERID_CommonPrograms
    '{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}' { return $(if ($CommonStartMenu) { Join-Path $CommonStartMenu 'Programs\Startup' } else { '' }) } # FOLDERID_CommonStartup
    '{D0384E7D-BAC3-4797-8F14-CBA229B392B5}' { return $(if ($CommonStartMenu) { Join-Path $CommonStartMenu 'Programs\Administrative Tools' } else { '' }) } # FOLDERID_CommonAdminTools
    default { return '' }
  }
}

function Get-NSISOsInfoMemoryValue {
  <#
  .SYNOPSIS
    Resolve source-generated GetWinVer reads from the NSIS runtime ABI block
  .DESCRIPTION
    NSIS compiles GetWinVer to EW_GETOSINFO/READMEMORY against an eight-byte
    osinfo record following fourteen 32-bit execution flags. Dumplings models
    the Windows 10 1809 baseline supported by WinGet instead of leaking the
    parser host's OS version into static installer control flow. Arbitrary
    ReadMemory addresses and unrecognized byte ranges remain unresolved.
  .PARAMETER Address
    The compiled source address; zero is NSIS ABI_OSINFOADDRESS
  .PARAMETER Specification
    Packed byte count in bits 0..7 and osinfo byte offset in bits 24..31
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The compiled memory address')]
    [long]$Address,

    [Parameter(Mandatory, HelpMessage = 'The packed byte-count and osinfo offset')]
    [uint32]$Specification
  )

  if ($Address -ne 0) { return $null }
  $ByteCount = [int]($Specification -band 0xFF)
  $FieldOffset = [int]($Specification -shr 24) - $Script:NSIS_ABI_OS_INFO_OFFSET

  # This mirrors little-endian mini_memcpy from NSIS exec.c. The two-byte
  # major/minor form starts at WVMin, so major occupies the high byte.
  switch ("$FieldOffset`:$ByteCount") {
    '0:4' { return [string]$Script:NSIS_TARGET_WINDOWS_BUILD }
    '4:1' { return [string]$Script:NSIS_TARGET_WINDOWS_PRODUCT }
    '5:1' { return [string]$Script:NSIS_TARGET_WINDOWS_SERVICE_PACK }
    '6:1' { return [string]$Script:NSIS_TARGET_WINDOWS_MINOR }
    '7:1' { return [string]$Script:NSIS_TARGET_WINDOWS_MAJOR }
    '6:2' { return [string](($Script:NSIS_TARGET_WINDOWS_MAJOR -shl 8) -bor $Script:NSIS_TARGET_WINDOWS_MINOR) }
    default { return $null }
  }
}

function Invoke-NSISSystemPluginCall {
  <#
  .SYNOPSIS
    Simulate deterministic NSIS System plug-in operations used by installer scripts
  .DESCRIPTION
    NSIS compiles System::Call arguments as stack pushes followed by EW_REGISTERDLL.
    This helper consumes those arguments where the plug-in would and models the
    known-folder and Windows architecture APIs used by electron-builder and
    x64.nsh. System::Store is also modeled because electron-builder protects
    its temporary registers around the legacy Windows 7 known-folder path.
    Other calls receive empty outputs rather than values derived from the
    parser host.
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER FunctionName
    The exported System plug-in function invoked by EW_REGISTERDLL
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The exported System plug-in function')]
    [string]$FunctionName
  )

  if ($FunctionName -ieq 'Int64Op') {
    # System::Int64Op pops ARG1, OP, and ARG2, then pushes one result. x64.nsh
    # uses bitwise OR to combine IsWow64Process2 with its legacy fallback.
    $LeftText = Pop-NSISStackValue -State $State
    $Operator = Pop-NSISStackValue -State $State
    $RightText = if ($Operator -in @('~', '!')) { '0' } else { Pop-NSISStackValue -State $State }
    $Left = 0L
    $Right = 0L
    $null = [long]::TryParse($LeftText, [ref]$Left)
    $null = [long]::TryParse($RightText, [ref]$Right)
    $Result = switch ($Operator) {
      '|' { $Left -bor $Right }
      '||' { [long]($Left -ne 0 -or $Right -ne 0) }
      default { 0L }
    }
    $State.Stack.Add([string]$Result)
    return $true
  }

  if ($FunctionName -ieq 'Store') {
    # System::Store consumes a compact operation string. S/L save and restore
    # all general registers on the plug-in's private stack; p/r transfer one
    # numbered register through the ordinary NSIS stack. This follows
    # Contrib/System/Source/Buffers.c instead of treating Store as a no-op.
    $Command = Pop-NSISStackValue -State $State
    if (-not $State.PSObject.Properties['SystemVariableStack']) {
      $State | Add-Member -NotePropertyName SystemVariableStack -NotePropertyValue ([System.Collections.Generic.List[object]]::new())
    }

    for ($Index = 0; $Index -lt $Command.Length; $Index++) {
      switch -CaseSensitive ($Command[$Index]) {
        { $_ -in @('s', 'S') } {
          $Snapshot = [string[]]::new(20)
          for ($RegisterIndex = 0; $RegisterIndex -lt $Snapshot.Length; $RegisterIndex++) {
            $Snapshot[$RegisterIndex] = Get-NSISVariableValue -State $State -Index $RegisterIndex
          }
          $State.SystemVariableStack.Add($Snapshot)
        }
        { $_ -in @('l', 'L') } {
          if ($State.SystemVariableStack.Count -eq 0) { continue }
          $SnapshotIndex = $State.SystemVariableStack.Count - 1
          $Snapshot = $State.SystemVariableStack[$SnapshotIndex]
          $State.SystemVariableStack.RemoveAt($SnapshotIndex)
          for ($RegisterIndex = 0; $RegisterIndex -lt 20; $RegisterIndex++) {
            # These indexes are exactly $0-$9 and $R0-$R9, so restoring them
            # cannot alter predefined paths such as $INSTDIR or $OUTDIR.
            $State.Variables[$RegisterIndex] = [string]$Snapshot[$RegisterIndex]
          }
        }
        { $_ -in @('p', 'P') } {
          if ($Index + 1 -ge $Command.Length -or -not [char]::IsDigit($Command[$Index + 1])) { continue }
          $RegisterIndex = [int][char]::GetNumericValue($Command[++$Index])
          if ($_ -ceq 'P') { $RegisterIndex += 10 }
          $State.Stack.Add((Get-NSISVariableValue -State $State -Index $RegisterIndex))
        }
        { $_ -in @('r', 'R') } {
          if ($Index + 1 -ge $Command.Length -or -not [char]::IsDigit($Command[$Index + 1])) { continue }
          $RegisterIndex = [int][char]::GetNumericValue($Command[++$Index])
          if ($_ -ceq 'R') { $RegisterIndex += 10 }
          Set-NSISVariableValue -State $State -Index $RegisterIndex -Value (Pop-NSISStackValue -State $State)
        }
      }
    }
    return $true
  }

  if ($FunctionName -ine 'Call') { return $false }
  $Command = Pop-NSISStackValue -State $State
  if ([string]::IsNullOrWhiteSpace($Command)) { return $true }

  if ($Command -match '(?i)SHELL32::SHGetKnownFolderPath\(g\s+"?(?<FolderId>\{[0-9A-F-]{36}\})"?.*\*p\s+\.r(?<PathRegister>\d+)\)i\.r(?<ResultRegister>\d+)') {
    # electron-builder resolves FOLDERID_UserProgramFiles and copies the
    # allocated result into its per-user installation root. The System plug-in
    # writes both values directly to NSIS variables; neither value is pushed.
    $KnownFolderPath = Resolve-NSISKnownFolderPath -FolderId $Matches.FolderId
    Set-NSISVariableValue -State $State -Index ([int]$Matches.PathRegister) -Value $KnownFolderPath
    Set-NSISVariableValue -State $State -Index ([int]$Matches.ResultRegister) -Value $(if ($KnownFolderPath) { '0' } else { '-2147024894' })
    return $true
  }

  if ($Command -match '(?i)KERNEL32::lstrcpynW\(w\s+\.r(?<DestinationRegister>\d+)\s*,\s*p\s+r(?<SourceRegister>\d+)') {
    # lstrcpynW writes into the destination buffer represented by the direct
    # NSIS register operand. Copy the deterministic source value without
    # attempting to model the transient native pointer.
    $SourceValue = Get-NSISVariableValue -State $State -Index ([int]$Matches.SourceRegister)
    Set-NSISVariableValue -State $State -Index ([int]$Matches.DestinationRegister) -Value $SourceValue
    return $true
  }

  if ($Command -match '(?i)OLE32::CoTaskMemFree\(') {
    # The allocation belongs to the simulated shell call; freeing it has no
    # additional script-visible output.
    return $true
  }

  if ($Command -match '(?i)kernel32::GetCurrentProcess\(\)p\.s') {
    # The pseudo handle is only consumed by later static API emulation.
    $State.Stack.Add('-1')
    return $true
  }

  if ($Command -match '(?i)kernel32::IsWow64Process2\((?<Arguments>[^)]*)\)') {
    # Architecture-dependent calls need an explicit target. Keep the stack
    # contract deterministic when the caller requested architecture-neutral
    # metadata, but do not derive the result from the parser host.
    $Architecture = [string]$State.TargetArchitecture
    $NativeMachine = if ($Architecture) { Get-NSISNativeMachineValue -Architecture $Architecture } else { 0 }
    $Arguments = @($Matches.Arguments -split '\s*,\s*')
    if ($Arguments.Count -gt 0 -and $Arguments[0] -match '(?i)^ps$') {
      $null = Pop-NSISStackValue -State $State
    }

    # A 32-bit stub reports I386 as its process machine on x64/ARM64 and zero
    # when it runs natively on x86. The second output is the native OS machine.
    $ProcessMachine = if ($Architecture -eq 'x86') { 0 } else { $Script:NSIS_IMAGE_FILE_MACHINE_I386 }
    for ($Index = 1; $Index -lt $Arguments.Count; $Index++) {
      if ($Arguments[$Index] -notmatch '(?i)^\*[^,]*s$') { continue }
      $OutputMachine = if ($Index -eq 1) { $ProcessMachine } else { $NativeMachine }
      $State.Stack.Add([string]$OutputMachine)
    }
    return $true
  }

  if ($Command -match '(?i)kernel32::IsWow64Process\((?<Arguments>[^)]*)\)') {
    $Architecture = [string]$State.TargetArchitecture
    $Arguments = @($Matches.Arguments -split '\s*,\s*')
    if ($Arguments.Count -gt 0 -and $Arguments[0] -match '(?i)^ps$') {
      $null = Pop-NSISStackValue -State $State
    }

    # The legacy API returns FALSE for native x86 and for x86 emulation on
    # ARM64. Current x64.nsh combines it with IsWow64Process2 on ARM64.
    $IsWow64 = [int]($Architecture -eq 'x64')
    foreach ($Argument in $Arguments | Select-Object -Skip 1) {
      if ($Argument -match '(?i)^\*[^,]*s$') { $State.Stack.Add([string]$IsWow64) }
    }
    return $true
  }

  if ($Command -match '(?i)^\*0x7FFE002E\(&i2\.s\)') {
    # GetNativeMachineArchitecture reads this shared-user-data processor field
    # as the fallback on Windows versions predating IsWow64Process2.
    $Architecture = [string]$State.TargetArchitecture
    $NativeMachine = if ($Architecture) { Get-NSISNativeMachineValue -Architecture $Architecture } else { 0 }
    $State.Stack.Add([string]$NativeMachine)
    return $true
  }

  # Consume unsupported System::Call input like the real plug-in. Direct .rN
  # outputs write variables, whereas .s outputs are pushed onto the NSIS stack.
  # Preserve those contracts without fabricating values from the parser host.
  foreach ($RegisterMatch in [regex]::Matches($Command, '(?i)\.r(?<Register>\d+)')) {
    Set-NSISVariableValue -State $State -Index ([int]$RegisterMatch.Groups['Register'].Value) -Value ''
  }
  if ($Command -match '\((?<Arguments>[^)]*)\)') {
    foreach ($Argument in @($Matches.Arguments -split '\s*,\s*')) {
      if ($Argument -match '(?i)^\*[^,]*s$') { $State.Stack.Add('') }
    }
  }
  if ($Command -match '(?i)\)[a-z0-9&*]+\.s(?:\s|$)') { $State.Stack.Add('') }
  return $true
}

function Get-NSISArchitectureProbeStart {
  <#
  .SYNOPSIS
    Locate the start of a compiled NSIS x64.nsh architecture probe
  .PARAMETER State
    The mutable NSIS execution state containing normalized command entries
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  for ($Index = 0; $Index -lt $State.Entries.Count; $Index++) {
    $Entry = $State.Entries[$Index]
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_PUSH_POP -or $Entry.Values[2] -ne 0) { continue }
    $Command = Get-NSISString -State $State -RelativeOffset $Entry.Values[1]
    if ($Command -notmatch '(?i)kernel32::IsWow64Process2?\(') { continue }

    # x64.nsh first pushes GetCurrentProcess, then invokes one or both WOW64
    # APIs. Start there so the System plug-in stack contract remains intact.
    $MinimumIndex = [Math]::Max(0, $Index - 24)
    for ($Candidate = $Index - 1; $Candidate -ge $MinimumIndex; $Candidate--) {
      $CandidateEntry = $State.Entries[$Candidate]
      if ($CandidateEntry.Opcode -ne $Script:NSIS_OPCODE_PUSH_POP -or $CandidateEntry.Values[2] -ne 0) { continue }
      $CandidateCommand = Get-NSISString -State $State -RelativeOffset $CandidateEntry.Values[1]
      if ($CandidateCommand -match '(?i)kernel32::GetCurrentProcess\(\)') { return $Candidate }
    }
  }

  return -1
}

function Get-NSISScopeSelectionStart {
  <#
  .SYNOPSIS
    Locate a compiled NSIS function that selects one installation scope
  .DESCRIPTION
    NSIS MultiUser templates compile their scope setters to a mode assignment
    followed by SetShellVarContext. Drizin/NsisMultiUser uses AllUsers while
    current electron-builder uses the shorter all value; both use CurrentUser
    for per-user mode. This structural pair is stronger evidence than switch
    text and lets the simulator enter the selected function without modeling
    UAC UI.
  .PARAMETER State
    The mutable NSIS execution state containing normalized command entries
  .PARAMETER Scope
    The scope whose compiled setter should be located
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The installation scope whose compiled setter should be located')]
    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  $ModeNames = if ($Scope -eq 'machine') {
    [string[]]@('AllUsers', 'all')
  } else {
    [string[]]@('CurrentUser')
  }
  $ExpectedContext = if ($Scope -eq 'machine') { 1 } else { 0 }

  for ($Index = 0; $Index -lt $State.Entries.Count; $Index++) {
    $Entry = $State.Entries[$Index]
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_ASSIGN_VAR) { continue }

    try { $AssignedValue = Get-NSISString -State $State -RelativeOffset $Entry.Values[2] } catch { continue }
    if ($ModeNames -cnotcontains $AssignedValue) { continue }

    # Require the nearby shell-context opcode so unrelated variables named
    # AllUsers or CurrentUser cannot become scope-selector false positives.
    $ContextEntry = $null
    for ($Candidate = $Index + 1; $Candidate -le [Math]::Min($Index + 4, $State.Entries.Count - 1); $Candidate++) {
      $CandidateEntry = $State.Entries[$Candidate]
      if ($CandidateEntry.Opcode -ne $Script:NSIS_OPCODE_SET_FLAG -or
        $CandidateEntry.Values[1] -ne $Script:NSIS_EXEC_FLAG_SHELL_VAR_CONTEXT) { continue }
      if ((Get-NSISInt -State $State -RelativeOffset $CandidateEntry.Values[2]) -ne $ExpectedContext) { continue }
      $ContextEntry = $CandidateEntry
      break
    }
    if (-not $ContextEntry) { continue }

    # Include the idempotence comparison at the function entrance when present.
    # Starting there preserves the source macro's normal return behavior.
    if ($Index -ge 2 -and $State.Entries[$Index - 1].Opcode -eq $Script:NSIS_OPCODE_RETURN -and
      $State.Entries[$Index - 2].Opcode -eq $Script:NSIS_OPCODE_STR_CMP) {
      $Comparison = $State.Entries[$Index - 2]
      $Left = Get-NSISString -State $State -RelativeOffset $Comparison.Values[1]
      $Right = Get-NSISString -State $State -RelativeOffset $Comparison.Values[2]
      if ($ModeNames -ccontains $Left -or $ModeNames -ccontains $Right) { return $Index - 2 }
    }

    return $Index
  }

  return -1
}

function Initialize-NSISTargetRegistryState {
  <#
  .SYNOPSIS
    Remove registry evidence collected before an explicit runtime branch is selected
  .DESCRIPTION
    Initialization can visit a default architecture or scope path before the
    caller-requested branch is applied. Clearing only registry-derived metadata
    preserves other initialized variables while preventing alternate ARP entries
    from contaminating the targeted result.
  .PARAMETER State
    The mutable NSIS execution state to reset
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state to reset')]
    [pscustomobject]$State
  )

  $State.Registry.Clear()
  $State.RegistryWrites.Clear()
  foreach ($Name in @('ProductCode', 'DisplayName', 'DisplayVersion', 'Publisher', 'Scope', 'DefaultInstallLocation', 'UninstallString', 'QuietUninstallString', 'DisplayIcon', 'SystemComponent')) {
    $State.Metadata[$Name] = $null
  }
  $State.Metadata.RegistryValues = @{}
  $State.Metadata.WritesAppsAndFeaturesEntry = $false
  $State.Metadata.AppsAndFeaturesProductCode = $null
  $State.Metadata.AppsAndFeaturesInstallerType = $null
  $State.Metadata.AppsAndFeaturesEntries = @()
  $State.Metadata.AppsAndFeaturesEntryEvidence = @()
}

function Add-NSISDirectUninstallWrites {
  <#
  .SYNOPSIS
    Apply direct uninstall registry writes that can be recovered without executing control flow
  .PARAMETER State
    The mutable NSIS execution state
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  for ($EntryIndex = 0; $EntryIndex -lt $State.Entries.Count; $EntryIndex++) {
    $Entry = $State.Entries[$EntryIndex]
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_WRITE_REG) { continue }
    $Write = Get-NSISRegistryWriteFromEntry -State $State -Entry $Entry -EntryIndex $EntryIndex
    if (-not $Write -or -not $Write.IsUninstallKey) { continue }
    $State.RegistryWrites.Add($Write)
    Set-NSISRegistryValue -State $State -Root $Write.Root -Key $Write.Key -Name $Write.Name -Value $Write.Value
  }
}

function Invoke-NSISCodeSegment {
  <#
  .SYNOPSIS
    Simulate a compiled NSIS code segment until it returns
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Position
    The starting entry index
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The starting entry index')]
    [int]$Position
  )

  $Watchdog = 0
  $WatchdogLimit = [Math]::Max($State.Entries.Count * $Script:NSIS_MAX_WATCHDOG_MULTIPLIER, 1)

  # Follow only statically resolvable control flow. Every dispatched instruction
  # consumes watchdog budget so loops and recursive callback patterns fail fast.
  while ($Position -ge 0 -and $Position -lt $State.Entries.Count) {
    $Result = Invoke-NSISEntry -State $State -Entry $State.Entries[$Position]

    if ($Result.Action -eq 'Return' -or $Result.Action -eq 'Quit' -or $Result.Action -eq 'Abort') {
      return $Result.Action
    }

    $ResolvedAddress = Resolve-NSISAddress -State $State -Address $Result.Address
    if ($ResolvedAddress -eq 0) {
      $Position++
    } else {
      $Position = $ResolvedAddress - 1
    }

    $Watchdog++
    if ($Watchdog -gt $WatchdogLimit) { throw 'The NSIS code segment exceeded the static execution watchdog' }
  }

  return 'Return'
}

function Invoke-NSISEntry {
  <#
  .SYNOPSIS
    Simulate one compiled NSIS entry relevant to deterministic metadata parsing
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Entry
    The parsed entry record
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The parsed entry record')]
    [pscustomobject]$Entry
  )

  $Opcode = $Entry.Opcode
  $Values = $Entry.Values
  $Raw = $Entry.Raw

  # Simulate only deterministic state needed for paths, variables, registry
  # writes, and nested execution. UI and unsupported runtime opcodes are no-ops.
  switch ($Opcode) {
    $Script:NSIS_OPCODE_INVALID { return $Script:NSIS_RETURN_RESULT }
    $Script:NSIS_OPCODE_RETURN { return $Script:NSIS_RETURN_RESULT }
    $Script:NSIS_OPCODE_ABORT { return $Script:NSIS_ABORT_RESULT }
    $Script:NSIS_OPCODE_QUIT { return $Script:NSIS_QUIT_RESULT }
    $Script:NSIS_OPCODE_JUMP { return [pscustomobject]@{ Action = 'Continue'; Address = $Values[1] } }
    $Script:NSIS_OPCODE_CALL {
      $Result = Invoke-NSISCodeSegment -State $State -Position ((Resolve-NSISAddress -State $State -Address $Values[1]) - 1)
      if ($Result -eq 'Quit' -or $Result -eq 'Abort') {
        return [pscustomobject]@{ Action = $Result; Address = 0 }
      } else {
        return $Script:NSIS_CONTINUE_RESULT
      }
    }
    $Script:NSIS_OPCODE_CREATE_DIR {
      $Path = Get-NSISString -State $State -RelativeOffset $Values[1]
      Add-NSISDirectory -State $State -Path $Path

      if ($Values[2] -ne 0) {
        Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_OUTDIR -Value $Path
        if ([string]::IsNullOrWhiteSpace((Get-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_INSTDIR))) {
          Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_INSTDIR -Value $Path
        }
      }

      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_IF_FILE_EXISTS {
      $FileName = Get-NSISString -State $State -RelativeOffset $Values[1]
      $Address = if (Test-NSISPathExists -State $State -Path $FileName) { $Values[2] } else { $Values[3] }
      return [pscustomobject]@{ Action = 'Continue'; Address = $Address }
    }
    $Script:NSIS_OPCODE_EXTRACT_FILE {
      $Path = Get-NSISString -State $State -RelativeOffset $Values[2]
      Add-NSISFile -State $State -Path $Path
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_SET_FLAG {
      $FlagType = $Values[1]
      $Value = Get-NSISInt -State $State -RelativeOffset $Values[2]
      $Mode = $Values[3]
      $RestoreControl = $Values[4]

      # Save/restore semantics matter for ShellVarContext and registry-view
      # selection, which determine whether uninstall evidence belongs to HKCU/HKLM.
      if ($Mode -le 0) {
        if ($State.ExecFlags.ContainsKey($FlagType)) {
          $State.LastExecFlags[$FlagType] = $State.ExecFlags[$FlagType]
        }
        $State.ExecFlags[$FlagType] = $Value
      } elseif ($State.LastExecFlags.ContainsKey($FlagType)) {
        $State.ExecFlags[$FlagType] = $State.LastExecFlags[$FlagType]
      }

      if ($FlagType -eq $Script:NSIS_EXEC_FLAG_SHELL_VAR_CONTEXT) {
        $ShellVarContextValue = if ($State.ExecFlags.ContainsKey($FlagType)) { $State.ExecFlags[$FlagType] } else { 0 }
        $State.ShellVarContext = if ($ShellVarContextValue -eq 0) { 'HKCU' } else { 'HKLM' }
      }

      if ($FlagType -eq $Script:NSIS_EXEC_FLAG_REG_VIEW -and $RestoreControl -lt 0 -and -not $State.ExecFlags.ContainsKey($FlagType)) {
        $State.ExecFlags[$FlagType] = $Value
      }

      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_IF_FLAG {
      $FlagValue = if ($State.ExecFlags.ContainsKey($Values[3])) { $State.ExecFlags[$Values[3]] } else { 0 }
      return [pscustomobject]@{ Action = 'Continue'; Address = if ($FlagValue -ne 0) { $Values[1] } else { $Values[2] } }
    }
    $Script:NSIS_OPCODE_GET_FLAG {
      $FlagValue = if ($State.ExecFlags.ContainsKey($Values[2])) { $State.ExecFlags[$Values[2]] } else { 0 }
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ([string]$FlagValue)
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_STR_LEN {
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ([string](Get-NSISString -State $State -RelativeOffset $Values[2]).Length)
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_ASSIGN_VAR {
      # EW_ASSIGNVAR stores MaxLen and StartOffset as string-table operands, not
      # immediate integers. This mirrors GetIntFromParmEx(2)/GetIntFromParm(3)
      # in the NSIS runtime, including negative lengths and start positions.
      $Result = Get-NSISString -State $State -RelativeOffset $Values[2]
      $MaximumLengthText = Get-NSISString -State $State -RelativeOffset $Values[3]
      $NewLength = if ([string]::IsNullOrEmpty($MaximumLengthText)) { $Result.Length } else { Get-NSISInt -State $State -RelativeOffset $Values[3] }
      $Start = Get-NSISInt -State $State -RelativeOffset $Values[4]

      if ($Start -lt 0) { $Start += $Result.Length }
      if ($Start -lt 0) {
        $Result = ''
      } else {
        if ($Start -gt $Result.Length) { $Start = $Result.Length }
        $Result = $Result.Substring($Start)
      }

      # A negative MaxLen removes characters from the end of the selected
      # substring. NSIS clamps an underflow to an empty destination variable.
      if ($NewLength -lt 0) { $NewLength += $Result.Length }
      if ($NewLength -lt 0) { $NewLength = 0 }
      if ($Result.Length -gt $NewLength) { $Result = $Result.Substring(0, $NewLength) }
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $Result
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_STR_CMP {
      $Left = Get-NSISString -State $State -RelativeOffset $Values[1]
      $Right = Get-NSISString -State $State -RelativeOffset $Values[2]
      $Equal = if ($Values[5] -eq 0) {
        $Left.Equals($Right, [System.StringComparison]::OrdinalIgnoreCase)
      } else {
        $Left -ceq $Right
      }

      return [pscustomobject]@{ Action = 'Continue'; Address = if ($Equal) { $Values[3] } else { $Values[4] } }
    }
    $Script:NSIS_OPCODE_READ_ENV {
      $EnvironmentName = Get-NSISString -State $State -RelativeOffset $Values[2]
      $EnvironmentValue = [System.Environment]::GetEnvironmentVariable($EnvironmentName)
      if ($null -eq $EnvironmentValue) { $EnvironmentValue = '' }
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $EnvironmentValue
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_GET_OS_INFO {
      # NSIS 3 compiles GetKnownFolderPath into EW_GETOSINFO rather than a
      # System plug-in call. offsets[1] is the output variable, offsets[2] is
      # the GUID string, and offsets[3] selects the operation. Tauri's standard
      # dual-scope template reaches this path through upstream MultiUser.nsh.
      $Operation = $Values[4]
      if ($Operation -eq $Script:NSIS_GET_OS_INFO_KNOWN_FOLDER) {
        $FolderId = Get-NSISString -State $State -RelativeOffset $Values[3]
        $KnownFolderPath = Resolve-NSISKnownFolderPath -FolderId $FolderId
        Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[2])) -Value $KnownFolderPath
      } elseif ($Operation -eq $Script:NSIS_GET_OS_INFO_READ_MEMORY) {
        $Address = Get-NSISInt -State $State -RelativeOffset $Values[3]
        $Specification = [uint32](Get-NSISInt -State $State -RelativeOffset $Values[5])
        $OsInfoValue = Get-NSISOsInfoMemoryValue -Address $Address -Specification $Specification
        if ($null -ne $OsInfoValue) {
          Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[2])) -Value $OsInfoValue
        }
      }

      # Arbitrary GETOSINFO_READMEMORY addresses remain unresolved; never copy
      # process memory from the parser host into installer evidence.
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_INT_CMP {
      $Left = Get-NSISInt -State $State -RelativeOffset $Values[1]
      $Right = Get-NSISInt -State $State -RelativeOffset $Values[2]

      if ($Left -eq $Right) {
        return [pscustomobject]@{ Action = 'Continue'; Address = $Values[3] }
      } elseif ($Left -lt $Right) {
        return [pscustomobject]@{ Action = 'Continue'; Address = $Values[4] }
      } else {
        return [pscustomobject]@{ Action = 'Continue'; Address = $Values[5] }
      }
    }
    $Script:NSIS_OPCODE_INT_OP {
      $Left = Get-NSISInt -State $State -RelativeOffset $Values[2]
      $Right = Get-NSISInt -State $State -RelativeOffset $Values[3]

      $Result = switch ($Values[4]) {
        0 { $Left + $Right }
        1 { $Left - $Right }
        2 { $Left * $Right }
        3 { if ($Right -eq 0) { 0 } else { [int]($Left / $Right) } }
        4 { $Left -bor $Right }
        5 { $Left -band $Right }
        6 { $Left -bxor $Right }
        7 { -bnot $Left }
        8 { [int]($Left -ne 0 -or $Right -ne 0) }
        9 { [int]($Left -ne 0 -and $Right -ne 0) }
        10 { if ($Right -eq 0) { 0 } else { $Left % $Right } }
        11 { $Left -shl $Right }
        12 { $Left -shr $Right }
        13 { [int](([uint32]$Left) -shr $Right) }
        default { $Left }
      }

      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ([string]$Result)
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_INT_FMT {
      $Format = Get-NSISString -State $State -RelativeOffset $Values[2]
      $Result = if ($Format.StartsWith('0x', [System.StringComparison]::OrdinalIgnoreCase)) {
        ('0x{0:X8}' -f [uint32]$Values[3])
      } else {
        [string]$Values[3]
      }

      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $Result
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_PUSH_POP {
      if ($Values[3] -ne 0) {
        $ExchangeIndex = $Values[3]
        if ($ExchangeIndex -lt $State.Stack.Count) {
          $TopIndex = $State.Stack.Count - 1
          $TargetIndex = $TopIndex - $ExchangeIndex
          $Temporary = $State.Stack[$TopIndex]
          $State.Stack[$TopIndex] = $State.Stack[$TargetIndex]
          $State.Stack[$TargetIndex] = $Temporary
        }
      } elseif ($Values[2] -eq $Script:NSIS_POP_OPERATION) {
        $PoppedValue = if ($State.Stack.Count -gt 0) {
          $State.Stack[$State.Stack.Count - 1]
        } else {
          ''
        }

        if ($State.Stack.Count -gt 0) { $State.Stack.RemoveAt($State.Stack.Count - 1) }
        Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $PoppedValue
      } else {
        $State.Stack.Add((Get-NSISString -State $State -RelativeOffset $Values[1]))
      }

      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_REGISTER_DLL {
      # Plug-in calls are encoded as EW_REGISTERDLL even though no COM
      # registration occurs. Resolve only the deterministic System operations
      # needed by architecture macros; all other plug-ins remain no-ops.
      $LibraryPath = Get-NSISString -State $State -RelativeOffset $Values[1]
      $FunctionName = Get-NSISString -State $State -RelativeOffset $Values[2]
      if ([IO.Path]::GetFileName($LibraryPath) -ieq 'System.dll') {
        $null = Invoke-NSISSystemPluginCall -State $State -FunctionName $FunctionName
      }
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_SHELL_EXEC {
      # Record configured nested execution as evidence only; never launch it.
      $Verb = Get-NSISString -State $State -RelativeOffset $Values[1]
      $File = Get-NSISString -State $State -RelativeOffset $Values[2]
      $Parameters = Get-NSISString -State $State -RelativeOffset $Values[3]
      $Kind = if ([string]::IsNullOrWhiteSpace($Verb)) { 'ShellExec' } else { "ShellExec:$Verb" }
      Add-NSISExecutedPayload -State $State -Command $File -Parameters $Parameters -Kind $Kind
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_EXECUTE {
      $Command = Get-NSISString -State $State -RelativeOffset $Values[1]
      $Kind = if ($Values[3] -ne 0) { 'ExecWait' } else { 'Exec' }
      Add-NSISExecutedPayload -State $State -Command $Command -Kind $Kind
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_DELETE_REG {
      $Root = Resolve-NSISRegistryRoot -State $State -Root $Raw[2]
      $Key = Get-NSISString -State $State -RelativeOffset $Values[3]
      $Name = Get-NSISString -State $State -RelativeOffset $Values[4]
      Remove-NSISRegistryValue -State $State -Root $Root -Key $Key -Name $Name
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_WRITE_REG {
      # Registry parsing maps the source-accurate EW_WRITEREG operands and updates
      # ARP metadata only for explicit uninstall-key writes.
      Add-NSISRegistryWrite -State $State -Entry $Entry
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_READ_REG {
      $Root = Resolve-NSISRegistryRoot -State $State -Root $Raw[2]
      $Key = Get-NSISString -State $State -RelativeOffset $Values[3]
      $Name = Get-NSISString -State $State -RelativeOffset $Values[4]
      $Value = Get-NSISRegistryValue -State $State -Root $Root -Key $Key -Name $Name
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $Value
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_WRITE_UNINSTALLER {
      $UninstallerPath = Get-NSISString -State $State -RelativeOffset $Values[1]
      Add-NSISFile -State $State -Path $UninstallerPath
      return $Script:NSIS_CONTINUE_RESULT
    }
    default {
      # Unsupported entries are ignored unless the resulting metadata stays incomplete and the caller throws.
      return $Script:NSIS_CONTINUE_RESULT
    }
  }
}

function ConvertTo-NSISManifestPath {
  <#
  .SYNOPSIS
    Convert a host-resolved installer path to the WinGet environment-variable form
  .DESCRIPTION
    NSIS simulation resolves special folders to live host paths such as
    C:\Program Files. WinGet manifests use stable environment-variable tokens
    instead, mirroring the directory-constant mapping of the Inno parser.
  .PARAMETER Path
    The resolved path to convert
  #>
  [OutputType([string])]
  param (
    [Parameter(HelpMessage = 'The resolved path to convert')]
    [AllowNull()]
    [string]$Path
  )

  if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }

  $ProgramFiles64 = if (${env:ProgramW6432}) { ${env:ProgramW6432} } else { $env:ProgramFiles }
  $ProgramFilesX86 = if (${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} } else { $ProgramFiles64 }
  $CommonProgramFiles64 = if (${env:CommonProgramW6432}) { ${env:CommonProgramW6432} } else { $env:CommonProgramFiles }
  $CommonProgramFilesX86 = if (${env:CommonProgramFiles(x86)}) { ${env:CommonProgramFiles(x86)} } else { $env:CommonProgramFiles }

  # Longest prefixes first so Common Files and the x86 roots win over the
  # shorter 64-bit Program Files prefix.
  $Mappings = @(
    @($CommonProgramFilesX86, '%ProgramFiles(x86)%\Common Files'),
    @($CommonProgramFiles64, '%ProgramFiles%\Common Files'),
    @($ProgramFilesX86, '%ProgramFiles(x86)%'),
    @($ProgramFiles64, '%ProgramFiles%'),
    @($env:LOCALAPPDATA, '%LocalAppData%'),
    @($env:APPDATA, '%AppData%'),
    @($env:ProgramData, '%ProgramData%'),
    @($env:USERPROFILE, '%UserProfile%'),
    @($Script:NSIS_WINDOWS_DIRECTORY, '%SystemRoot%')
  ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_[0]) } | Sort-Object -Property { - $_[0].Length } -Stable

  foreach ($Mapping in $Mappings) {
    $Prefix = $Mapping[0]
    if ($Path.Equals($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $Mapping[1] }
    if ($Path.StartsWith("$Prefix\", [System.StringComparison]::OrdinalIgnoreCase)) {
      return $Mapping[1] + $Path.Substring($Prefix.Length)
    }
  }
  return $Path
}

function Get-NSISLanguageLocaleName {
  <#
  .SYNOPSIS
    Convert an NSIS Windows language identifier to a BCP47 culture name
  .PARAMETER LanguageId
    The unsigned Windows language identifier stored in the NSIS language record
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The Windows language identifier')]
    [uint16]$LanguageId
  )

  try {
    return [System.Globalization.CultureInfo]::GetCultureInfo([int]$LanguageId).Name
  } catch {
    # Custom or obsolete LANGIDs remain useful numeric evidence even when .NET
    # cannot map them to a current BCP47 culture name.
    return $null
  }
}

function Get-NSISAppsAndFeaturesEntryInfo {
  <#
  .SYNOPSIS
    Resolve visible uninstall registry identities across every compiled NSIS language
  .DESCRIPTION
    NSIS language strings are selected at runtime. This function reevaluates only
    explicit EW_WRITEREG commands for each compiled language table; it does not
    probe arbitrary strings or execute the installer. The simulation's primary
    scalar metadata remains unchanged for compatibility.
  .PARAMETER State
    The mutable NSIS execution state after direct or simulated registry discovery
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  $LanguageTables = if ($State.PSObject.Properties.Name -contains 'LanguageTables') {
    @($State.LanguageTables)
  } elseif ($State.LanguageTable) {
    @($State.LanguageTable)
  } else {
    @()
  }
  if ($LanguageTables.Count -eq 0) {
    # Installers without a language block still need one pass for literal ARP writes.
    $LanguageTables = @([pscustomobject]@{
        LanguageId = [uint16]$Script:NSIS_DEFAULT_LANGUAGE; DialogOffset = [uint32]0
        RightToLeft = $false; StringOffsets = [int[]]@()
      })
  }

  $TargetArchitectureProperty = $State.PSObject.Properties['TargetArchitecture']
  $HasTargetArchitecture = $null -ne $TargetArchitectureProperty -and
  -not [string]::IsNullOrWhiteSpace([string]$TargetArchitectureProperty.Value)
  $TargetScopeProperty = $State.PSObject.Properties['TargetScope']
  $HasTargetScope = $null -ne $TargetScopeProperty -and
  -not [string]::IsNullOrWhiteSpace([string]$TargetScopeProperty.Value)
  $AllowedRegistryIdentities = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  if ($HasTargetArchitecture -and $State.PSObject.Properties.Name -contains 'RegistryWrites') {
    foreach ($RegistryWrite in @($State.RegistryWrites)) {
      if ($RegistryWrite.IsUninstallKey) {
        $null = $AllowedRegistryIdentities.Add("$($RegistryWrite.Root)`0$($RegistryWrite.Key)")
      }
    }
  }

  $Evidence = [System.Collections.Generic.List[object]]::new()
  if ($HasTargetScope -and $State.PSObject.Properties.Name -contains 'RegistryWrites') {
    $EntriesByRegistryKey = [ordered]@{}

    # A selected MultiUser branch has already resolved temporary variables and
    # SHCTX. Preserve only the uninstall writes reached by that branch instead
    # of re-reading every compiled EW_WRITEREG instruction from both scopes.
    foreach ($Write in @($State.RegistryWrites)) {
      if (-not $Write.IsUninstallKey) { continue }
      $ResolvedScope = if ($Write.Root -eq 'HKLM') { 'machine' } elseif ($Write.Root -eq 'HKCU') { 'user' } else { $null }
      if ($ResolvedScope -ne $TargetScopeProperty.Value) { continue }

      $RegistryIdentity = "$($Write.Root)`0$($Write.Key)"
      if (-not $EntriesByRegistryKey.Contains($RegistryIdentity)) {
        $EntriesByRegistryKey[$RegistryIdentity] = [pscustomobject]@{
          Root   = $Write.Root
          Key    = $Write.Key
          Scope  = $ResolvedScope
          Values = [ordered]@{}
        }
      }
      $EntriesByRegistryKey[$RegistryIdentity].Values[$Write.Name] = $Write.Value
    }

    $SelectedLanguageTable = if ($State.LanguageTable) {
      $State.LanguageTable
    } else {
      $LanguageTables | Select-Object -First 1
    }
    foreach ($RegistryEntry in $EntriesByRegistryKey.Values) {
      $Values = $RegistryEntry.Values
      if ([string]::IsNullOrWhiteSpace([string]$Values['DisplayName']) -and
        [string]::IsNullOrWhiteSpace([string]$Values['DisplayVersion']) -and
        [string]::IsNullOrWhiteSpace([string]$Values['Publisher'])) { continue }

      $SystemComponent = [string]$Values['SystemComponent']
      $Evidence.Add([pscustomobject][ordered]@{
          LanguageId      = [uint16]$SelectedLanguageTable.LanguageId
          Locale          = Get-NSISLanguageLocaleName -LanguageId $SelectedLanguageTable.LanguageId
          RegistryRoot    = $RegistryEntry.Root
          RegistryKey     = $RegistryEntry.Key
          Scope           = $RegistryEntry.Scope
          ProductCode     = $RegistryEntry.Key.Substring($RegistryEntry.Key.LastIndexOf('\') + 1)
          DisplayName     = $Values['DisplayName']
          DisplayVersion  = $Values['DisplayVersion']
          Publisher       = $Values['Publisher']
          InstallerType   = 'nullsoft'
          SystemComponent = $SystemComponent
          IsVisible       = $SystemComponent -notin @('1', '0x00000001')
        })
    }
  }

  $HadLanguageTableProperty = $State.PSObject.Properties.Name -contains 'LanguageTable'
  $OriginalLanguageTable = if ($HadLanguageTableProperty) { $State.LanguageTable } else { $null }
  if (-not $HadLanguageTableProperty) {
    $State | Add-Member -NotePropertyName LanguageTable -NotePropertyValue $null
  }
  $HadLanguageVariable = $State.Variables.ContainsKey($Script:NSIS_PREDEFINED_VAR_LANGUAGE)
  $OriginalLanguageVariable = if ($HadLanguageVariable) { $State.Variables[$Script:NSIS_PREDEFINED_VAR_LANGUAGE] } else { $null }
  $LanguageTablesToScan = if ($HasTargetScope) { @() } else { $LanguageTables }
  try {
    # Untargeted analysis intentionally evaluates every language table. A
    # targeted scope uses reached writes above because rescanning source entries
    # would lose runtime-computed key suffixes such as " (current user)".
    foreach ($LanguageTable in $LanguageTablesToScan) {
      $State.LanguageTable = $LanguageTable
      Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_LANGUAGE -Value ([string]$LanguageTable.LanguageId)
      $EntriesByRegistryKey = [ordered]@{}

      # Re-resolve only source-backed registry commands. This catches $(LangString)
      # values while retaining the exact uninstall key, hive, and registry type.
      foreach ($Entry in $State.Entries) {
        if ($Entry.Opcode -ne $Script:NSIS_OPCODE_WRITE_REG) { continue }
        $Write = Get-NSISRegistryWriteFromEntry -State $State -Entry $Entry
        if (-not $Write -or -not $Write.IsUninstallKey) { continue }

        $RegistryIdentity = "$($Write.Root)`0$($Write.Key)"
        if ($HasTargetArchitecture -and $AllowedRegistryIdentities.Count -gt 0 -and
          -not $AllowedRegistryIdentities.Contains($RegistryIdentity)) { continue }
        if (-not $EntriesByRegistryKey.Contains($RegistryIdentity)) {
          $EntriesByRegistryKey[$RegistryIdentity] = [pscustomobject]@{
            Root   = $Write.Root
            Key    = $Write.Key
            Values = [ordered]@{}
          }
        }
        $EntriesByRegistryKey[$RegistryIdentity].Values[$Write.Name] = $Write.Value
      }

      foreach ($RegistryEntry in $EntriesByRegistryKey.Values) {
        $Values = $RegistryEntry.Values
        $SystemComponent = [string]$Values['SystemComponent']
        $IsVisible = $SystemComponent -notin @('1', '0x00000001')
        $ProductCode = $RegistryEntry.Key.Substring($RegistryEntry.Key.LastIndexOf('\') + 1)
        $Scope = if ($RegistryEntry.Root -eq 'HKLM') { 'machine' } elseif ($RegistryEntry.Root -eq 'HKCU') { 'user' } else { $null }

        # Omit empty registry shells that do not establish an ARP identity.
        if ([string]::IsNullOrWhiteSpace([string]$Values['DisplayName']) -and
          [string]::IsNullOrWhiteSpace([string]$Values['DisplayVersion']) -and
          [string]::IsNullOrWhiteSpace([string]$Values['Publisher'])) { continue }

        $Evidence.Add([pscustomobject][ordered]@{
            LanguageId      = [uint16]$LanguageTable.LanguageId
            Locale          = Get-NSISLanguageLocaleName -LanguageId $LanguageTable.LanguageId
            RegistryRoot    = $RegistryEntry.Root
            RegistryKey     = $RegistryEntry.Key
            Scope           = $Scope
            ProductCode     = $ProductCode
            DisplayName     = $Values['DisplayName']
            DisplayVersion  = $Values['DisplayVersion']
            Publisher       = $Values['Publisher']
            InstallerType   = 'nullsoft'
            SystemComponent = $SystemComponent
            IsVisible       = $IsVisible
          })
      }
    }
  } finally {
    if ($HadLanguageTableProperty) {
      $State.LanguageTable = $OriginalLanguageTable
    } else {
      $State.PSObject.Properties.Remove('LanguageTable')
    }
    if ($HadLanguageVariable) {
      $State.Variables[$Script:NSIS_PREDEFINED_VAR_LANGUAGE] = $OriginalLanguageVariable
    } else {
      $null = $State.Variables.Remove($Script:NSIS_PREDEFINED_VAR_LANGUAGE)
    }
  }

  $ManifestEntries = [System.Collections.Generic.List[object]]::new()
  $SeenManifestEntries = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
  foreach ($Entry in $Evidence) {
    if (-not $Entry.IsVisible) { continue }
    $Identity = "$($Entry.ProductCode)`0$($Entry.DisplayName)`0$($Entry.DisplayVersion)`0$($Entry.Publisher)`0$($Entry.InstallerType)"
    if (-not $SeenManifestEntries.Add($Identity)) { continue }

    # Keep this projection schema-shaped. Language and registry provenance stay
    # in AppsAndFeaturesEntryEvidence for analyzer display and VM correlation.
    $ManifestEntry = [ordered]@{}
    foreach ($Name in @('DisplayName', 'DisplayVersion', 'Publisher', 'ProductCode', 'InstallerType')) {
      if (-not [string]::IsNullOrWhiteSpace([string]$Entry.$Name)) { $ManifestEntry[$Name] = $Entry.$Name }
    }
    $ManifestEntries.Add([pscustomobject]$ManifestEntry)
  }

  $LocalizedRegistryKeys = [System.Collections.Generic.List[string]]::new()
  foreach ($Group in @($Evidence | Where-Object IsVisible | Group-Object { "$($_.RegistryRoot)`0$($_.RegistryKey)" })) {
    $Identities = @($Group.Group | ForEach-Object { "$($_.DisplayName)`0$($_.Publisher)" } | Select-Object -Unique)
    if ($Identities.Count -gt 1) { $LocalizedRegistryKeys.Add($Group.Name) }
  }

  $Notices = [System.Collections.Generic.List[string]]::new()
  if ($LocalizedRegistryKeys.Count -gt 0) {
    $Locales = @($Evidence | Where-Object IsVisible | ForEach-Object { $_.Locale ?? "LANGID-$($_.LanguageId)" } | Select-Object -Unique)
    $Notices.Add("NSIS uninstall DisplayName or Publisher varies by installer language ($($Locales -join ', ')); AppsAndFeaturesEntries contains $($ManifestEntries.Count) distinct visible ARP identities. Preserve the applicable localized identities and validate installed-language behavior in a VM when authoring the manifest.")
  }

  return [pscustomobject][ordered]@{
    AppsAndFeaturesEntries       = $ManifestEntries.ToArray()
    AppsAndFeaturesEntryEvidence = $Evidence.ToArray()
    Notices                      = [string[]]$Notices.ToArray()
    HasLocalizedEntries          = $LocalizedRegistryKeys.Count -gt 0
  }
}

function Repair-NSISIncompleteInstallMetadata {
  <#
  .SYNOPSIS
    Recover a missing install root from a unique explicit compiled path assignment
  .DESCRIPTION
    Custom directory pages can initialize INSTDIR only after UI interaction. If
    static simulation therefore observes a root-relative suffix, this helper
    accepts a replacement only when one explicit StrCpy source is an absolute
    known install-root path ending in that exact suffix.
  .PARAMETER State
    The mutable NSIS execution state and metadata to repair
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  $ObservedInstallRoot = Get-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_INSTDIR
  if ([string]::IsNullOrWhiteSpace($ObservedInstallRoot)) { $ObservedInstallRoot = [string]$State.Metadata.DefaultInstallLocation }
  $EffectiveScope = [string]$State.Metadata.Scope
  $UninstallRoots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($Entry in $State.Entries) {
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_WRITE_REG) { continue }
    $Write = Get-NSISRegistryWriteFromEntry -State $State -Entry $Entry
    if ($Write.IsUninstallKey) { $null = $UninstallRoots.Add($Write.Root) }
  }
  if ($UninstallRoots.Count -eq 1) {
    # An explicit uninstall hive is stronger scope evidence than a temporary
    # path left by incomplete simulation of a custom directory page.
    $EffectiveScope = if (@($UninstallRoots)[0] -eq 'HKLM') { 'machine' } elseif (@($UninstallRoots)[0] -eq 'HKCU') { 'user' } else { $EffectiveScope }
    if ($EffectiveScope) { $State.Metadata.Scope = $EffectiveScope }
  }

  $IsRootRelative = $ObservedInstallRoot -match '^[\\/](?![\\/])'
  $TemporaryRoot = [System.IO.Path]::GetTempPath().TrimEnd('\')
  $IsTemporaryMachineRoot = $EffectiveScope -eq 'machine' -and $ObservedInstallRoot.StartsWith($TemporaryRoot, [System.StringComparison]::OrdinalIgnoreCase)
  if (-not $IsRootRelative -and -not $IsTemporaryMachineRoot) { return }

  $InstallSuffix = if ($IsRootRelative) {
    $ObservedInstallRoot.TrimStart('\', '/')
  } else {
    Split-Path -Path $ObservedInstallRoot -Leaf
  }
  if ([string]::IsNullOrWhiteSpace($InstallSuffix)) { return }
  $SuffixPath = '\' + $InstallSuffix

  $KnownRoots = if ($EffectiveScope -eq 'machine') {
    @($env:ProgramFiles, ${env:ProgramFiles(x86)}, ${env:ProgramW6432})
  } elseif ($EffectiveScope -eq 'user') {
    @($env:LOCALAPPDATA, $env:APPDATA)
  } else {
    @($env:ProgramFiles, ${env:ProgramFiles(x86)}, ${env:ProgramW6432}, $env:LOCALAPPDATA, $env:APPDATA)
  }
  $KnownRoots = @($KnownRoots) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique
  $DirectInstallDirectoryCandidates = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $SuffixCandidates = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

  foreach ($Entry in $State.Entries) {
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_ASSIGN_VAR) { continue }
    $Candidate = Get-NSISString -State $State -RelativeOffset $Entry.Values[2]
    if ([string]::IsNullOrWhiteSpace($Candidate) -or -not [System.IO.Path]::IsPathFullyQualified($Candidate)) { continue }
    if (-not @($KnownRoots).Where({ $Candidate.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) }, 'First')) { continue }

    if ([Math]::Abs($Entry.Values[1]) -eq $Script:NSIS_PREDEFINED_VAR_INSTDIR) {
      $ResolvedCandidate = if ($Candidate.EndsWith($SuffixPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        $Candidate
      } else {
        Join-Path $Candidate $InstallSuffix
      }
      $null = $DirectInstallDirectoryCandidates.Add($ResolvedCandidate.TrimEnd('\'))
    } elseif ($Candidate.EndsWith($SuffixPath, [System.StringComparison]::OrdinalIgnoreCase)) {
      $null = $SuffixCandidates.Add($Candidate.TrimEnd('\'))
    }
  }

  # Multiple explicit roots represent conditional behavior and must remain
  # unresolved until the caller supplies scope/architecture or VM evidence.
  $Candidates = if ($DirectInstallDirectoryCandidates.Count -gt 0) { $DirectInstallDirectoryCandidates } else { $SuffixCandidates }
  if ($Candidates.Count -ne 1) { return }
  $InstallRoot = @($Candidates)[0]

  # Variables derived while INSTDIR was root-relative retain that same prefix.
  # Replace it before re-evaluating explicit ARP writes so versioned paths keep
  # their compiled suffix without inheriting a branch-only lexical value.
  foreach ($VariableIndex in @($State.Variables.Keys)) {
    $VariableValue = [string]$State.Variables[$VariableIndex]
    if ($VariableValue.StartsWith($ObservedInstallRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
      $State.Variables[$VariableIndex] = $InstallRoot + $VariableValue.Substring($ObservedInstallRoot.Length)
    }
  }
  $State.Metadata.DefaultInstallLocation = $InstallRoot
  $State.Variables[$Script:NSIS_PREDEFINED_VAR_INSTDIR] = $InstallRoot

  foreach ($PropertyName in @('UninstallString', 'QuietUninstallString', 'DisplayIcon')) {
    $Value = [string]$State.Metadata[$PropertyName]
    if ($Value.StartsWith('"' + $ObservedInstallRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
      $State.Metadata[$PropertyName] = '"' + $InstallRoot + $Value.Substring($ObservedInstallRoot.Length + 1)
    } elseif ($Value.StartsWith($ObservedInstallRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
      $State.Metadata[$PropertyName] = $InstallRoot + $Value.Substring($ObservedInstallRoot.Length)
    }
  }

  # Keep the structured registry projection consistent with the top-level
  # metadata returned to bridge and analyzer callers.
  foreach ($PropertyName in @('InstallLocation', 'UninstallString', 'QuietUninstallString', 'DisplayIcon')) {
    $MetadataName = if ($PropertyName -eq 'InstallLocation') { 'DefaultInstallLocation' } else { $PropertyName }
    if ($State.Metadata.RegistryValues.ContainsKey($PropertyName) -and $State.Metadata[$MetadataName]) {
      $State.Metadata.RegistryValues[$PropertyName] = $State.Metadata[$MetadataName]
    }
  }
  foreach ($Write in $State.RegistryWrites) {
    $MetadataName = if ($Write.Name -eq 'InstallLocation') { 'DefaultInstallLocation' } else { [string]$Write.Name }
    if ($MetadataName -in @('DefaultInstallLocation', 'UninstallString', 'QuietUninstallString', 'DisplayIcon') -and $State.Metadata[$MetadataName]) {
      $Write.Value = $State.Metadata[$MetadataName]
    }
  }

  # Re-evaluate path-valued uninstall writes with the repaired live variables.
  # This intentionally bypasses direct lexical data-flow: current variables now
  # contain the branch selected by simulation rather than every compiled branch.
  foreach ($Entry in $State.Entries) {
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_WRITE_REG) { continue }
    $Write = Get-NSISRegistryWriteFromEntry -State $State -Entry $Entry
    if (-not $Write.IsUninstallKey -or $Write.Name -notin @('InstallLocation', 'UninstallString', 'QuietUninstallString', 'DisplayIcon')) { continue }
    Set-NSISRegistryValue -State $State -Root $Write.Root -Key $Write.Key -Name $Write.Name -Value $Write.Value
    foreach ($ExistingWrite in $State.RegistryWrites) {
      if ($ExistingWrite.Root -eq $Write.Root -and $ExistingWrite.Key -eq $Write.Key -and $ExistingWrite.Name -eq $Write.Name) {
        $ExistingWrite.Value = $Write.Value
      }
    }
  }
}

function Get-NSISPortableLauncherInfo {
  <#
  .SYNOPSIS
    Detect a source-backed NSIS portable-launcher layout
  .DESCRIPTION
    electron-builder's portable.nsi template sets three PORTABLE_EXECUTABLE_*
    environment variables before executing the unpacked application from a
    temporary directory. Requiring that complete marker set, temporary payload
    execution, and no visible uninstall write avoids classifying ordinary NSIS
    bootstrappers as portable merely because they also unpack into TEMP.
  .PARAMETER State
    The completed NSIS simulation state containing strings, files, execution,
    and Apps & Features evidence
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The completed NSIS simulation state')]
    [pscustomobject]$State
  )

  $RequiredMarkers = [string[]]@(
    'PORTABLE_EXECUTABLE_DIR'
    'PORTABLE_EXECUTABLE_FILE'
    'PORTABLE_EXECUTABLE_APP_FILENAME'
  )
  $PresentMarkers = [System.Collections.Generic.List[string]]::new()
  $MarkerEncoding = if ($State.VersionInfo.Unicode) { [System.Text.Encoding]::Unicode } else { [System.Text.Encoding]::ASCII }
  foreach ($Marker in $RequiredMarkers) {
    # Search the bounded decoded strings block directly. Materializing every
    # string solely for three exact markers is slower and allocates many
    # short-lived PowerShell objects on large generated installers.
    $Pattern = $MarkerEncoding.GetBytes($Marker)
    if (@(Find-BinaryPattern -Bytes $State.StringsBlock -Pattern $Pattern -Maximum 1).Count -gt 0) {
      $PresentMarkers.Add($Marker)
    }
  }

  # The portable template extracts under $PLUGINSDIR or an optional $TEMP
  # unpack directory, then waits for the application before deleting that tree.
  $TemporaryRoots = [System.Collections.Generic.List[string]]::new()
  foreach ($Root in @(
      [System.IO.Path]::GetTempPath().TrimEnd('\')
      (Get-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_PLUGINSDIR)
    )) {
    if (-not [string]::IsNullOrWhiteSpace($Root) -and -not $TemporaryRoots.Contains($Root)) {
      $TemporaryRoots.Add($Root)
    }
  }
  $TemporaryPayloads = [System.Collections.Generic.List[string]]::new()
  foreach ($Payload in @($State.ExecutedPayloads)) {
    $Command = ([string]$Payload.Command).Trim().TrimStart('"')
    if (@($TemporaryRoots).Where({
          $Command.Equals($_, [System.StringComparison]::OrdinalIgnoreCase) -or
          $Command.StartsWith("$_\", [System.StringComparison]::OrdinalIgnoreCase)
        }, 'First').Count -gt 0) {
      $TemporaryPayloads.Add([string]$Payload.Command)
    }
  }

  $AppPackageFiles = @(
    foreach ($Value in @($State.Files)) {
      if ($Value -match '(?i)(app-(?:32|64|arm64)(?:\.(?:7z|zip))?)') {
        $Matches[1].ToLowerInvariant()
      }
    }
  ) | Select-Object -Unique
  $HasPortableMarkers = $PresentMarkers.Count -eq $RequiredMarkers.Count
  $IsPortable = $HasPortableMarkers -and $TemporaryPayloads.Count -gt 0 -and -not $State.Metadata.WritesAppsAndFeaturesEntry

  $Evidence = [System.Collections.Generic.List[string]]::new()
  foreach ($Marker in $PresentMarkers) { $Evidence.Add("EnvironmentVariable:$Marker") }
  foreach ($AppPackageFile in $AppPackageFiles) { $Evidence.Add("AppPackage:$AppPackageFile") }
  foreach ($Payload in $TemporaryPayloads) { $Evidence.Add("TemporaryExecution:$Payload") }
  if (-not $State.Metadata.WritesAppsAndFeaturesEntry) { $Evidence.Add('NoAppsAndFeaturesEntry') }

  return [pscustomobject][ordered]@{
    IsPortable                = $IsPortable
    Family                    = if ($HasPortableMarkers) { 'electron-builder' } else { $null }
    EnvironmentVariables      = [string[]]$PresentMarkers.ToArray()
    AppPackageFiles           = [string[]]@($AppPackageFiles)
    TemporaryExecutedPayloads = [string[]]$TemporaryPayloads.ToArray()
    Evidence                  = [string[]]$Evidence.ToArray()
  }
}

function Test-NSISStringBlockLiteral {
  <#
  .SYNOPSIS
    Test whether the decoded NSIS string block contains one exact template marker
  .PARAMETER State
    The mutable NSIS execution state containing the decoded strings block
  .PARAMETER Value
    The case-sensitive literal emitted by the installer template
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The exact template marker to locate')]
    [string]$Value
  )

  # Search bytes directly instead of materializing every decoded string merely
  # to identify a few compiler-generated markers on large installers.
  $Encoding = if ($State.VersionInfo.Unicode) { [Text.Encoding]::Unicode } else { [Text.Encoding]::Default }
  $Pattern = $Encoding.GetBytes($Value)
  return @(Find-BinaryPattern -Bytes $State.StringsBlock -Pattern $Pattern -Maximum 1).Count -gt 0
}

function Get-NSISTauriInstallerInfo {
  <#
  .SYNOPSIS
    Identify the standard Tauri NSIS template and its compiled install mode
  .DESCRIPTION
    Tauri permits custom NSIS templates, so generic product strings are not
    enough. Detection requires three markers emitted together by Tauri's
    standard template: its native utility plug-in, MainBinaryName registry
    value, and placeholder installation directory. The mode then comes from
    compiled MultiUser setters, the visible ARP scope, and the PE execution
    level rather than a package-name allowlist.
  .PARAMETER State
    The mutable NSIS execution state after scope selectors were discovered
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  if (-not $State.PSObject.Properties['TauriTemplateEvidence']) {
    $Markers = [System.Collections.Generic.List[string]]::new()
    foreach ($Marker in @('nsis_tauri_utils.dll', 'MainBinaryName', 'placeholder\')) {
      if (Test-NSISStringBlockLiteral -State $State -Value $Marker) { $Markers.Add($Marker) }
    }

    $IsTauri = $Markers.Count -eq 3
    $RequestedExecutionLevel = if ($IsTauri) { Get-PERequestedExecutionLevel -Path $State.Path } else { $null }
    $State | Add-Member -NotePropertyName TauriTemplateEvidence -NotePropertyValue ([pscustomobject]@{
        IsTauri                 = $IsTauri
        Markers                 = [string[]]$Markers.ToArray()
        RequestedExecutionLevel = $RequestedExecutionLevel
      })
  }

  $Template = $State.TauriTemplateEvidence
  $InstallerMode = $null
  if ($Template.IsTauri) {
    $SupportedScopes = @($State.Metadata.SupportedScopes)
    if ($SupportedScopes -contains 'user' -and $SupportedScopes -contains 'machine' -and
      $Template.RequestedExecutionLevel -eq 'highestAvailable') {
      $InstallerMode = 'both'
    } elseif ($State.Metadata.Scope -eq 'user' -and $Template.RequestedExecutionLevel -eq 'asInvoker') {
      $InstallerMode = 'currentUser'
    } elseif ($State.Metadata.Scope -eq 'machine' -and $Template.RequestedExecutionLevel -eq 'requireAdministrator') {
      $InstallerMode = 'perMachine'
    }
  }

  $Evidence = [System.Collections.Generic.List[string]]::new()
  foreach ($Marker in @($Template.Markers)) { $Evidence.Add("String:$Marker") }
  if ($Template.RequestedExecutionLevel) { $Evidence.Add("RequestedExecutionLevel:$($Template.RequestedExecutionLevel)") }
  foreach ($SupportedScope in @($State.Metadata.SupportedScopes)) { $Evidence.Add("CompiledScope:$SupportedScope") }
  if ($State.Metadata.Scope) { $Evidence.Add("ObservedArpScope:$($State.Metadata.Scope)") }

  return [pscustomobject][ordered]@{
    IsTauri                 = [bool]$Template.IsTauri
    InstallerMode           = $InstallerMode
    RequestedExecutionLevel = $Template.RequestedExecutionLevel
    Evidence                = [string[]]$Evidence.ToArray()
  }
}

function Complete-NSISMetadata {
  <#
  .SYNOPSIS
    Apply deterministic fallbacks after the NSIS simulation completes
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER SkipLocalizedAppsAndFeaturesEntries
    Skip the all-language registry projection during intermediate completeness checks
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(HelpMessage = 'Skip localized ARP projection during an intermediate parser pass')]
    [switch]$SkipLocalizedAppsAndFeaturesEntries
  )

  # Language-table name and split VersionMajor/VersionMinor values are structured
  # fallbacks only; arbitrary strings are never probed as metadata candidates.
  if (-not $State.Metadata.DisplayName -and $State.LanguageTable -and $State.LanguageTable.StringOffsets.Count -gt 2) {
    $NameOffset = $State.LanguageTable.StringOffsets[2]
    if ($NameOffset -ne 0) { $State.Metadata.DisplayName = Get-NSISString -State $State -RelativeOffset $NameOffset }
  }

  if (-not $State.Metadata.DisplayVersion) {
    $Major = $State.Metadata.RegistryValues['VersionMajor']
    $Minor = $State.Metadata.RegistryValues['VersionMinor']
    if (-not [string]::IsNullOrWhiteSpace($Major) -and -not [string]::IsNullOrWhiteSpace($Minor)) {
      $State.Metadata.DisplayVersion = "$Major.$Minor"
    }
  }

  if (-not $State.Metadata.DefaultInstallLocation) {
    $State.Metadata.DefaultInstallLocation = Get-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_INSTDIR
  }

  if (-not $SkipLocalizedAppsAndFeaturesEntries) {
    # Some custom directory pages establish the root only after UI interaction.
    # Run this only for the final projection; intermediate completeness checks
    # must not mutate variables before section simulation selects its branches.
    Repair-NSISIncompleteInstallMetadata -State $State
  }

  if (-not $State.Metadata.Scope) {
    # Scope fallback uses the resolved install root only when no explicit
    # uninstall hive or ShellVarContext evidence established it during simulation.
    if ($State.Metadata.DefaultInstallLocation -and (
        $State.Metadata.DefaultInstallLocation.StartsWith($env:ProgramFiles, [System.StringComparison]::OrdinalIgnoreCase) -or
        (${env:ProgramFiles(x86)} -and $State.Metadata.DefaultInstallLocation.StartsWith(${env:ProgramFiles(x86)}, [System.StringComparison]::OrdinalIgnoreCase))
      )) {
      $State.Metadata.Scope = 'machine'
    } else {
      $State.Metadata.Scope = 'user'
    }
  }

  # Tauri's standard template has three install-mode variants. Record only a
  # mode proven by its template markers plus compiled scope/execution evidence;
  # custom templates remain ordinary NSIS when those markers do not agree.
  $TauriInfo = Get-NSISTauriInstallerInfo -State $State
  $State.Metadata.IsTauri = $TauriInfo.IsTauri
  $State.Metadata.TauriInstallerMode = $TauriInfo.InstallerMode
  $State.Metadata.RequestedExecutionLevel = $TauriInfo.RequestedExecutionLevel
  $State.Metadata.TauriEvidence = [string[]]$TauriInfo.Evidence
  if ($TauriInfo.IsTauri) {
    if ($TauriInfo.InstallerMode -eq 'currentUser' -and @($State.Metadata.SupportedScopes).Count -eq 0) {
      $State.Metadata.SupportedScopes = [string[]]@('user')
    } elseif ($TauriInfo.InstallerMode -eq 'perMachine' -and @($State.Metadata.SupportedScopes).Count -eq 0) {
      $State.Metadata.SupportedScopes = [string[]]@('machine')
    } elseif (-not $TauriInfo.InstallerMode) {
      $State.Warnings.Add('The standard Tauri NSIS template was detected, but its compiled installer mode could not be resolved from scope and PE execution-level evidence.')
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$State.TargetScope) -and
      @($State.Metadata.SupportedScopes).Count -gt 0 -and
      $State.Metadata.SupportedScopes -notcontains $State.TargetScope) {
      $State.Warnings.Add("The Tauri installer supports '$($State.Metadata.SupportedScopes -join ', ')' scope, not the requested '$($State.TargetScope)' scope.")
    }
  }

  if ($State.Metadata.SystemComponent -eq '1' -or $State.Metadata.SystemComponent -eq '0x00000001') {
    $State.Metadata.WritesAppsAndFeaturesEntry = $false
  }

  if (-not $SkipLocalizedAppsAndFeaturesEntries) {
    # Portable launchers have an extraction directory rather than a persistent
    # installation location. Detect the compiled template before path
    # normalization and prevent that transient directory entering manifests.
    $PortableInfo = Get-NSISPortableLauncherInfo -State $State
    $State.Metadata.IsPortable = $PortableInfo.IsPortable
    $State.Metadata.PortableEvidence = [string[]]$PortableInfo.Evidence
    if ($PortableInfo.IsPortable) {
      $State.Metadata.DefaultInstallLocation = $null
      $State.Warnings.Add('The NSIS executable is an electron-builder portable launcher: it sets the PORTABLE_EXECUTABLE_* environment variables, executes the unpacked application from a temporary directory, and writes no visible Apps & Features entry. Treat the outer EXE as portable payload evidence rather than an installed NSIS package.')
    }
  }

  # Manifests carry environment-variable install roots, not host-absolute paths.
  # Scope detection above already consumed the resolved path, so normalize only
  # the reported value.
  if ($State.Metadata.DefaultInstallLocation) {
    $State.Metadata.DefaultInstallLocation = ConvertTo-NSISManifestPath -Path $State.Metadata.DefaultInstallLocation
  }

  $ExtractedFiles = @($State.Files) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique
  $ExecutedPayloads = @($State.ExecutedPayloads)
  $SeenRegistryWrites = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

  # Deduplicate exact registry evidence while preserving first-observed order.
  $RegistryWrites = @(
    foreach ($Write in @($State.RegistryWrites)) {
      $WriteKey = "$($Write.Root)`0$($Write.Key)`0$($Write.Name)`0$($Write.Value)`0$($Write.Type)"
      if ($SeenRegistryWrites.Add($WriteKey)) { $Write }
    }
  )
  $NestedInstallerEvidence = @($ExtractedFiles + @($ExecutedPayloads | ForEach-Object { "$($_.Command) $($_.Parameters)" })).Where({
      $_ -match '(?i)\.(msi|msp|msu)(\s|$)|(^|[\\/])(setup|install|installer)\.exe(\s|$)'
    })

  if (-not $State.Metadata.WritesAppsAndFeaturesEntry -and $NestedInstallerEvidence.Count -gt 0) {
    # A wrapper that extracts or executes another installer may delegate ARP
    # ownership; surface that ambiguity instead of inventing an NSIS ProductCode.
    $State.Warnings.Add('The NSIS installer has nested installer evidence but no visible uninstall registry write was found; inspect the nested payload or validate ARP in a VM.')
  }
  if (-not $SkipLocalizedAppsAndFeaturesEntries -and
    -not $State.Metadata.IsPortable -and
    $State.Metadata.HasArchitectureRuntimeCheck -and
    [string]::IsNullOrWhiteSpace([string]$State.TargetArchitecture) -and
    [string]::IsNullOrWhiteSpace([string]$State.Metadata.ProductCode)) {
    $State.Warnings.Add('The installer contains a runtime architecture branch; pass -Architecture x86, x64, or arm64 to resolve architecture-specific ARP metadata deterministically.')
  }
  if (-not $SkipLocalizedAppsAndFeaturesEntries -and
    $State.Metadata.HasScopeRuntimeCheck -and
    [string]::IsNullOrWhiteSpace([string]$State.TargetScope) -and
    @($State.Metadata.SupportedScopes).Count -gt 1) {
    $State.Warnings.Add('The installer contains runtime user and machine scope branches; pass -Scope user or machine to resolve scope-specific ARP metadata deterministically.')
  }
  if (-not $SkipLocalizedAppsAndFeaturesEntries -and
    $State.Metadata.HasScopeRuntimeCheck -and
    -not [string]::IsNullOrWhiteSpace([string]$State.TargetScope) -and
    -not [string]::IsNullOrWhiteSpace([string]$State.Metadata.Scope) -and
    $State.TargetScope -ne $State.Metadata.Scope) {
    $State.Warnings.Add("The requested '$($State.TargetScope)' scope did not resolve to matching uninstall registry evidence; the parser observed '$($State.Metadata.Scope)' scope instead.")
  }

  $State.Metadata.AppsAndFeaturesProductCode = if ($State.Metadata.WritesAppsAndFeaturesEntry) { $State.Metadata.ProductCode } else { $null }
  $State.Metadata.AppsAndFeaturesInstallerType = if ($State.Metadata.WritesAppsAndFeaturesEntry) { 'nullsoft' } else { $null }
  $State.Metadata.RegistryWrites = @($RegistryWrites)
  if (-not $SkipLocalizedAppsAndFeaturesEntries) {
    # The all-language projection scans explicit registry commands once per
    # language. Defer it until a result is returned rather than repeating it for
    # the simulator's intermediate completeness checks.
    $AppsAndFeaturesInfo = Get-NSISAppsAndFeaturesEntryInfo -State $State
    $State.Metadata.AppsAndFeaturesEntries = @($AppsAndFeaturesInfo.AppsAndFeaturesEntries)
    $State.Metadata.AppsAndFeaturesEntryEvidence = @($AppsAndFeaturesInfo.AppsAndFeaturesEntryEvidence)
    $State.Metadata.Notices = [string[]]@($AppsAndFeaturesInfo.Notices)
    $State.Metadata.HasLocalizedAppsAndFeaturesEntries = $AppsAndFeaturesInfo.HasLocalizedEntries

    # Architecture-targeted simulation can intentionally skip a direct scan.
    # Recover a missing scalar only when every explicit visible ARP projection
    # agrees, preserving localized or architecture-specific differences.
    foreach ($PropertyName in @('DisplayName', 'DisplayVersion', 'Publisher')) {
      if (-not [string]::IsNullOrWhiteSpace([string]$State.Metadata[$PropertyName])) { continue }
      $Values = @($AppsAndFeaturesInfo.AppsAndFeaturesEntryEvidence | Where-Object IsVisible | ForEach-Object { $_.$PropertyName } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
      if ($Values.Count -eq 1) { $State.Metadata[$PropertyName] = $Values[0] }
    }
  }
  $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
  foreach ($Warning in @($RegistryAssociationInfo.Warnings)) { $State.Warnings.Add($Warning) }
  $State.Metadata.RegistryAssociationInfo = $RegistryAssociationInfo
  $State.Metadata.Protocols = $RegistryAssociationInfo.Protocols
  $State.Metadata.FileExtensions = $RegistryAssociationInfo.FileExtensions
  $State.Metadata.ExtractedFiles = @($ExtractedFiles)
  $State.Metadata.ExecutedPayloads = @($ExecutedPayloads)
  $State.Metadata.Warnings = [string[]]@($State.Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
  $State.Metadata.UnresolvedFields = [string[]]@($State.Metadata.UnresolvedFields | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
  $State.Metadata.ParserVersionInfo = $State.VersionInfo

  return [pscustomobject]$State.Metadata
}

function Invoke-NSISStaticSimulation {
  <#
  .SYNOPSIS
    Simulate NSIS installer code paths needed for deterministic static metadata
  .PARAMETER Path
    The path to the NSIS installer
  .PARAMETER Mode
    The simulation mode. Full runs initialization and sections; Fast returns early when direct uninstall metadata is complete.
  .PARAMETER Architecture
    The target Windows architecture used to resolve compiled runtime architecture checks
  .PARAMETER Scope
    The target installation scope used to resolve compiled MultiUser scope setters
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The simulation mode')]
    [ValidateSet('Full', 'Fast')]
    [string]$Mode = 'Full',

    [Parameter(HelpMessage = 'The target Windows architecture used to resolve runtime architecture checks')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [Parameter(HelpMessage = 'The target installation scope used to resolve runtime scope checks')]
    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  process {
    # Parse and normalize the compiled header once; all later phases share the
    # same mutable state so callbacks and sections observe prior variable writes.
    $HeaderData = Get-NSISHeaderData -Path $Path
    $InitializationArguments = @{ HeaderData = $HeaderData }
    if (-not [string]::IsNullOrWhiteSpace($Architecture)) { $InitializationArguments.Architecture = $Architecture }
    if (-not [string]::IsNullOrWhiteSpace($Scope)) { $InitializationArguments.Scope = $Scope }
    $InitializedState = Initialize-NSISState @InitializationArguments
    $State = $InitializedState.State
    $Layout = $InitializedState.Layout
    $ArchitectureProbeStart = Get-NSISArchitectureProbeStart -State $State
    $State.Metadata.HasArchitectureRuntimeCheck = $ArchitectureProbeStart -ge 0
    $ScopeSelectionStarts = [ordered]@{
      user    = Get-NSISScopeSelectionStart -State $State -Scope user
      machine = Get-NSISScopeSelectionStart -State $State -Scope machine
    }
    $State.Metadata.SupportedScopes = [string[]]@($ScopeSelectionStarts.Keys | Where-Object { $ScopeSelectionStarts[$_] -ge 0 })
    $State.Metadata.HasScopeRuntimeCheck = $State.Metadata.SupportedScopes.Count -gt 0
    $ScopeSelectionStart = if (-not [string]::IsNullOrWhiteSpace($Scope)) { $ScopeSelectionStarts[$Scope] } else { -1 }
    $HasTargetArchitectureResolver = $ArchitectureProbeStart -ge 0 -and -not [string]::IsNullOrWhiteSpace($Architecture)
    $HasTargetScopeResolver = $ScopeSelectionStart -ge 0 -and -not [string]::IsNullOrWhiteSpace($Scope)
    $UseDirectRegistryFallback = -not ($HasTargetArchitectureResolver -or $HasTargetScopeResolver)

    # Prefer direct uninstall registry writes when they already expose a single deterministic ARP identity.
    if ($UseDirectRegistryFallback) { Add-NSISDirectUninstallWrites -State $State }
    $Metadata = Complete-NSISMetadata -State $State -SkipLocalizedAppsAndFeaturesEntries
    if ($Mode -eq 'Fast' -and -not [string]::IsNullOrWhiteSpace($Metadata.DisplayName) -and -not [string]::IsNullOrWhiteSpace($Metadata.DisplayVersion) -and -not [string]::IsNullOrWhiteSpace($Metadata.ProductCode)) {
      # Fast mode is an explicit optimization: direct uninstall writes must
      # already provide complete deterministic identity before callbacks are skipped.
      return [pscustomobject]@{
        State       = $State
        Layout      = $Layout
        HeaderData  = $HeaderData
        Metadata    = Complete-NSISMetadata -State $State
        IsEarlyExit = $true
      }
    }

    $InitializationCompleted = $true
    if ($Layout.CodeOnInit -ge 0) {
      try {
        $null = Invoke-NSISCodeSegment -State $State -Position $Layout.CodeOnInit
      } catch {
        # Continue parsing when non-metadata callbacks loop or rely on unsupported runtime state.
        $InitializationCompleted = $false
      }
    }

    if (-not $InitializationCompleted -and -not [string]::IsNullOrWhiteSpace($Architecture)) {
      # Some legacy installers execute complex UI helpers before their x64.nsh
      # probe. If that prefix exceeds the watchdog, resume at the source-backed
      # architecture macro rather than losing architecture-selected ARP values.
      if ($ArchitectureProbeStart -ge 0) {
        try {
          $null = Invoke-NSISCodeSegment -State $State -Position $ArchitectureProbeStart
        } catch {
          # Later UI-only initialization remains optional after the architecture
          # branch has had an opportunity to populate deterministic variables.
        }
      }
    }

    if ($HasTargetScopeResolver) {
      # Enter the compiled scope setter directly after initialization. This
      # mirrors the deterministic MultiUser macro branch without emulating UAC,
      # account privilege checks, dialogs, or command-line parsing.
      Initialize-NSISTargetRegistryState -State $State
      try {
        $null = Invoke-NSISCodeSegment -State $State -Position $ScopeSelectionStart
      } catch {
        $State.Warnings.Add("The compiled '$Scope' scope selector could not be simulated completely: $($_.Exception.Message)")
      }
    }

    # Initialization commonly establishes SHCTX before install sections begin.
    # Replay explicit writes so their scope reflects that context instead of the
    # conservative pre-simulation fallback used by the first literal scan.
    if ($State.ShellVarContext -and -not $HasTargetScopeResolver) { Add-NSISDirectUninstallWrites -State $State }

    # Very large NSISBI installers can contain one extraction command per
    # payload file. Walking all of those commands adds no identity evidence once
    # initialization and explicit uninstall writes are complete, and can take
    # minutes for Unity-sized archives. Keep Full as the normal behavior while
    # bounding this payload-only path after deterministic ARP metadata is known.
    $InitializedMetadata = Complete-NSISMetadata -State $State -SkipLocalizedAppsAndFeaturesEntries
    if ($HeaderData.IsNsisBi -and $State.Entries.Count -gt $Script:NSIS_MAX_FULL_SIMULATION_ENTRY_COUNT -and
      -not [string]::IsNullOrWhiteSpace($InitializedMetadata.DisplayName) -and
      -not [string]::IsNullOrWhiteSpace($InitializedMetadata.DisplayVersion) -and
      -not [string]::IsNullOrWhiteSpace($InitializedMetadata.ProductCode)) {
      $State.Warnings.Add("Full section simulation was skipped after deterministic uninstall metadata was recovered because the NSISBI command table contains $($State.Entries.Count) entries.")
      return [pscustomobject]@{
        State           = $State
        Layout          = $Layout
        HeaderData      = $HeaderData
        Metadata        = Complete-NSISMetadata -State $State
        IsEarlyExit     = $true
        EarlyExitReason = 'LargeNsisBiCommandTable'
      }
    }

    foreach ($Section in $State.Sections) {
      if ($Section.CodeOffset -lt 0) { continue }

      # Sections are independent entry points. Unsupported or looping sections
      # do not discard evidence already recovered from other sections.
      try {
        $Result = Invoke-NSISCodeSegment -State $State -Position $Section.CodeOffset
      } catch {
        continue
      }
      if ($Result -eq 'Quit') { break }
    }

    if ($Layout.CodeOnInstSuccess -ge 0) {
      try {
        $null = Invoke-NSISCodeSegment -State $State -Position $Layout.CodeOnInstSuccess
      } catch {
        # Continue parsing when the success callback contains unsupported UI-only behavior.
      }
    }

    if ($UseDirectRegistryFallback -and
      ([string]::IsNullOrWhiteSpace($State.Metadata.DisplayVersion) -or [string]::IsNullOrWhiteSpace($State.Metadata.ProductCode))) {
      # Re-scan literal EW_WRITEREG instructions only when dynamic control flow
      # did not reach enough explicit uninstall metadata.
      Add-NSISDirectUninstallWrites -State $State
    }

    return [pscustomobject]@{
      State       = $State
      Layout      = $Layout
      HeaderData  = $HeaderData
      Metadata    = Complete-NSISMetadata -State $State
      IsEarlyExit = $false
    }
  }
}

function Get-NSISPlainStrings {
  <#
  .SYNOPSIS
    Recover plain strings from the decoded NSIS strings block for static feature detection
  .PARAMETER State
    The mutable NSIS execution state
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  $Strings = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $Encoding = if ($State.VersionInfo.Unicode) { [System.Text.Encoding]::Unicode } else { [System.Text.Encoding]::Default }
  $Step = if ($State.VersionInfo.Unicode) { 2 } else { 1 }
  $Start = 0
  $Index = 0

  while ($Index -lt $State.StringsBlock.Length) {
    $IsTerminator = if ($State.VersionInfo.Unicode) {
      $Index + 1 -lt $State.StringsBlock.Length -and $State.StringsBlock[$Index] -eq 0x00 -and $State.StringsBlock[$Index + 1] -eq 0x00
    } else {
      $State.StringsBlock[$Index] -eq 0x00
    }

    if ($IsTerminator) {
      if ($Index -gt $Start) {
        $Text = $Encoding.GetString($State.StringsBlock, $Start, $Index - $Start).Trim()
        if (-not [string]::IsNullOrWhiteSpace($Text)) { $null = $Strings.Add($Text) }
      }

      $Index += $Step
      $Start = $Index
    } else {
      $Index += $Step
    }
  }

  if ($State.LanguageTable) {
    foreach ($Offset in $State.LanguageTable.StringOffsets) {
      if ($Offset -eq 0) { continue }
      $Text = Get-NSISString -State $State -RelativeOffset $Offset
      if (-not [string]::IsNullOrWhiteSpace($Text)) { $null = $Strings.Add($Text) }
    }
  }

  return @($Strings)
}

function Get-NSISInstallerSwitchInfo {
  <#
  .SYNOPSIS
    Extract command-line switch evidence from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    # Reuse one full parse/simulation and inspect its decoded string table; do not
    # invoke individual metadata readers, which would parse the installer again.
    $Simulation = Invoke-NSISStaticSimulation -Path $Path
    $Strings = Get-NSISPlainStrings -State $Simulation.State
    $TauriInfo = Get-NSISTauriInstallerInfo -State $Simulation.State
    $Switches = [System.Collections.Generic.List[object]]::new()
    $RejectedSwitches = [System.Collections.Generic.List[object]]::new()
    $Seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $Pattern = '(?<![A-Za-z0-9_./\\-])(?:--[A-Za-z][A-Za-z0-9._-]+|/[A-Za-z](?:[A-Za-z0-9._-]+)?)(?::[^\s"''<>]+|=[^\s"''<>]+)?'
    $DefaultSwitches = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Switch in @('/S', '/NCRC', '/D', '/SD', '/LANG', '/LOG')) { $null = $DefaultSwitches.Add($Switch) }
    $ScopeSwitches = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Switch in @('/CURRENTUSER', '/currentuser', '/AllUsers', '/ALLUSERS', '/allusers', '--all-users', '--current-user')) { $null = $ScopeSwitches.Add($Switch) }
    $SilentSwitches = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Switch in @('/S', '/silent', '/verysilent', '--silent', '--updated')) { $null = $SilentSwitches.Add($Switch) }
    $TauriSwitchPurposes = [ordered]@{
      '/P'      = 'Passive installation with progress'
      '/NS'     = 'Suppress shortcut creation'
      '/UPDATE' = 'Internal updater mode'
      '/R'      = 'Run the application after silent or passive installation'
      '/ARGS'   = 'Arguments passed to the application launched by /R'
    }
    $ParsingMarkers = @($Strings | Where-Object {
        $_ -match '(?i)\b(TestParameter|GetParameters|GetOptions|IfSilent|StrStr|CommandLine|Parameters)\b'
      } | Select-Object -First 20)

    # A slash token is accepted only when known, adjacent to command-line parser
    # evidence, or a short standalone token. This filters nested process switches.
    foreach ($String in $Strings) {
      foreach ($Match in [regex]::Matches($String, $Pattern)) {
        $Value = $Match.Value
        $Name = if ($Value -match '^([^:=]+)') { $Matches[1] } else { $Value }
        if ($Name -match '\.(exe|dll|msi|zip|7z|ico|png|jpg|jpeg|json|yml|yaml|txt|html?)$') { continue }
        if ($Name -match '^/[A-Z]:$') { continue }

        $IsTauriSwitch = $TauriInfo.IsTauri -and $TauriSwitchPurposes.Contains($Name)
        $IsKnownSwitch = $DefaultSwitches.Contains($Name) -or $ScopeSwitches.Contains($Name) -or $SilentSwitches.Contains($Name) -or $IsTauriSwitch
        $HasParsingEvidence = $String -match '(?i)\b(TestParameter|GetParameters|GetOptions|IfSilent|StrStr|CommandLine|Parameters)\b'
        $EscapedValue = [regex]::Escape($Value)
        $TrimmedString = $String.Trim()
        $IsStandaloneEvidence = $TrimmedString -eq $Value -or ($TrimmedString.Length -le 160 -and $TrimmedString -match "(^|\s)$EscapedValue(\s|$)")
        $LooksLikeNestedCommand = $String -match '(?i)\b(taskkill|cmd(?:\.exe)?|powershell(?:\.exe)?|reg(?:\.exe)?|regsvr32(?:\.exe)?|msiexec(?:\.exe)?|rundll32(?:\.exe)?)\b'
        if (-not ($IsKnownSwitch -or $HasParsingEvidence -or ($IsStandaloneEvidence -and -not $LooksLikeNestedCommand))) {
          $RejectedSwitches.Add([pscustomobject]@{
              Switch   = $Value
              Reason   = 'Internal command-line or non-installer switch evidence'
              Evidence = $String
            })
          continue
        }
        if (-not $Seen.Add($Value)) { continue }
        $Evidence = @($Strings | Where-Object { $_ -like "*$Value*" } | Select-Object -First 5)
        $Switches.Add([pscustomobject]@{
            Switch              = $Value
            Name                = $Name
            IsDefaultNsisSwitch = $DefaultSwitches.Contains($Name)
            IsScopeSwitch       = $ScopeSwitches.Contains($Name)
            IsSilentSwitch      = $SilentSwitches.Contains($Name)
            IsTauriSwitch       = $IsTauriSwitch
            Purpose             = if ($IsTauriSwitch) { $TauriSwitchPurposes[$Name] } else { $null }
            IsCustomCandidate   = -not $DefaultSwitches.Contains($Name)
            Evidence            = $Evidence
          })
      }
    }

    $AdditionalSwitches = @($Switches | Where-Object { $_.IsCustomCandidate } | Select-Object -ExpandProperty Switch)

    $Warnings = [System.Collections.Generic.List[string]]::new()
    $Warnings.Add('Switch extraction is static string evidence. Confirm switch control-flow in the NSIS script or a VM before using custom switches in manifests.')
    if ($TauriInfo.IsTauri) {
      $Warnings.Add('Tauri /P is passive installation with progress; /R launches the application after installation, while /UPDATE and /ARGS are internal update/run arguments rather than general manifest switches.')
    }

    [pscustomobject]@{
      Path                       = (Get-Item -Path $Path -Force).FullName
      InstallerType              = 'Nullsoft'
      IsTauri                    = $TauriInfo.IsTauri
      TauriInstallerMode         = $TauriInfo.InstallerMode
      Switches                   = $Switches.ToArray()
      TauriSwitches              = @($Switches | Where-Object { $_.IsTauriSwitch })
      AdditionalSwitches         = $AdditionalSwitches
      ScopeSwitches              = @($Switches | Where-Object { $_.IsScopeSwitch } | Select-Object -ExpandProperty Switch)
      SilentSwitches             = @($Switches | Where-Object { $_.IsSilentSwitch } | Select-Object -ExpandProperty Switch)
      CommandLineParsingEvidence = $ParsingMarkers
      RejectedSwitchCandidates   = $RejectedSwitches.ToArray()
      Warnings                   = [string[]]$Warnings.ToArray()
    }
  }
}

function Read-AdditionalInstallerSwitchesFromNSIS {
  <#
  .SYNOPSIS
    Read non-default command-line switch candidates from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    (Get-NSISInstallerSwitchInfo -Path $Path).AdditionalSwitches
  }
}

function Get-ElectronBuilderNSISArchitecture {
  <#
  .SYNOPSIS
    Infer the preferred WinGet architecture from electron-builder app package files
  .PARAMETER Architectures
    The detected electron-builder app package architectures
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The detected electron-builder app package architectures')]
    [string[]]$Architectures
  )

  # electron-builder universal installers with x86 payloads are x86-compatible,
  if ($Architectures -contains 'x86') { return 'x86' }
  if ($Architectures -contains 'x64') { return 'x64' }
  if ($Architectures -contains 'arm64') { return 'arm64' }
  return $null
}

function Get-ElectronBuilderNSISDetection {
  <#
  .SYNOPSIS
    Detect electron-builder payload evidence from simulated NSIS state
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Strings
    Plain strings recovered from the NSIS strings block
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'Plain strings recovered from the NSIS strings block')]
    [string[]]$Strings
  )

  # electron-builder's architecture payload names are compiler-generated format
  # evidence; generic Electron strings or `--updated` alone are insufficient.
  $Architectures = [System.Collections.Generic.List[string]]::new()
  foreach ($Value in @($State.Files) + @($Strings)) {
    if ($Value -match '(?i)(^|[\\/])app-32\.(7z|zip)$|(^|[\\/])app-32$') {
      if (-not $Architectures.Contains('x86')) { $Architectures.Add('x86') }
    }
    if ($Value -match '(?i)(^|[\\/])app-64\.(7z|zip)$|(^|[\\/])app-64$') {
      if (-not $Architectures.Contains('x64')) { $Architectures.Add('x64') }
    }
    if ($Value -match '(?i)(^|[\\/])app-arm64\.(7z|zip)$|(^|[\\/])app-arm64$') {
      if (-not $Architectures.Contains('arm64')) { $Architectures.Add('arm64') }
    }
  }

  $AppPackageEvidence = @(
    foreach ($Value in @($State.Files) + @($Strings)) {
      if ($Value -match '(?i)(app-(?:32|64|arm64)(?:\.(?:7z|zip))?)') { $Matches[1].ToLowerInvariant() }
    }
  ) | Select-Object -Unique
  # Scope support is identified independently from architecture because some
  # electron-builder configurations are per-user or per-machine only.
  $HasDualScopeUi = @($Strings).Where({
      $_ -like '*make this software available to all users*' -or
      $_ -like '*Fresh install for all users*' -or
      $_ -like '*Fresh install for current user*'
    }, 'First').Count -gt 0

  $OrderedArchitectures = @('arm64', 'x64', 'x86').Where({ $Architectures.Contains($_) })
  $PortableInfo = Get-NSISPortableLauncherInfo -State $State

  return [pscustomobject]@{
    IsElectronBuilder = $Architectures.Count -gt 0
    IsPortable        = $PortableInfo.IsPortable
    PortableEvidence  = [string[]]$PortableInfo.Evidence
    Architectures     = $OrderedArchitectures
    AppPackageFiles   = $AppPackageEvidence
    HasUpdatedSwitch  = @($Strings).Where({ $_ -eq '--updated' }, 'First').Count -gt 0
    HasDualScopeUi    = $HasDualScopeUi
  }
}

function Test-ElectronBuilder {
  <#
  .SYNOPSIS
    Test whether a Nullsoft installer was built by electron-builder
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Simulation = Invoke-NSISStaticSimulation -Path $Path
    $Strings = Get-NSISPlainStrings -State $Simulation.State
    return (Get-ElectronBuilderNSISDetection -State $Simulation.State -Strings $Strings).IsElectronBuilder
  }
}

function Get-ElectronBuilderNSISInfo {
  <#
  .SYNOPSIS
    Get static electron-builder traits from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Simulation = Invoke-NSISStaticSimulation -Path $Path
    $State = $Simulation.State
    $Strings = Get-NSISPlainStrings -State $State
    $Detection = Get-ElectronBuilderNSISDetection -State $State -Strings $Strings
    $Architectures = @($Detection.Architectures)

    # Prefer explicit dual-scope UI evidence, otherwise retain the uninstall
    # registry hive observed by the shared NSIS simulation.
    $SupportedScopes = if ($Detection.HasDualScopeUi) {
      @('user', 'machine')
    } elseif ($State.Metadata.Scope -eq 'machine') {
      @('machine')
    } else {
      @('user')
    }

    [pscustomobject]@{
      Path                   = (Get-Item -Path $Path -Force).FullName
      InstallerType          = 'Nullsoft'
      Family                 = 'electron-builder'
      IsElectronBuilder      = $Detection.IsElectronBuilder
      IsPortable             = $Detection.IsPortable
      Architectures          = @($Architectures)
      Architecture           = if ($Architectures.Count -gt 0) { Get-ElectronBuilderNSISArchitecture -Architectures @($Architectures) } else { $null }
      SupportedScopes        = [string[]]$SupportedScopes
      SupportsUserScope      = $SupportedScopes -contains 'user'
      SupportsMachineScope   = $SupportedScopes -contains 'machine'
      SupportsDualScope      = $SupportedScopes.Count -gt 1
      ProductCode            = $State.Metadata.ProductCode
      DisplayName            = $State.Metadata.DisplayName
      DisplayVersion         = $State.Metadata.DisplayVersion
      Publisher              = $State.Metadata.Publisher
      DefaultInstallLocation = $State.Metadata.DefaultInstallLocation
      Evidence               = [pscustomobject]@{
        AppPackageFiles  = $Detection.AppPackageFiles
        HasUpdatedSwitch = $Detection.HasUpdatedSwitch
        HasDualScopeUi   = $Detection.HasDualScopeUi
        PortableEvidence = [string[]]$Detection.PortableEvidence
      }
    }
  }
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

function Get-NSISPayloadEntries {
  <#
  .SYNOPSIS
    Read source filenames and data offsets from normalized EW_EXTRACTFILE entries
  .PARAMETER State
    Initialized NSIS parser state containing normalized command and string tables.
  .PARAMETER HeaderData
    Validated first-header and archive layout evidence.
  .PARAMETER Name
    Wildcard matched against the compiled path, safe relative path, and base name.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][pscustomobject]$HeaderData,
    [Parameter(Mandatory)][string]$Name
  )

  $Payloads = [System.Collections.Generic.List[object]]::new()
  foreach ($Entry in $State.Entries) {
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_EXTRACT_FILE) { continue }

    # Standard NSIS stores a uint32 data offset in operand 2. NSISBI widens that
    # value over operands 2 and 3, moving FILETIME and CRC fields to the right.
    $DataOffset = if ($HeaderData.IsNsisBi) {
      [uint64]$Entry.Raw[3] -bor ([uint64]$Entry.Raw[4] -shl 32)
    } else {
      [uint64]$Entry.Raw[3]
    }
    $SourcePath = Get-NSISString -State $State -RelativeOffset $Entry.Values[2]
    $RelativePath = ConvertTo-NSISExtractionRelativePath -Path $SourcePath -DataOffset $DataOffset
    if (-not (Test-ExtractionPattern -Path $SourcePath -Pattern $Name) -and
      -not (Test-ExtractionPattern -Path $RelativePath -Pattern $Name)) { continue }

    $TimeLowIndex = if ($HeaderData.IsNsisBi) { 5 } else { 4 }
    $TimeHighIndex = if ($HeaderData.IsNsisBi) { 6 } else { 5 }
    $Payloads.Add([pscustomobject]@{
        SourcePath   = $SourcePath
        RelativePath = $RelativePath
        DataOffset   = $DataOffset
        TimeLow      = $Entry.Raw[$TimeLowIndex]
        TimeHigh     = $Entry.Raw[$TimeHighIndex]
        Crc32        = if ($HeaderData.IsNsisBi) { $Entry.Raw[8] } else { $null }
      })
    if ($Payloads.Count -gt $Script:NSIS_MAX_EXTRACTION_FILE_COUNT) {
      throw "The NSIS extraction selection exceeds the supported $($Script:NSIS_MAX_EXTRACTION_FILE_COUNT)-file limit"
    }
  }

  return $Payloads.ToArray()
}

function Read-NSISSequentialInteger {
  <#
  .SYNOPSIS
    Read one little-endian unsigned integer from the current stream position
  .PARAMETER Stream
    Sequential decoded stream. The caller owns it and its position advances.
  .PARAMETER Size
    Integer width in bytes: four for standard NSIS or eight for NSISBI.
  #>
  [OutputType([uint64])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateSet(4, 8)][int]$Size
  )

  $Bytes = [byte[]]::new($Size)
  $Read = 0
  while ($Read -lt $Size) {
    $Count = $Stream.Read($Bytes, $Read, $Size - $Read)
    if ($Count -le 0) { throw 'The NSIS payload length field is truncated' }
    $Read += $Count
  }
  return $(if ($Size -eq 8) { [BitConverter]::ToUInt64($Bytes, 0) } else { [uint64][BitConverter]::ToUInt32($Bytes, 0) })
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

      $UnpackedLength = Read-NSISSequentialInteger -Stream $Decoder -Size $HeaderData.PackedSizeWidth
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

function Expand-NSISInstaller {
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
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt'
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
    $Initialized = Initialize-NSISState -HeaderData $HeaderData
    $Selected = Get-NSISPayloadEntries -State $Initialized.State -HeaderData $HeaderData -Name $Name
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

function Get-NSISInfo {
  <#
  .SYNOPSIS
    Get static metadata from a Nullsoft Scriptable Install System installer
  .PARAMETER Path
    The path to the NSIS installer
  .PARAMETER Architecture
    The target Windows architecture used when the installer selects architecture-specific ARP metadata
  .PARAMETER Scope
    The target installation scope used when the installer selects scope-specific ARP metadata
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The target Windows architecture used to resolve architecture-specific ARP metadata')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [Parameter(HelpMessage = 'The target installation scope used to resolve scope-specific ARP metadata')]
    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  process {
    $SimulationArguments = @{ Path = $Path }
    if (-not [string]::IsNullOrWhiteSpace($Architecture)) { $SimulationArguments.Architecture = $Architecture }
    if (-not [string]::IsNullOrWhiteSpace($Scope)) { $SimulationArguments.Scope = $Scope }
    $Metadata = (Invoke-NSISStaticSimulation @SimulationArguments).Metadata
    if ([string]::IsNullOrWhiteSpace($Metadata.DisplayName) -and [string]::IsNullOrWhiteSpace($Metadata.DisplayVersion)) {
      throw 'The NSIS installer does not expose deterministic uninstall metadata'
    }

    # Invoke-NSISStaticSimulation constructs the canonical aggregate result;
    # return it unchanged so bridge callers see exactly the parser's evidence.
    return [pscustomobject]$Metadata
  }
}

function Read-ProductVersionFromNSIS {
  <#
  .SYNOPSIS
    Read the product version from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  .PARAMETER Architecture
    The target Windows architecture used to resolve architecture-specific metadata
  .PARAMETER Scope
    The target installation scope used to resolve scope-specific metadata
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  process {
    $Arguments = @{ Path = $Path }
    if ($Architecture) { $Arguments.Architecture = $Architecture }
    if ($Scope) { $Arguments.Scope = $Scope }
    $Info = Get-NSISInfo @Arguments
    if ([string]::IsNullOrWhiteSpace($Info.DisplayVersion)) { throw 'The NSIS installer does not expose a DisplayVersion value' }
    return $Info.DisplayVersion
  }
}

function Read-ProductNameFromNSIS {
  <#
  .SYNOPSIS
    Read the product name from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  .PARAMETER Architecture
    The target Windows architecture used to resolve architecture-specific metadata
  .PARAMETER Scope
    The target installation scope used to resolve scope-specific metadata
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  process {
    $Arguments = @{ Path = $Path }
    if ($Architecture) { $Arguments.Architecture = $Architecture }
    if ($Scope) { $Arguments.Scope = $Scope }
    $Info = Get-NSISInfo @Arguments
    if ([string]::IsNullOrWhiteSpace($Info.DisplayName)) { throw 'The NSIS installer does not expose a DisplayName value' }
    return $Info.DisplayName
  }
}

function Read-PublisherFromNSIS {
  <#
  .SYNOPSIS
    Read the publisher from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  .PARAMETER Architecture
    The target Windows architecture used to resolve architecture-specific metadata
  .PARAMETER Scope
    The target installation scope used to resolve scope-specific metadata
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  process {
    $Arguments = @{ Path = $Path }
    if ($Architecture) { $Arguments.Architecture = $Architecture }
    if ($Scope) { $Arguments.Scope = $Scope }
    $Info = Get-NSISInfo @Arguments
    if ([string]::IsNullOrWhiteSpace($Info.Publisher)) { throw 'The NSIS installer does not expose a Publisher value' }
    return $Info.Publisher
  }
}

function Read-ProductCodeFromNSIS {
  <#
  .SYNOPSIS
    Read the uninstall registry key name from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  .PARAMETER Architecture
    The target Windows architecture used to resolve architecture-specific metadata
  .PARAMETER Scope
    The target installation scope used to resolve scope-specific metadata
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  process {
    $Arguments = @{ Path = $Path }
    if ($Architecture) { $Arguments.Architecture = $Architecture }
    if ($Scope) { $Arguments.Scope = $Scope }
    $Info = Get-NSISInfo @Arguments
    if ([string]::IsNullOrWhiteSpace($Info.ProductCode)) { throw 'The NSIS installer does not expose an uninstall registry key' }
    return $Info.ProductCode
  }
}

Export-ModuleMember -Function Get-NSISInfo, Expand-NSISInstaller, Get-NSISInstallerSwitchInfo, Read-AdditionalInstallerSwitchesFromNSIS, Test-ElectronBuilder, Get-ElectronBuilderNSISInfo, Read-ProductVersionFromNSIS, Read-ProductNameFromNSIS, Read-PublisherFromNSIS, Read-ProductCodeFromNSIS
