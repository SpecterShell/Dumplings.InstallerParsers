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

$Script:NSISFormatCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'NSISFormatCatalog.psd1')

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

function Import-NSISLz4Decoder {
  <#
  .SYNOPSIS
    Load the bounded raw LZ4 block decoder used by NSISBI MTW records.
  #>
  if (([System.Management.Automation.PSTypeName]'Dumplings.InstallerParsers.NSIS.NsisLz4BlockDecoder').Type) { return }

  $SourcePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\Assets\Source\NSIS\NsisLz4BlockDecoder.cs'
  $null = Import-InstallerManagedSource -Path $SourcePath -TypeName 'Dumplings.InstallerParsers.NSIS.NsisLz4BlockDecoder'
}

function Import-NSISSegmentedReadStream {
  <#
  .SYNOPSIS
    Load the seekable multi-sidecar stream used by NSISBI 3.12 split output.
  #>
  if (([System.Management.Automation.PSTypeName]'Dumplings.InstallerParsers.NSIS.NsisSegmentedReadStream').Type) { return }

  $SourcePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\Assets\Source\NSIS\NsisSegmentedReadStream.cs'
  $null = Import-InstallerManagedSource -Path $SourcePath -TypeName 'Dumplings.InstallerParsers.NSIS.NsisSegmentedReadStream'
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
$NSISBI_CURRENT_FLAG_FORMAT = [uint32]0x10
$NSISBI_CURRENT_FLAG_HAS_EXTERNAL_FILE = [uint32]0x20
$NSISBI_CURRENT_FLAG_IS_STUB_INSTALLER = [uint32]0x40
$NSIS_ARCHIVE_ALIGNMENT = 512
$NSIS_MAX_BACKWARD_PE_SCAN = 1048576
$NSIS_MAX_FILE_SIZE = [uint64]4294967295
$NSIS_MAX_HEADER_SIZE = 134217728
$NSIS_MAX_ENTRY_COUNT = 33554432
$NSIS_MAX_FULL_SIMULATION_ENTRY_COUNT = 16384
$NSIS_MAX_EXTRACTION_FILE_COUNT = 262144
$NSIS_DEFAULT_MAXIMUM_EXPANDED_BYTES = 1073741824
$NSIS_MAX_VIRTUAL_FILE_BYTES = 4194304
$NSISBI_MTW_BLOCK_HEADER_SIZE = 3
# Current NSISBI codecs use different MTW block sizes: BZip2 uses 900,000
# bytes, zlib/LZ4 use 1 MiB, and LZMA uses 4 MiB. Keep the parser bounds at
# the largest source-defined route so older observed 2 MiB blocks also remain
# valid without weakening the per-record output limit beyond current NSISBI.
$NSISBI_MTW_BLOCK_DATA_SIZE = 4194304
$NSISBI_MTW_BLOCK_BUFFER_SIZE = 4614758
$NSISBI_MTW_LZMA_DICTIONARY_SIZES = [uint32[]]@(2307891, 4614758)
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
$NSIS_SECTION_OFFSET_INSTALL_TYPES = 4
$NSIS_SECTION_OFFSET_FLAGS = 8
$NSIS_SECTION_OFFSET_CODE = 12
$NSIS_SECTION_OFFSET_CODE_SIZE = 16
$NSIS_SECTION_OFFSET_SIZE_KB = 20
$NSIS_DEFAULT_LANGUAGE = 1033
$NSIS_MAX_WATCHDOG_MULTIPLIER = 2
$NSIS_MAX_BRANCH_PATHS = 16
$NSIS_MAX_BRANCH_DEPTH = 8
$NSIS_UNINSTALL_KEY_PATTERN = '(?i)^Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\'
$NSIS_UNPACKED_HEADER_SOLID_FLAG = [uint32]2147483648
$NSISBI_PRE304_EXTERNAL_DATA_FLAG = [uint32]2147483648
$NSISBI_PRE304_DATA_LENGTH_MASK = [uint32]2147483647

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
$NSIS_EXEC_FLAG_ERROR = 2
$NSIS_EXEC_FLAG_SILENT = 8
$NSIS_EXEC_FLAG_REG_VIEW = 12
$NSIS_SECTION_FLAG_SELECTED = 1

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
$NSIS_OPCODE_RENAME = 16
$NSIS_OPCODE_GET_FULL_PATH_NAME = 17
$NSIS_OPCODE_SEARCH_PATH = 18
$NSIS_OPCODE_GET_TEMP_FILE_NAME = 19
$NSIS_OPCODE_EXTRACT_FILE = 20
$NSIS_OPCODE_DELETE_FILE = 21
$NSIS_OPCODE_MESSAGE_BOX = 22
$NSIS_OPCODE_REMOVE_DIRECTORY = 23
$NSIS_OPCODE_EXTRACT_STUB_FILE = 1000
$NSIS_OPCODE_VERIFY_EXTERNAL_FILE = 1001
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
$NSIS_OPCODE_GET_FILE_TIME = 42
$NSIS_OPCODE_GET_DLL_VERSION = 43
$NSIS_OPCODE_DELETE_REG = 50
$NSIS_OPCODE_WRITE_REG = 51
$NSIS_OPCODE_READ_REG = 52
$NSIS_OPCODE_ENUM_REG = 53
$NSIS_OPCODE_FILE_CLOSE = 54
$NSIS_OPCODE_FILE_OPEN = 55
$NSIS_OPCODE_FILE_WRITE = 56
$NSIS_OPCODE_FILE_READ = 57
$NSIS_OPCODE_FILE_SEEK = 58
$NSIS_OPCODE_FIND_CLOSE = 59
$NSIS_OPCODE_FIND_NEXT = 60
$NSIS_OPCODE_FIND_FIRST = 61
$NSIS_OPCODE_WRITE_UNINSTALLER = 62
$NSIS_OPCODE_SECTION_SET = 63
$NSIS_OPCODE_INSTALL_TYPE_SET = 64
$NSIS_OPCODE_GET_OS_INFO = 65
$NSIS_OPCODE_RESERVED = 66
$NSIS_OPCODE_LOCK_WINDOW = 67
$NSIS_OPCODE_FILE_WRITE_UTF16 = 68
$NSIS_OPCODE_FILE_READ_UTF16 = 69
$NSIS_OPCODE_LOG = 70
$NSIS_OPCODE_FIND_PROC = 71
$NSIS_OPCODE_GET_FONT_VERSION = 72
$NSIS_OPCODE_GET_FONT_NAME = 73

$NSIS_OPCODE_GET_DLG_ITEM = 35

$NSIS_OPCODE_REGISTER_DLL = 44
$NSIS_OPCODE_CREATE_SHORTCUT = 45
$NSIS_OPCODE_COPY_FILES = 46
$NSIS_OPCODE_WRITE_INI = 48
$NSIS_OPCODE_READ_INI = 49
$NSIS_COMMAND_PARAMETER_COUNTS = [int[]]@(
  0, 0, 1, 1, 0, 2, 6, 1, 0, 2, 2, 3, 3, 4, 4, 2,
  4, 3, 2, 2, 6, 2, 6, 2, 2, 4, 5, 3, 6, 4, 4, 6,
  5, 6, 3, 3, 2, 4, 5, 4, 6, 3, 3, 4, 6, 6, 4, 1,
  5, 4, 5, 6, 5, 5, 1, 4, 3, 4, 4, 1, 2, 3, 4, 5,
  4, 6, 2, 1, 4, 4, 2, 2, 2, 2
)

function Get-NSISCatalogProfile {
  <#
  .SYNOPSIS
    Resolve one immutable NSIS serialized-format profile by catalog ID.
  .PARAMETER Id
    Stable profile ID from NSISFormatCatalog.psd1.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The stable NSIS format profile ID')]
    [string]$Id
  )

  # PowerShell's Where() method returns a collection even in First mode. Select
  # the element explicitly; treating that collection as a hashtable silently
  # projects null route properties and breaks opcode normalization.
  $ProfileCandidates = @($Script:NSISFormatCatalog.Profiles).Where({ $_.Id -ceq $Id }, 'First')
  if ($ProfileCandidates.Count -eq 0) { throw "Unknown NSIS format profile '$Id'." }
  $CatalogProfile = $ProfileCandidates[0]

  # Return a private projection so per-installer detection evidence never
  # mutates the module-wide PowerShell data-file catalog.
  $Result = [ordered]@{}
  foreach ($Key in $CatalogProfile.Keys) { $Result[$Key] = $CatalogProfile[$Key] }
  $Result.Edition = [string]$Script:NSISFormatCatalog.Editions[$CatalogProfile.EditionId]
  return [pscustomobject]$Result
}

function Test-NSISFormatCatalog {
  <#
  .SYNOPSIS
    Validate that every NSIS catalog profile resolves all parser routes.
  #>
  [OutputType([bool])]
  param ()

  $RequiredProperties = @(
    'Id', 'EditionId', 'Generation', 'VersionRange', 'CharacterMode',
    'CommandType', 'FirstHeaderRoute', 'HeaderRoute', 'EntryRoute',
    'StringRoute', 'OpcodeRoute', 'VariableRoute', 'PayloadRoute',
    'CompressionRoutes', 'ChecksumRoute', 'Supported'
  )
  $SeenIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
  foreach ($CatalogProfile in @($Script:NSISFormatCatalog.Profiles)) {
    foreach ($Property in $RequiredProperties) {
      if (-not $CatalogProfile.ContainsKey($Property)) { throw "NSIS profile '$($CatalogProfile.Id)' is missing '$Property'." }
    }
    if (-not $SeenIds.Add([string]$CatalogProfile.Id)) { throw "Duplicate NSIS profile ID '$($CatalogProfile.Id)'." }
    if (-not $Script:NSISFormatCatalog.Editions.ContainsKey($CatalogProfile.EditionId)) {
      throw "NSIS profile '$($CatalogProfile.Id)' references unknown edition '$($CatalogProfile.EditionId)'."
    }
  }
  return $true
}

$null = Test-NSISFormatCatalog

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

$NSIS_WINDOWS_DIRECTORY = '%SystemRoot%'
$NSIS_SYSTEM_DIRECTORY = '%SystemRoot%\System32'

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
  '%AppData%',
  'PrintHood',
  '%LocalAppData%',
  'ALTStartUp',
  'ALTStartUp',
  'Favorites',
  'InternetCache',
  'Cookies',
  'History',
  '%AppData%',
  $Script:NSIS_WINDOWS_DIRECTORY,
  $Script:NSIS_WINDOWS_DIRECTORY,
  '%ProgramFiles%',
  'Pictures',
  '%UserProfile%',
  $Script:NSIS_SYSTEM_DIRECTORY,
  '%ProgramFiles(x86)%',
  '%ProgramFiles%\Common Files',
  '%ProgramFiles(x86)%\Common Files',
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

function Get-NSISPEStubOffsetStream {
  <#
  .SYNOPSIS
    Locate the PE stub whose alignment coordinate system owns an NSIS archive.
  .PARAMETER Stream
    Caller-owned seekable installer stream.
  .PARAMETER FirstHeaderOffset
    Absolute file offset of the validated NSIS first header.
  .OUTPUTS
    Absolute PE-stub offset, or -1 when no bounded valid stub exists.
  #>
  [OutputType([long])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$FirstHeaderOffset
  )

  # Offset zero owns the archive only when the first header is aligned in that
  # coordinate system. A resource-embedded inner PE can coexist with a valid
  # outer PE, but its nonzero alignment remainder identifies the inner stub.
  if (($FirstHeaderOffset % $Script:NSIS_ARCHIVE_ALIGNMENT) -eq 0) {
    try { if (Get-PELayout -Stream $Stream) { return 0L } } catch { }
  }
  $MinimumOffset = [Math]::Max(0L, $FirstHeaderOffset - $Script:NSIS_MAX_BACKWARD_PE_SCAN)
  for ($Offset = $FirstHeaderOffset - $Script:NSIS_ARCHIVE_ALIGNMENT; $Offset -ge $MinimumOffset; $Offset -= $Script:NSIS_ARCHIVE_ALIGNMENT) {
    if ($Offset + 64 -gt $Stream.Length) { continue }
    $Candidate = New-BoundedReadStream -Stream $Stream -Offset $Offset -Length ($FirstHeaderOffset - $Offset) -LeaveOpen
    try { if (Get-PELayout -Stream $Candidate) { return [long]$Offset } } catch { } finally { $Candidate.Dispose() }
  }
  return -1L
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

function Get-NSISPEStubOffsetBytes {
  <#
  .SYNOPSIS
    Locate the owning PE stub in a synthetic or already-bounded byte array.
  .PARAMETER Bytes
    Bytes containing the candidate PE and NSIS archive.
  .PARAMETER FirstHeaderOffset
    Candidate first-header offset in Bytes.
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][int]$FirstHeaderOffset
  )

  if (($FirstHeaderOffset % $Script:NSIS_ARCHIVE_ALIGNMENT) -eq 0 -and (Test-NSISPEHeaderAtOffset -Bytes $Bytes -Offset 0)) { return 0 }
  $MinimumOffset = [Math]::Max(0, $FirstHeaderOffset - $Script:NSIS_MAX_BACKWARD_PE_SCAN)
  for ($Offset = $FirstHeaderOffset - $Script:NSIS_ARCHIVE_ALIGNMENT; $Offset -ge $MinimumOffset; $Offset -= $Script:NSIS_ARCHIVE_ALIGNMENT) {
    if (Test-NSISPEHeaderAtOffset -Bytes $Bytes -Offset $Offset) { return $Offset }
  }
  return -1
}

function Get-NSISFirstHeaderFlagInfo {
  <#
  .SYNOPSIS
    Resolve standard, legacy NSISBI, and compact NSISBI 3.12 first-header flags.
  .PARAMETER Flags
    Little-endian first-header flags.
  .PARAMETER DataBlockLow
    First NSISBI data-block word at offset 0x1C.
  .PARAMETER DataBlockHigh
    Second NSISBI data-block word at offset 0x20.
  .PARAMETER Pre304
    Interpret the two trailing words using the NSISBI 3.03 ABI, whose stock
    flag mask does not contain an NSISBI marker.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][uint32]$Flags,
    [uint32]$DataBlockLow,
    [uint32]$DataBlockHigh,
    [switch]$Pre304
  )

  if ($Pre304) {
    $HasExternalFile = ($DataBlockHigh -band $Script:NSISBI_PRE304_EXTERNAL_DATA_FLAG) -ne 0
    $LengthHigh = $DataBlockHigh -band $Script:NSISBI_PRE304_DATA_LENGTH_MASK
    return [pscustomobject]@{
      IsNsisBi = $true; FlagRoute = 'nsisbi-pre-3.04.1'; FirstHeaderSize = $Script:NSISBI_FIRST_HEADER_SIZE
      HasLongDataBlockOffsets = $true; HasLargeFileSource = $true; SupportsExternalFiles = $true
      HasExternalFile = $HasExternalFile; IsStubInstaller = $false
      ExternalFileCount = if ($HasExternalFile) { 1 } else { 0 }; ExternalSegmentSize = 0L
      DataBlockLength = [uint64]$DataBlockLow -bor ([uint64]$LengthHigh -shl 32)
    }
  }

  $IsNsisBi = ($Flags -band $Script:NSISBI_CURRENT_FLAG_FORMAT) -ne 0
  if (-not $IsNsisBi) {
    return [pscustomobject]@{
      IsNsisBi = $false; FlagRoute = 'standard'; FirstHeaderSize = $Script:NSIS_FIRST_HEADER_SIZE
      HasLongDataBlockOffsets = $false; HasLargeFileSource = $false; SupportsExternalFiles = $false
      HasExternalFile = $false; IsStubInstaller = $false; ExternalFileCount = 0; ExternalSegmentSize = 0L
      DataBlockLength = [uint64]0
    }
  }

  # NSISBI <=3.10 always sets 0x10/0x20/0x40 and uses 0x80/0x100 for
  # external/stub state. NSISBI 3.12 compacts those flags to 0x10/0x20/0x40.
  # The otherwise ambiguous 0x70 form is separated by the two trailing words:
  # legacy AIO stores a nonzero uint64 data-block length, while current stub
  # mode stores zeroes or a small split count plus a MiB segment size.
  $HasLegacyStateBits = ($Flags -band 0x180) -ne 0
  $LooksCurrentSplit = $DataBlockLow -le 65535 -and $DataBlockHigh -gt 0 -and $DataBlockHigh -le 1048576
  $LooksCurrentUnsplit = $DataBlockLow -eq 0 -and $DataBlockHigh -eq 0
  $IsCurrent = -not $HasLegacyStateBits -and (($Flags -band 0x60) -ne 0) -and ($LooksCurrentSplit -or $LooksCurrentUnsplit)
  if ($Flags -eq $Script:NSISBI_CURRENT_FLAG_FORMAT) { $IsCurrent = $true }

  $FlagRoute = if ($IsCurrent) { 'nsisbi-compact-3.12' } else { 'nsisbi-legacy' }
  $HasExternalFile = if ($IsCurrent) {
    ($Flags -band $Script:NSISBI_CURRENT_FLAG_HAS_EXTERNAL_FILE) -ne 0
  } else {
    ($Flags -band $Script:NSISBI_FLAG_HAS_EXTERNAL_FILE) -ne 0
  }
  $IsStubInstaller = if ($IsCurrent) {
    ($Flags -band $Script:NSISBI_CURRENT_FLAG_IS_STUB_INSTALLER) -ne 0
  } else {
    ($Flags -band $Script:NSISBI_FLAG_IS_STUB_INSTALLER) -ne 0
  }

  return [pscustomobject]@{
    IsNsisBi                = $true
    FlagRoute               = $FlagRoute
    FirstHeaderSize         = $Script:NSISBI_FIRST_HEADER_SIZE
    HasLongDataBlockOffsets = $IsCurrent -or (($Flags -band $Script:NSISBI_FLAG_LONG_DATA_BLOCK_OFFSET) -ne 0)
    HasLargeFileSource      = $IsCurrent -or (($Flags -band $Script:NSISBI_FLAG_LARGE_FILE_SOURCE) -ne 0)
    SupportsExternalFiles   = $true
    HasExternalFile         = $HasExternalFile
    IsStubInstaller         = $IsStubInstaller
    ExternalFileCount       = if ($IsCurrent -and $HasExternalFile) { if ($DataBlockLow) { [int]$DataBlockLow } else { 1 } } else { 0 }
    ExternalSegmentSize     = if ($IsCurrent -and $HasExternalFile -and $DataBlockHigh) { [long]$DataBlockHigh * 1MB } else { 0L }
    DataBlockLength         = if ($IsCurrent -and $HasExternalFile) { [uint64]0 } else { [uint64]$DataBlockLow -bor ([uint64]$DataBlockHigh -shl 32) }
  }
}

function Test-NSISPackedHeaderRecord {
  <#
  .SYNOPSIS
    Test a stock 32-bit NSIS packed-header record without decompressing it.
  .PARAMETER Bytes
    Probe containing the candidate record.
  .PARAMETER Offset
    Probe-relative offset of the uint32 packed-size word.
  .PARAMETER AvailableBytes
    Bytes available from the packed-size word through the declared archive.
  .PARAMETER ExpectedHeaderBytes
    Uncompressed logical header size from the first header.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][int]$Offset,
    [Parameter(Mandatory)][long]$AvailableBytes,
    [Parameter(Mandatory)][uint32]$ExpectedHeaderBytes
  )

  if ($Offset -lt 0 -or $Offset + 4 -gt $Bytes.Length -or $AvailableBytes -le 4) { return $false }
  $Packed = [BitConverter]::ToUInt32($Bytes, $Offset)
  $Size = [uint32]($Packed -band $Script:NSISBI_PRE304_DATA_LENGTH_MASK)
  if ($Size -eq 0 -or $Size -gt $AvailableBytes - 4) { return $false }
  return ($Packed -band $Script:NSISBI_PRE304_EXTERNAL_DATA_FLAG) -ne 0 -or $Size -eq $ExpectedHeaderBytes
}

function Test-NSISCodecStart {
  <#
  .SYNOPSIS
    Test whether a probe begins with a recognized solid NSIS codec stream.
  .PARAMETER Bytes
    Probe containing the candidate codec bytes.
  .PARAMETER Offset
    Probe-relative codec offset.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][int]$Offset
  )

  if ($Offset -lt 0 -or $Offset -ge $Bytes.Length) { return $false }
  $Probe = [byte[]]$Bytes[$Offset..($Bytes.Length - 1)]
  return (Get-NSISLzmaFilterLength -Bytes $Probe) -ge 0 -or
  (Test-NSISBZip2Header -Bytes $Probe) -or
  (Test-NSISZlibHeader -Bytes $Probe)
}

function Test-NSISPre304FirstHeader {
  <#
  .SYNOPSIS
    Distinguish NSISBI 3.03's unmarked 36-byte first header from stock NSIS.
  .DESCRIPTION
    The legacy fork retained stock first-header flags. Its two extra data-size
    words occupy the location where stock NSIS begins its compressed header.
    Stock framing at +0x1C therefore wins; only a structurally valid record at
    +0x24 or an external-data marker without stock framing selects NSISBI.
  .PARAMETER Bytes
    Probe beginning at the candidate first header.
  .PARAMETER LengthOfHeader
    Logical header length from first-header offset 0x14.
  .PARAMETER LengthOfFollowingData
    Declared archive length from first-header offset 0x18.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][uint32]$LengthOfHeader,
    [Parameter(Mandatory)][uint32]$LengthOfFollowingData
  )

  if ($Bytes.Length -lt $Script:NSISBI_FIRST_HEADER_SIZE) { return $false }
  $DataBlockLow = [BitConverter]::ToUInt32($Bytes, 28)
  $DataBlockHigh = [BitConverter]::ToUInt32($Bytes, 32)
  $StockAvailable = [long]$LengthOfFollowingData - $Script:NSIS_FIRST_HEADER_SIZE
  $LooksStock = (Test-NSISPackedHeaderRecord -Bytes $Bytes -Offset 28 -AvailableBytes $StockAvailable -ExpectedHeaderBytes $LengthOfHeader) -or
  (Test-NSISCodecStart -Bytes $Bytes -Offset 28)
  if ($LooksStock) { return $false }

  $HasExternalData = ($DataBlockHigh -band $Script:NSISBI_PRE304_EXTERNAL_DATA_FLAG) -ne 0
  if ($HasExternalData) { return $true }
  if ($DataBlockLow -ne 0 -or $DataBlockHigh -ne 0) { return $false }

  $LegacyAvailable = [long]$LengthOfFollowingData - $Script:NSISBI_FIRST_HEADER_SIZE
  return (Test-NSISPackedHeaderRecord -Bytes $Bytes -Offset 36 -AvailableBytes $LegacyAvailable -ExpectedHeaderBytes $LengthOfHeader) -or
  (Test-NSISCodecStart -Bytes $Bytes -Offset 36)
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
        $Header = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count $Script:NSIS_FIRST_HEADER_SIZE
        $Flags = [BitConverter]::ToUInt32($Header, 0)

        # Reject unknown flag bits and impossible declared ranges before testing
        # the more expensive nearby-PE invariant.
        $InvalidFlagMask = [uint32]([uint64]4294967295 - [uint64]$Script:NSISBI_FIRST_HEADER_FLAGS_MASK)
        if (($Flags -band $InvalidFlagMask) -ne 0) { continue }
        # NSISBI 3.03 uses the stock flag mask. Its additional two words are
        # zero for all-in-one output or carry an external length whose high bit
        # marks the sidecar. A stock payload cannot begin with two zero words
        # because its packed header is nonempty.
        $LengthOfHeader = [BitConverter]::ToUInt32($Header, 20)
        $LengthOfFollowingData = [BitConverter]::ToUInt32($Header, 24)
        $ProbeLength = [int][Math]::Min(64L, $Stream.Length - $Offset)
        $FirstHeaderProbe = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count $ProbeLength
        $PotentialDataBlockWords = if ($Offset + $Script:NSISBI_FIRST_HEADER_SIZE -le $Stream.Length) { [byte[]]$FirstHeaderProbe[28..35] } else { [byte[]]::new(8) }
        $IsPre304 = ($Flags -band $Script:NSISBI_CURRENT_FLAG_FORMAT) -eq 0 -and (Test-NSISPre304FirstHeader -Bytes $FirstHeaderProbe -LengthOfHeader $LengthOfHeader -LengthOfFollowingData $LengthOfFollowingData)
        $IsNsisBi = $IsPre304 -or ($Flags -band $Script:NSISBI_CURRENT_FLAG_FORMAT) -ne 0
        $FirstHeaderSize = if ($IsNsisBi) { $Script:NSISBI_FIRST_HEADER_SIZE } else { $Script:NSIS_FIRST_HEADER_SIZE }
        if ($Offset + $FirstHeaderSize -gt $Stream.Length) { continue }
        $DataBlockWords = if ($IsNsisBi) { $PotentialDataBlockWords } else { [byte[]]::new(8) }
        $FlagInfo = Get-NSISFirstHeaderFlagInfo -Flags $Flags -DataBlockLow ([BitConverter]::ToUInt32($DataBlockWords, 0)) -DataBlockHigh ([BitConverter]::ToUInt32($DataBlockWords, 4)) -Pre304:$IsPre304
        if ($LengthOfHeader -le 0 -or $LengthOfHeader -gt $Script:NSIS_MAX_HEADER_SIZE) { continue }
        if ($LengthOfFollowingData -le $FirstHeaderSize -or $LengthOfFollowingData -gt $Stream.Length - $Offset) { continue }
        # Record the owning stub offset for CRC verification. Stepping backward
        # in 512-byte units handles ordinary, concatenated, and embedded NSIS
        # coordinate systems without accepting an unrelated MZ byte sequence.
        $StubOffset = Get-NSISPEStubOffsetStream -Stream $Stream -FirstHeaderOffset $Offset
        if ($StubOffset -lt 0) { continue }
        return [pscustomobject]@{
          Offset                  = $Offset
          StubOffset              = $StubOffset
          Flags                   = $Flags
          FirstHeaderSize         = $FirstHeaderSize
          IsNsisBi                = $FlagInfo.IsNsisBi
          FlagRoute               = $FlagInfo.FlagRoute
          HasLongDataBlockOffsets = $FlagInfo.HasLongDataBlockOffsets
          HasLargeFileSource      = $FlagInfo.HasLargeFileSource
          SupportsExternalFiles   = $FlagInfo.SupportsExternalFiles
          HasExternalFile         = $FlagInfo.HasExternalFile
          IsStubInstaller         = $FlagInfo.IsStubInstaller
          ExternalFileCount       = $FlagInfo.ExternalFileCount
          ExternalSegmentSize     = $FlagInfo.ExternalSegmentSize
          DataBlockLength         = $FlagInfo.DataBlockLength
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

    $PotentialDataBlockLow = if ($Offset + $Script:NSISBI_FIRST_HEADER_SIZE -le $Bytes.Length) { [BitConverter]::ToUInt32($Bytes, $Offset + 28) } else { [uint32]0 }
    $PotentialDataBlockHigh = if ($Offset + $Script:NSISBI_FIRST_HEADER_SIZE -le $Bytes.Length) { [BitConverter]::ToUInt32($Bytes, $Offset + 32) } else { [uint32]0 }
    $LengthOfHeader = [System.BitConverter]::ToUInt32($Bytes, $Offset + 20)
    $LengthOfFollowingData = [System.BitConverter]::ToUInt32($Bytes, $Offset + 24)
    $ProbeEnd = [Math]::Min($Offset + 63, $Bytes.Length - 1)
    $FirstHeaderProbe = [byte[]]$Bytes[$Offset..$ProbeEnd]
    $IsPre304 = ($Flags -band $Script:NSISBI_CURRENT_FLAG_FORMAT) -eq 0 -and (Test-NSISPre304FirstHeader -Bytes $FirstHeaderProbe -LengthOfHeader $LengthOfHeader -LengthOfFollowingData $LengthOfFollowingData)
    $IsNsisBi = $IsPre304 -or ($Flags -band $Script:NSISBI_CURRENT_FLAG_FORMAT) -ne 0
    $FirstHeaderSize = if ($IsNsisBi) { $Script:NSISBI_FIRST_HEADER_SIZE } else { $Script:NSIS_FIRST_HEADER_SIZE }
    if ($Offset + $FirstHeaderSize -gt $Bytes.Length) { continue }
    $DataBlockLow = if ($IsNsisBi) { [BitConverter]::ToUInt32($Bytes, $Offset + 28) } else { [uint32]0 }
    $DataBlockHigh = if ($IsNsisBi) { [BitConverter]::ToUInt32($Bytes, $Offset + 32) } else { [uint32]0 }
    $FlagInfo = Get-NSISFirstHeaderFlagInfo -Flags $Flags -DataBlockLow $DataBlockLow -DataBlockHigh $DataBlockHigh -Pre304:$IsPre304

    if ($LengthOfHeader -le 0 -or $LengthOfHeader -gt $Script:NSIS_MAX_HEADER_SIZE) { continue }
    if ($LengthOfFollowingData -le $FirstHeaderSize -or $LengthOfFollowingData -gt $Bytes.Length - $Offset) { continue }
    $StubOffset = Get-NSISPEStubOffsetBytes -Bytes $Bytes -FirstHeaderOffset $Offset
    if ($StubOffset -lt 0) { continue }

    return [pscustomobject]@{
      Offset                  = $Offset
      StubOffset              = [long]$StubOffset
      Flags                   = $Flags
      FirstHeaderSize         = $FirstHeaderSize
      IsNsisBi                = $FlagInfo.IsNsisBi
      FlagRoute               = $FlagInfo.FlagRoute
      HasLongDataBlockOffsets = $FlagInfo.HasLongDataBlockOffsets
      HasLargeFileSource      = $FlagInfo.HasLargeFileSource
      SupportsExternalFiles   = $FlagInfo.SupportsExternalFiles
      HasExternalFile         = $FlagInfo.HasExternalFile
      IsStubInstaller         = $FlagInfo.IsStubInstaller
      ExternalFileCount       = $FlagInfo.ExternalFileCount
      ExternalSegmentSize     = $FlagInfo.ExternalSegmentSize
      DataBlockLength         = $FlagInfo.DataBlockLength
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
  .PARAMETER AllowLz4
    Permit raw LZ4 as the signatureless final candidate for a confirmed NSISBI header.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [long]$CompressedSize = -1,
    [switch]$AllowLz4
  )

  if ($Bytes.Length -lt ($Script:NSISBI_MTW_BLOCK_HEADER_SIZE + 2)) { return @() }
  $BlockLength = [int]$Bytes[0] -bor ([int]$Bytes[1] -shl 8) -bor ([int]$Bytes[2] -shl 16)
  if ($BlockLength -le 0 -or $BlockLength -gt $Script:NSISBI_MTW_BLOCK_BUFFER_SIZE) { return @() }
  if ($CompressedSize -ge 0 -and ($Script:NSISBI_MTW_BLOCK_HEADER_SIZE + [long]$BlockLength) -gt $CompressedSize) { return @() }

  # A three-byte integer alone is weak evidence. Require the first wrapped
  # block to expose a source-backed codec signature before classifying MTW.
  $InnerBytes = $Bytes[$Script:NSISBI_MTW_BLOCK_HEADER_SIZE..($Bytes.Length - 1)]
  # NSISBI initializes every MTW LZMA worker with its source-defined block
  # buffer size as the dictionary. Older observed output used a 2 MiB block;
  # 3.12.3 uses a 4 MiB block, so both non-power-of-two dictionary values are
  # structural LZMA evidence.
  if ($InnerBytes.Length -ge 5 -and $InnerBytes[0] -lt (9 * 5 * 5) -and
    [BitConverter]::ToUInt32($InnerBytes, 1) -in $Script:NSISBI_MTW_LZMA_DICTIONARY_SIZES) { return @('Lzma') }
  if (Test-NSISBZip2Header -Bytes $InnerBytes) { return @('BZip2') }
  if (Test-NSISZlibHeader -Bytes $InnerBytes) { return @('Zlib', 'Deflate') }

  # Current NSISBI zlib workers emit raw DEFLATE, while raw LZ4 blocks have no
  # magic. A confirmed MTW route therefore tries bounded DEFLATE first and LZ4
  # second; the logical NSIS header and complete stream framing decide the tie.
  if ($AllowLz4) { return @('Deflate', 'Lz4') }
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
  .PARAMETER AllowLz4
    Permit raw LZ4 probing after the outer first header established NSISBI.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [long]$CompressedSize = -1,
    [switch]$AllowLz4
  )

  return (Get-NSISMtwCompressionCandidate -Bytes $Bytes -CompressedSize $CompressedSize -AllowLz4:$AllowLz4).Count -gt 0
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
    @(Get-NSISMtwCompressionCandidate -Bytes $Probe -CompressedSize ($Stream.Length - $RecordOffset) -AllowLz4)
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
      if ($Candidate -eq 'Lz4') {
        Import-NSISLz4Decoder
        $CompressedBytes = Read-BinaryBytes -Stream $CompressedBlock -Offset 0 -Count $CompressedBlockSize
        $DecodedBytes = [Dumplings.InstallerParsers.NSIS.NsisLz4BlockDecoder]::Decode($CompressedBytes, $Script:NSISBI_MTW_BLOCK_DATA_SIZE)
        $BlockOutput.Write($DecodedBytes, 0, $DecodedBytes.Length)
      } else {
        $InnerProbe = $Probe[$Script:NSISBI_MTW_BLOCK_HEADER_SIZE..($Probe.Length - 1)]
        $LzmaFilterLength = if ($Candidate -eq 'Lzma') { Get-NSISLzmaFilterLength -Bytes $InnerProbe } else { -1 }
        $Decoder = New-NSISDecoder -Compression $Candidate -PayloadStream $CompressedBlock `
          -LzmaFilterLength $LzmaFilterLength -ExpectedOutputBytes $Script:NSISBI_MTW_BLOCK_DATA_SIZE
        $null = Copy-BoundedStream -Source $Decoder -Destination $BlockOutput -MaximumBytes $Script:NSISBI_MTW_BLOCK_DATA_SIZE
      }
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

function Get-NSISArchiveCrcInfo {
  <#
  .SYNOPSIS
    Verify the stock NSIS archive checksum using the runtime's exact byte range.
  .PARAMETER Stream
    Caller-owned installer stream. The checksum helper restores its position.
  .PARAMETER FirstHeader
    Validated first-header candidate including archive and owning-stub offsets.
  .OUTPUTS
    Structured checksum presence, coverage range, expected value, and validity.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][pscustomobject]$FirstHeader
  )

  if (($FirstHeader.Flags -band 0x04) -ne 0) {
    return [pscustomobject]@{ Status = 'NotPresent'; IsPresent = $false; IsVerified = $false; IsValid = $null; StartOffset = $null; Length = 0L; Expected = $null; Actual = $null }
  }
  if ($FirstHeader.IsNsisBi) {
    # Legacy NSISBI checks a fork-specific header CRC rather than the stock
    # continuous archive range. Keep that route explicit until each fork ABI is
    # backed by compiler output and do not apply the stock algorithm to it.
    return [pscustomobject]@{ Status = 'ForkSpecific'; IsPresent = $true; IsVerified = $false; IsValid = $null; StartOffset = $null; Length = 0L; Expected = $null; Actual = $null }
  }

  $ArchiveEnd = [long]$FirstHeader.Offset + [long]$FirstHeader.LengthOfFollowingData
  $ChecksumOffset = $ArchiveEnd - 4
  $ChecksumStart = [long]$FirstHeader.StubOffset + 512
  if ($ChecksumStart -gt $ChecksumOffset -or $ChecksumOffset + 4 -gt $Stream.Length) {
    throw 'The NSIS archive CRC32 range is outside the owning PE and declared archive.'
  }

  $Expected = [uint32](Read-BinaryInteger -Stream $Stream -Offset $ChecksumOffset -Size 4)
  $ChecksumRange = New-BoundedReadStream -Stream $Stream -Offset $ChecksumStart -Length ($ChecksumOffset - $ChecksumStart) -LeaveOpen
  try { $Actual = [uint32](Get-BinaryCrc32 -Stream $ChecksumRange -MaximumBytes $ChecksumRange.Length) }
  finally { $ChecksumRange.Dispose() }

  return [pscustomobject]@{
    Status      = if ($Actual -eq $Expected) { 'Valid' } else { 'Invalid' }
    IsPresent   = $true
    IsVerified  = $true
    IsValid     = $Actual -eq $Expected
    StartOffset = $ChecksumStart
    Length      = $ChecksumOffset - $ChecksumStart
    Expected    = $Expected
    Actual      = $Actual
  }
}

function Read-NSISHeaderDataCandidate {
  <#
  .SYNOPSIS
    Decode one stock or legacy NSISBI first-header route.
  .PARAMETER Path
    The path to the installer.
  .PARAMETER FirstHeaderRoute
    Stock first-header framing or the unmarked NSISBI 3.03 extension.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(Mandatory)]
    [ValidateSet('Standard', 'Pre304')]
    [string]$FirstHeaderRoute
  )

  $InstallerPath = (Get-Item -Path $Path -Force).FullName
  $InstallerItem = Get-Item -LiteralPath $InstallerPath -Force
  if ([uint64]$InstallerItem.Length -gt $Script:NSIS_MAX_FILE_SIZE) { throw 'The NSIS installer exceeds the supported 4 GiB executable size' }
  $InstallerStream = [IO.File]::Open($InstallerPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $FirstHeader = Get-NSISFirstHeaderCandidate -Stream $InstallerStream
    if (-not $FirstHeader) { throw 'The NSIS installer header could not be located at a valid aligned archive start' }

    # NSISBI 3.03 did not reserve a first-header flag. Its two extra words can
    # therefore collide with arbitrary bytes at the beginning of a stock raw
    # Deflate stream. Decode both physical routes and accept only a complete,
    # bounded logical header; the public caller gives stock framing priority.
    if (($FirstHeader.Flags -band $Script:NSISBI_CURRENT_FLAG_FORMAT) -eq 0) {
      $ProbeLength = [int][Math]::Min(64L, $InstallerStream.Length - $FirstHeader.Offset)
      $FirstHeaderProbe = Read-BinaryBytes -Stream $InstallerStream -Offset $FirstHeader.Offset -Count $ProbeLength
      $DataBlockLow = if ($FirstHeaderProbe.Length -ge 36) { [BitConverter]::ToUInt32($FirstHeaderProbe, 28) } else { [uint32]0 }
      $DataBlockHigh = if ($FirstHeaderProbe.Length -ge 36) { [BitConverter]::ToUInt32($FirstHeaderProbe, 32) } else { [uint32]0 }
      if ($FirstHeaderRoute -eq 'Pre304') {
        if (-not (Test-NSISPre304FirstHeader -Bytes $FirstHeaderProbe -LengthOfHeader $FirstHeader.LengthOfHeader -LengthOfFollowingData $FirstHeader.LengthOfFollowingData)) {
          throw 'The unmarked NSISBI 3.03 first-header route did not satisfy its structural invariants.'
        }
        $FlagInfo = Get-NSISFirstHeaderFlagInfo -Flags $FirstHeader.Flags -DataBlockLow $DataBlockLow -DataBlockHigh $DataBlockHigh -Pre304
      } else {
        $FlagInfo = Get-NSISFirstHeaderFlagInfo -Flags $FirstHeader.Flags -DataBlockLow 0 -DataBlockHigh 0
      }
      foreach ($PropertyName in @(
          'FirstHeaderSize', 'IsNsisBi', 'FlagRoute', 'HasLongDataBlockOffsets', 'HasLargeFileSource',
          'SupportsExternalFiles', 'HasExternalFile', 'IsStubInstaller', 'ExternalFileCount',
          'ExternalSegmentSize', 'DataBlockLength'
        )) {
        $FirstHeader.$PropertyName = $FlagInfo.$PropertyName
      }
    }

    $FirstHeaderOffset = $FirstHeader.Offset
    $LengthOfHeader = $FirstHeader.LengthOfHeader
    $LengthOfFollowingData = $FirstHeader.LengthOfFollowingData
    $ArchiveCrcInfo = Get-NSISArchiveCrcInfo -Stream $InstallerStream -FirstHeader $FirstHeader
    if ($ArchiveCrcInfo.IsVerified -and -not $ArchiveCrcInfo.IsValid) {
      throw "The NSIS archive CRC32 does not match: expected $($ArchiveCrcInfo.Expected.ToString('X8')), got $($ArchiveCrcInfo.Actual.ToString('X8'))."
    }

    $PayloadOffset = $FirstHeaderOffset + $FirstHeader.FirstHeaderSize
    $PayloadLength = [long]$LengthOfFollowingData - $FirstHeader.FirstHeaderSize
    # NSISBI 3.03 widens data-block offsets carried by EW_EXTRACTFILE, but its
    # add_data/_dodecomp framing still stores a 32-bit packed-size prefix. Later
    # NSISBI ABIs widen the record prefix as well.
    $PackedSizeWidth = if ($FirstHeader.HasLongDataBlockOffsets -and $FirstHeader.FlagRoute -ne 'nsisbi-pre-3.04.1') { 8 } else { 4 }
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
    # NSISBI 3.03 still uses the stock NSIS compression framing. MTW/LZ4 was
    # introduced by a later fork ABI, so probing it here would misinterpret an
    # ordinary LZMA stream whose first bytes happen to satisfy an MTW record.
    $AllowMtwLz4 = $FirstHeader.IsNsisBi -and $FirstHeader.FlagRoute -ne 'nsisbi-pre-3.04.1'
    $PackedSizeMarker = if ($PackedSizeWidth -eq 8) { [uint64]::Parse('9223372036854775808') } else { [uint64]2147483648 }
    $HasPackedHeaderPrefix = ($PackedHeaderSize -band $PackedSizeMarker) -ne 0

    # A solid LZMA stream can begin with bytes that also form a plausible
    # packed-size value (for example 5D 00 00 80). Keep both physical routes
    # and let exact decompressed-header validation select the real one.
    $HeaderRoutes = [System.Collections.Generic.List[object]]::new()
    if ($PackedHeaderSize -eq $LengthOfHeader) {
      $HeaderRoutes.Add([pscustomobject]@{ Name = 'stored-non-solid'; IsSolid = $false; CandidateHeader = $Signature; Compression = [string[]]@('None'); DataOffset = $PayloadOffset + $PackedSizeWidth; DataLength = [long]$LengthOfHeader })
    } else {
      $DirectCompression = if (Test-NSISMtwHeader -Bytes $Signature -CompressedSize $PayloadLength -AllowLz4:$AllowMtwLz4) {
        [string[]]@('Mtw')
      } elseif ((Get-NSISLzmaFilterLength -Bytes $Signature) -ge 0) {
        [string[]]@('Lzma')
      } elseif (Test-NSISBZip2Header -Bytes $Signature) {
        [string[]]@('BZip2')
      } elseif (Test-NSISZlibHeader -Bytes $Signature) {
        [string[]]@('Zlib', 'Deflate')
      } else {
        [string[]]@()
      }
      if ($DirectCompression.Count -gt 0) {
        $HeaderRoutes.Add([pscustomobject]@{ Name = 'solid-signature'; IsSolid = $true; CandidateHeader = $Signature; Compression = $DirectCompression; DataOffset = $PayloadOffset; DataLength = $PayloadLength })
      }

      if ($HasPackedHeaderPrefix -and $CompressedHeaderSize -gt 0 -and $CompressedHeaderSize -le $PayloadLength - $PackedSizeWidth) {
        $PrefixedHeader = [byte[]]$Signature[$PackedSizeWidth..($Signature.Length - 1)]
        $PrefixedCompression = if (Test-NSISMtwHeader -Bytes $PrefixedHeader -CompressedSize $CompressedHeaderSize -AllowLz4:$AllowMtwLz4) {
          [string[]]@('Mtw')
        } else {
          [string[]]@(Get-NSISCompressionCandidates -Bytes $PrefixedHeader -CompressedSize $CompressedHeaderSize -ExpectedUncompressedSize $LengthOfHeader)
        }
        if ($PrefixedCompression.Count -gt 0) {
          $HeaderRoutes.Add([pscustomobject]@{ Name = 'packed-non-solid'; IsSolid = $false; CandidateHeader = $PrefixedHeader; Compression = $PrefixedCompression; DataOffset = $PayloadOffset + $PackedSizeWidth; DataLength = [long]$CompressedHeaderSize })
        }
      }

      if ($DirectCompression.Count -eq 0) {
        $FallbackCompression = [string[]]@(Get-NSISCompressionCandidates -Bytes $Signature -CompressedSize $PayloadLength -ExpectedUncompressedSize ($LengthOfHeader + $PackedSizeWidth))
        if ($FallbackCompression.Count -gt 0) {
          $HeaderRoutes.Add([pscustomobject]@{ Name = 'solid-probed'; IsSolid = $true; CandidateHeader = $Signature; Compression = $FallbackCompression; DataOffset = $PayloadOffset; DataLength = $PayloadLength })
        }
      }
    }
    if ($HeaderRoutes.Count -eq 0) { throw 'The NSIS header compression and framing route could not be identified' }

    $LastError = $null
    $AttemptedRoutes = [System.Collections.Generic.List[string]]::new()

    # Ambiguous DEFLATE framing is resolved by bounded decode plus exact header
    # length validation; a codec is accepted only when it produces the full header.
    foreach ($HeaderRoute in $HeaderRoutes) {
      $IsSolid = [bool]$HeaderRoute.IsSolid
      $CandidateHeader = [byte[]]$HeaderRoute.CandidateHeader
      $PayloadDataOffset = [long]$HeaderRoute.DataOffset
      $PayloadDataLength = [long]$HeaderRoute.DataLength
      foreach ($Compression in [string[]]$HeaderRoute.Compression) {
        $AttemptedRoutes.Add("$($HeaderRoute.Name)/$Compression")
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
            StubOffset              = $FirstHeader.StubOffset
            FirstHeaderFlags        = $FirstHeader.Flags
            FirstHeaderSize         = $FirstHeader.FirstHeaderSize
            FirstHeaderFlagRoute    = $FirstHeader.FlagRoute
            IsNsisBi                = $FirstHeader.IsNsisBi
            HasLongDataBlockOffsets = $FirstHeader.HasLongDataBlockOffsets
            HasLargeFileSource      = $FirstHeader.HasLargeFileSource
            SupportsExternalFiles   = $FirstHeader.SupportsExternalFiles
            HasExternalFile         = $FirstHeader.HasExternalFile
            IsStubInstaller         = $FirstHeader.IsStubInstaller
            ExternalFileCount       = $FirstHeader.ExternalFileCount
            ExternalSegmentSize     = $FirstHeader.ExternalSegmentSize
            DataBlockLength         = $FirstHeader.DataBlockLength
            ArchiveSize             = $LengthOfFollowingData
            ArchiveCrcInfo          = $ArchiveCrcInfo
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
    }

    throw "Failed to decode the NSIS header using $($AttemptedRoutes -join ', '): $($LastError.Exception.Message)"
  } finally {
    $InstallerStream.Dispose()
  }
}

function Get-NSISHeaderData {
  <#
  .SYNOPSIS
    Locate and decompress the NSIS installer header without invoking external tools.
  .DESCRIPTION
    Unmarked first headers are attempted as stock 28-byte NSIS records before
    the legacy 36-byte NSISBI route. Every route must decode the exact declared
    logical header length and pass the existing archive and stream bounds.
  .PARAMETER Path
    The path to the installer.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory, HelpMessage = 'The path to the installer')][string]$Path)

  $Errors = [Collections.Generic.List[string]]::new()
  foreach ($Route in @('Standard', 'Pre304')) {
    try {
      return Read-NSISHeaderDataCandidate -Path $Path -FirstHeaderRoute $Route
    } catch {
      $Errors.Add("$Route`: $($_.Exception.Message)")
    }
  }
  throw "Failed to decode the NSIS first header using stock and legacy NSISBI framing: $($Errors -join '; ')"
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
  if ($Opcode -eq ($Script:NSIS_OPCODE_EXTRACT_FILE + 1)) { return $Script:NSIS_OPCODE_EXTRACT_STUB_FILE }
  if ($Opcode -eq ($Script:NSIS_OPCODE_EXTRACT_FILE + 2)) { return $Script:NSIS_OPCODE_VERIFY_EXTERNAL_FILE }
  return [int]$Opcode - 2
}

function Get-NSISEntries {
  <#
  .SYNOPSIS
    Parse fixed-width records from the compiled NSIS command table.
  .PARAMETER HeaderBytes
    Decompressed logical NSIS header containing the command block.
  .PARAMETER BlockHeaders
    Validated NSIS block table.
  .PARAMETER VersionInfo
    Optional resolved catalog profile used to normalize raw opcodes.
  .PARAMETER IsNsisBi
    Selects NSISBI's 36-byte record with eight operands instead of the
    standard 28-byte record with six operands.
  .PARAMETER HasNsisBiExternalOpcodes
    Whether this NSISBI ABI inserted its two external-file opcodes after the
    ordinary extraction command. NSISBI 3.03 predates those commands.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header bytes')]
    [byte[]]$HeaderBytes,

    [Parameter(Mandatory, HelpMessage = 'The parsed NSIS block headers')]
    [pscustomobject[]]$BlockHeaders,

    [Parameter(HelpMessage = 'The resolved NSIS command layout')]
    [pscustomobject]$VersionInfo,

    [Parameter(HelpMessage = 'Whether the entry table uses eight NSISBI operands')]
    [bool]$IsNsisBi = $false,

    [Parameter(HelpMessage = 'Whether NSISBI external-file opcodes shift later commands')]
    [bool]$HasNsisBiExternalOpcodes = $true
  )

  $EntryBlock = Get-NSISBlockBytes -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Index 2
  if ($BlockHeaders[2].Count -gt $Script:NSIS_MAX_ENTRY_COUNT) { throw 'The NSIS entry table exceeds the supported parser limit' }
  $EntryCount = [int]$BlockHeaders[2].Count
  $EntrySize = if ($IsNsisBi) { $Script:NSISBI_ENTRY_SIZE } else { $Script:NSIS_ENTRY_SIZE }
  $ValueCount = if ($IsNsisBi) { 9 } else { 7 }
  if ($EntryBlock.Length -lt ($EntryCount * $EntrySize)) { throw 'The NSIS entry table is truncated' }

  $Entries = [System.Collections.Generic.List[object]]::new($EntryCount)
  for ($EntryIndex = 0; $EntryIndex -lt $EntryCount; $EntryIndex++) {
    $Offset = $EntryIndex * $EntrySize
    $Raw = [uint32[]]::new($ValueCount)
    $Values = [int[]]::new($ValueCount)
    for ($ValueIndex = 0; $ValueIndex -lt $ValueCount; $ValueIndex++) {
      $ValueOffset = $Offset + ($ValueIndex * 4)
      $Raw[$ValueIndex] = [System.BitConverter]::ToUInt32($EntryBlock, $ValueOffset)
      $Values[$ValueIndex] = [System.BitConverter]::ToInt32($EntryBlock, $ValueOffset)
    }

    # NSISBI 3.04 and later insert two external-file commands after
    # EW_EXTRACTFILE. The 3.03 ABI widens the record without shifting opcodes.
    $LayoutOpcode = if ($IsNsisBi -and $HasNsisBiExternalOpcodes) { ConvertFrom-NSISBiOpcode -Opcode $Raw[0] } else { [int]$Raw[0] }
    $Opcode = if ($VersionInfo) {
      Get-NSISNormalizedOpcode -Opcode $LayoutOpcode -CatalogProfile $VersionInfo.Profile -LogCmdIsEnabled $VersionInfo.LogCmdIsEnabled
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

function Get-NSISAnsiVariableIndexAtStringOffset {
  <#
  .SYNOPSIS
    Decode an exact variable-only NSIS 2 ANSI string.
  .PARAMETER StringsBlock
    Raw ANSI strings block.
  .PARAMETER Offset
    Character/byte offset into the strings block.
  #>
  [OutputType([Nullable[int]])]
  param (
    [Parameter(Mandatory)][byte[]]$StringsBlock,
    [Parameter(Mandatory)][int]$Offset
  )

  if ($Offset -lt 0 -or $Offset + 3 -ge $StringsBlock.Length) { return $null }
  if ($StringsBlock[$Offset] -ne 253 -or $StringsBlock[$Offset + 3] -ne 0) { return $null }
  return [int](($StringsBlock[$Offset + 1] -band 0x7F) -bor (($StringsBlock[$Offset + 2] -band 0x7F) -shl 7))
}

function Get-NSISLegacyVariableProfileEvidence {
  <#
  .SYNOPSIS
    Distinguish source-backed NSIS variable-table generations through 2.25.
  .DESCRIPTION
    NSIS 2.04 added $_OUTDIR at index 29. NSIS 2.26 inserted EXEPATH and
    EXEFILE, moving HWND_PARENT and $_OUTDIR to their current indexes. This
    follows 7-Zip's DetectNsisType probes and does not infer a marketing
    version from arbitrary strings.
  .PARAMETER StringsBlock
    Raw NSIS 2 ANSI strings block.
  .PARAMETER Entries
    Raw command records after NSISBI command-number normalization.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$StringsBlock,
    [AllowEmptyCollection()]
    [Parameter(Mandatory)][pscustomobject[]]$Entries
  )

  $IsLegacy225 = $false
  $IsLegacy200 = $false
  foreach ($Entry in $Entries) {
    if ($Entry.LayoutOpcode -eq $Script:NSIS_OPCODE_GET_DLG_ITEM) {
      $DialogVariable = Get-NSISAnsiVariableIndexAtStringOffset -StringsBlock $StringsBlock -Offset $Entry.Values[2]
      if ($DialogVariable -eq 27) {
        $IsLegacy225 = $true
        if ($Entry.Values[1] -eq 29) { $IsLegacy200 = $true; break }
      }
      continue
    }
    if ($Entry.LayoutOpcode -eq $Script:NSIS_OPCODE_ASSIGN_VAR -and
      $Entry.Values[1] -eq 29 -and $Entry.Values[3] -eq 0 -and $Entry.Values[4] -eq 0) {
      $SourceVariable = Get-NSISAnsiVariableIndexAtStringOffset -StringsBlock $StringsBlock -Offset $Entry.Values[2]
      if ($SourceVariable -eq $Script:NSIS_PREDEFINED_VAR_OUTDIR) { $IsLegacy225 = $true }
    }
  }

  return [pscustomobject]@{
    VariableRoute = if ($IsLegacy200) { 'legacy-200' } elseif ($IsLegacy225) { 'legacy-225' } else { 'current' }
    IsLegacy200   = $IsLegacy200
    IsLegacy225   = $IsLegacy225
  }
}

function Resolve-NSISCatalogProfile {
  <#
  .SYNOPSIS
    Resolve one catalog profile from validated string, command, and fork evidence.
  .PARAMETER CommandType
    Source-backed command ABI selected by candidate scoring.
  .PARAMETER Unicode
    Whether the strings table uses UTF-16LE code units.
  .PARAMETER IsNsisBi
    Whether the first header and command records use NSISBI extensions.
  .PARAMETER StringsBlock
    Raw strings block used for legacy variable-table detection.
  .PARAMETER Entries
    Parsed raw command records.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$CommandType,
    [Parameter(Mandatory)][bool]$Unicode,
    [Parameter(Mandatory)][bool]$IsNsisBi,
    [Parameter(Mandatory)][byte[]]$StringsBlock,
    [Parameter(Mandatory)][pscustomobject[]]$Entries
  )

  $CharacterMode = if ($Unicode) { 'Unicode' } else { 'Ansi' }
  if ($IsNsisBi) {
    if ($CommandType -cne 'NSIS3') { throw "NSISBI command layout '$CommandType' is not source-backed." }
    return Get-NSISCatalogProfile -Id "nsisbi-nsis3-$($CharacterMode.ToLowerInvariant())"
  }

  if ($CommandType -like 'Park*') {
    $ParkId = switch ($CommandType) {
      'Park1' { 'park-2461-unicode' }
      'Park2' { 'park-2462-unicode' }
      'Park3' { 'park-2463-unicode' }
      default { throw "Unknown Park Unicode command layout '$CommandType'." }
    }
    return Get-NSISCatalogProfile -Id $ParkId
  }

  if ($CommandType -ceq 'NSIS3') {
    return Get-NSISCatalogProfile -Id "official-nsis3-$($CharacterMode.ToLowerInvariant())"
  }

  if ($Unicode) { throw 'The official NSIS 2 serialized format is ANSI; Unicode NSIS 2 installers require a Park profile.' }
  $Legacy = Get-NSISLegacyVariableProfileEvidence -StringsBlock $StringsBlock -Entries $Entries
  $ProfileId = switch ($Legacy.VariableRoute) {
    'legacy-200' { 'official-legacy-200-ansi' }
    'legacy-225' { 'official-legacy-225-ansi' }
    default { 'official-nsis2-ansi' }
  }
  return Get-NSISCatalogProfile -Id $ProfileId
}

function Get-NSISCommandLayoutSemanticSignature {
  <#
  .SYNOPSIS
    Describe how one candidate layout interprets the opcodes used by an installer.
  .DESCRIPTION
    NSIS permits compile-time command removal and source-level command-table
    reordering. Structural arity checks can therefore leave several layouts
    tied even though they assign different meanings to the same raw opcode.
    This signature records only raw opcodes present in the installer, allowing
    equivalent candidates to remain usable while rejecting semantic ambiguity.
  .PARAMETER Entries
    Raw NSIS command records before catalog normalization.
  .PARAMETER Type
    Candidate official or Park command generation.
  .PARAMETER Unicode
    Whether strings use the Unicode command ABI.
  .PARAMETER LogCmdIsEnabled
    Whether EW_LOG occupies its compile-time command-table slot.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][pscustomobject[]]$Entries,
    [Parameter(Mandatory)][string]$Type,
    [Parameter(Mandatory)][bool]$Unicode,
    [Parameter(Mandatory)][bool]$LogCmdIsEnabled
  )

  $UsedOpcodes = [System.Collections.Generic.HashSet[uint32]]::new()
  foreach ($Entry in $Entries) { $null = $UsedOpcodes.Add([uint32]$Entry.LayoutOpcode) }
  $Mappings = foreach ($Opcode in @($UsedOpcodes | Sort-Object)) {
    $CanonicalOpcode = Get-NSISNormalizedOpcode -Opcode $Opcode -Type $Type -Unicode $Unicode -LogCmdIsEnabled $LogCmdIsEnabled
    '{0}={1}' -f $Opcode, $CanonicalOpcode
  }
  return [string]::Join(';', [string[]]$Mappings)
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

  # Explicit control codes constrain the ABI. A Unicode table without any
  # control codes is genuinely ambiguous, so retain official NSIS 3 and all
  # Park generations for command-layout scoring instead of assuming Park1.
  $CandidateTypes = if ($IsNsisBi) {
    @('NSIS3')
  } elseif ($StrongNSIS3) {
    @('NSIS3')
  } elseif ($ParkCount -gt 0) {
    @('Park1', 'Park2', 'Park3')
  } elseif ($Unicode -and $NSIS3Count -eq 0) {
    @('NSIS3', 'Park1', 'Park2', 'Park3')
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
  $ScoredCandidates = @()
  if ($Entries.Count -gt 0) {
    $LogEvidenceByType = @{}
    foreach ($CandidateType in $CandidateTypes) {
      $LogEvidenceByType[$CandidateType] = Test-NSISLogCommandEvidence -Entries $Entries -Type $CandidateType -Unicode $Unicode -StringsBlock $StringsBlock
    }
    $ScoredCandidates = @($Candidates | ForEach-Object {
        $Score = Measure-NSISCommandLayoutCandidate -Entries $Entries -Type $_.Type -Unicode $Unicode -LogCmdIsEnabled $_.LogCmdIsEnabled -IsNsisBi:$IsNsisBi
        [pscustomobject]@{
          Type                         = $_.Type
          LogCmdIsEnabled              = $_.LogCmdIsEnabled
          Priority                     = $_.Priority
          BadCommandCount              = $Score.FatalInvalidCommandCount
          FatalInvalidCommandCount     = $Score.FatalInvalidCommandCount
          IgnoredExtensionOperandCount = $Score.IgnoredExtensionOperandCount
          IgnoredExtensionOperands     = $Score.IgnoredExtensionOperands
          SemanticPenalty              = $Score.SemanticPenalty + $(if ($LogEvidenceByType[$_.Type] -and -not $_.LogCmdIsEnabled) { 1 } else { 0 })
          SemanticSignature            = Get-NSISCommandLayoutSemanticSignature -Entries $Entries -Type $_.Type -Unicode $Unicode -LogCmdIsEnabled $_.LogCmdIsEnabled
        }
      } | Sort-Object -Property BadCommandCount, SemanticPenalty, IgnoredExtensionOperandCount, Priority)
    $BestCandidate = $ScoredCandidates[0]
  } else {
    $BestCandidate | Add-Member -NotePropertyName BadCommandCount -NotePropertyValue 0 -Force
    $BestCandidate | Add-Member -NotePropertyName FatalInvalidCommandCount -NotePropertyValue 0 -Force
    $BestCandidate | Add-Member -NotePropertyName IgnoredExtensionOperandCount -NotePropertyValue 0 -Force
    $BestCandidate | Add-Member -NotePropertyName IgnoredExtensionOperands -NotePropertyValue ([object[]]@()) -Force
    $BestCandidate | Add-Member -NotePropertyName SemanticPenalty -NotePropertyValue 0 -Force
    $BestCandidate | Add-Member -NotePropertyName SemanticSignature -NotePropertyValue '' -Force
    $ScoredCandidates = @($BestCandidate)
  }

  $CatalogProfile = Resolve-NSISCatalogProfile -CommandType $BestCandidate.Type -Unicode $Unicode -IsNsisBi $IsNsisBi -StringsBlock $StringsBlock -Entries $Entries
  $BestScoreCandidates = @($ScoredCandidates | Where-Object {
      $_.BadCommandCount -eq $BestCandidate.BadCommandCount -and
      $_.SemanticPenalty -eq $BestCandidate.SemanticPenalty -and
      $_.IgnoredExtensionOperandCount -eq $BestCandidate.IgnoredExtensionOperandCount
    })
  $BestScoreCount = $BestScoreCandidates.Count
  $SemanticSignatures = @($BestScoreCandidates.SemanticSignature | Select-Object -Unique)
  $HasSemanticAmbiguity = $SemanticSignatures.Count -gt 1
  $DetectionConfidence = if ($HasSemanticAmbiguity) {
    'UnsupportedAmbiguous'
  } elseif ($StrongNSIS3 -or $ParkCount -gt 0 -or $IsNsisBi -or $CatalogProfile.VariableRoute -ne 'current') {
    'Structural'
  } elseif ($BestScoreCount -eq 1) {
    'ValidatedHeuristic'
  } else {
    'Ambiguous'
  }

  return [pscustomobject]@{
    Unicode                      = $Unicode
    Type                         = $BestCandidate.Type
    IsV3                         = $BestCandidate.Type -eq 'NSIS3'
    IsPark                       = $BestCandidate.Type -like 'Park*'
    IsNsisBi                     = $IsNsisBi
    LogCmdIsEnabled              = [bool]$BestCandidate.LogCmdIsEnabled
    BadCommandCount              = [int]$BestCandidate.BadCommandCount
    FatalInvalidCommandCount     = [int]$BestCandidate.FatalInvalidCommandCount
    IgnoredExtensionOperandCount = [int]$BestCandidate.IgnoredExtensionOperandCount
    IgnoredExtensionOperands     = [object[]]@($BestCandidate.IgnoredExtensionOperands)
    Profile                      = $CatalogProfile
    CatalogProfileId             = $CatalogProfile.Id
    EditionId                    = $CatalogProfile.EditionId
    Edition                      = $CatalogProfile.Edition
    CharacterMode                = $CatalogProfile.CharacterMode
    Generation                   = $CatalogProfile.Generation
    VersionRange                 = $CatalogProfile.VersionRange
    CompilerVersion              = $null
    DetectionConfidence          = $DetectionConfidence
    HasSemanticAmbiguity         = $HasSemanticAmbiguity
    CandidateLayouts             = [pscustomobject[]]$ScoredCandidates
    StringCodeCounts             = [pscustomobject]@{
      NSIS2 = $NSIS2Count
      NSIS3 = $NSIS3Count
      Park  = $ParkCount
    }
  }
}

function Test-NSISLogCommandEvidence {
  <#
  .SYNOPSIS
    Test source-defined EW_LOG operand shapes for one candidate command layout.
  .PARAMETER Entries
    Raw command records before catalog normalization.
  .PARAMETER Type
    Candidate official or Park command generation.
  .PARAMETER Unicode
    Whether string offsets address UTF-16LE code units.
  .PARAMETER StringsBlock
    Raw string table used to bound LogText string operands.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][pscustomobject[]]$Entries,
    [Parameter(Mandatory)][string]$Type,
    [Parameter(Mandatory)][bool]$Unicode,
    [Parameter(Mandatory)][byte[]]$StringsBlock
  )

  $MaximumStringOffset = if ($Unicode) { [Math]::Floor($StringsBlock.Length / 2) } else { $StringsBlock.Length }
  $Found = $false
  foreach ($Entry in $Entries) {
    $Opcode = Get-NSISNormalizedOpcode -Opcode $Entry.LayoutOpcode -Type $Type -Unicode $Unicode -LogCmdIsEnabled $true
    if ($Opcode -ne $Script:NSIS_OPCODE_LOG) { continue }
    $Mode = [int]$Entry.Raw[1]
    if ($Mode -notin @(0, 1)) { return $false }
    if ($Mode -eq 0 -and ([uint32]$Entry.Raw[2] -ge $MaximumStringOffset)) { return $false }
    for ($Index = 3; $Index -le 6; $Index++) {
      if ($Entry.Raw[$Index] -ne 0) { return $false }
    }
    $Found = $true
  }
  return $Found
}

function ConvertFrom-NSISParkOpcode {
  <#
  .SYNOPSIS
    Normalize one Park Unicode opcode using its catalogued insertion count.
  .PARAMETER Opcode
    Raw command number from the Park command table.
  .PARAMETER FontCommandCount
    Number of font-query opcodes inserted before RegisterDLL: zero for Park1,
    one for Park2, and two for Park3.
  .PARAMETER LogCmdIsEnabled
    Whether the build inserted EW_LOG before section commands.
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory)][uint32]$Opcode,
    [Parameter(Mandatory)][ValidateRange(0, 2)][int]$FontCommandCount,
    [Parameter(Mandatory)][bool]$LogCmdIsEnabled
  )

  $Value = [int]$Opcode
  if ($Value -lt $Script:NSIS_OPCODE_REGISTER_DLL) { return $Value }
  if ($FontCommandCount -ge 1) {
    if ($Value -eq $Script:NSIS_OPCODE_REGISTER_DLL) { return $Script:NSIS_OPCODE_GET_FONT_VERSION }
    $Value--
  }
  if ($FontCommandCount -ge 2) {
    if ($Value -eq $Script:NSIS_OPCODE_REGISTER_DLL) { return $Script:NSIS_OPCODE_GET_FONT_NAME }
    $Value--
  }
  if ($Value -lt $Script:NSIS_OPCODE_FILE_SEEK) { return $Value }

  # Park Unicode inserts UTF-16 file operations at FSEEK and FINDPROC after
  # them. Later commands can additionally be shifted by an optional LOG slot.
  if ($Value -eq $Script:NSIS_OPCODE_FILE_SEEK) { return $Script:NSIS_OPCODE_FILE_WRITE_UTF16 }
  if ($Value -eq ($Script:NSIS_OPCODE_FILE_SEEK + 1)) { return $Script:NSIS_OPCODE_FILE_READ_UTF16 }
  $Value -= 2
  if ($Value -ge $Script:NSIS_OPCODE_SECTION_SET -and $LogCmdIsEnabled) {
    if ($Value -eq $Script:NSIS_OPCODE_SECTION_SET) { return $Script:NSIS_OPCODE_LOG }
    return $Value - 1
  }
  if ($Value -eq $Script:NSIS_OPCODE_FILE_WRITE_UTF16) { return $Script:NSIS_OPCODE_FIND_PROC }
  return $Value
}

$Script:NSIS_OPCODE_ROUTE_HANDLERS = @{
  official = {
    param([uint32]$Opcode, [bool]$LogCmdIsEnabled)
    $Value = [int]$Opcode
    if (-not $LogCmdIsEnabled -or $Value -lt $Script:NSIS_OPCODE_SECTION_SET) { return $Value }
    if ($Value -eq $Script:NSIS_OPCODE_SECTION_SET) { return $Script:NSIS_OPCODE_LOG }
    return $Value - 1
  }
  park1    = { param([uint32]$Opcode, [bool]$LogCmdIsEnabled) ConvertFrom-NSISParkOpcode -Opcode $Opcode -FontCommandCount 0 -LogCmdIsEnabled $LogCmdIsEnabled }
  park2    = { param([uint32]$Opcode, [bool]$LogCmdIsEnabled) ConvertFrom-NSISParkOpcode -Opcode $Opcode -FontCommandCount 1 -LogCmdIsEnabled $LogCmdIsEnabled }
  park3    = { param([uint32]$Opcode, [bool]$LogCmdIsEnabled) ConvertFrom-NSISParkOpcode -Opcode $Opcode -FontCommandCount 2 -LogCmdIsEnabled $LogCmdIsEnabled }
}

function Get-NSISNormalizedOpcode {
  <#
  .SYNOPSIS
    Normalize a raw compiled opcode to the NSIS 3 command layout used by the simulator
  .PARAMETER Opcode
    The raw command opcode
  .PARAMETER Type
    Compatibility input for the detected NSIS command layout type.
  .PARAMETER Unicode
    Compatibility input indicating Unicode string storage.
  .PARAMETER CatalogProfile
    Preferred catalog profile containing the opcode route.
  .PARAMETER LogCmdIsEnabled
    Whether a log opcode was inserted before section commands
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The raw command opcode')]
    [uint32]$Opcode,

    [Parameter(HelpMessage = 'The detected NSIS command layout type')]
    [string]$Type,

    [Parameter(HelpMessage = 'Whether the installer stores Unicode strings')]
    [bool]$Unicode,

    [Alias('Profile')]
    [Parameter(HelpMessage = 'The resolved NSIS catalog profile')]
    [pscustomobject]$CatalogProfile,

    [Parameter(Mandatory, HelpMessage = 'Whether a log opcode was inserted before section commands')]
    [bool]$LogCmdIsEnabled
  )

  if ($Opcode -in @($Script:NSIS_OPCODE_EXTRACT_STUB_FILE, $Script:NSIS_OPCODE_VERIFY_EXTERNAL_FILE)) { return [int]$Opcode }

  # Unicode is retained for callers of the pre-catalog API. The selected route
  # now carries the character-mode decision.
  $null = $Unicode
  $Route = if ($CatalogProfile) {
    [string]$CatalogProfile.OpcodeRoute
  } else {
    # Keep focused tests and external research scripts compatible while all
    # parser paths use catalog profiles directly.
    switch ($Type) {
      'Park1' { 'park1' }
      'Park2' { 'park2' }
      'Park3' { 'park3' }
      'NSIS2' { 'official' }
      'NSIS3' { 'official' }
      default { throw "Unknown NSIS command layout '$Type'." }
    }
  }
  $Handler = $Script:NSIS_OPCODE_ROUTE_HANDLERS[$Route]
  if (-not $Handler) { throw "NSIS opcode route '$Route' is not implemented." }
  return [int](& $Handler $Opcode $LogCmdIsEnabled)
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
  .PARAMETER IsNsisBi
    Whether records use NSISBI's eight-operand command ABI.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The raw NSIS command entries')]
    [pscustomobject[]]$Entries,

    [Parameter(Mandatory, HelpMessage = 'The candidate NSIS command layout type')]
    [string]$Type,

    [Parameter(Mandatory, HelpMessage = 'Whether the installer stores Unicode strings')]
    [bool]$Unicode,

    [Parameter(Mandatory, HelpMessage = 'Whether a log opcode was inserted before section commands')]
    [bool]$LogCmdIsEnabled,

    [Parameter(HelpMessage = 'Whether the records use the NSISBI command ABI')]
    [bool]$IsNsisBi = $false
  )

  $FatalInvalidCommandCount = 0
  $IgnoredExtensionOperandCount = 0
  $IgnoredExtensionOperands = [Collections.Generic.List[object]]::new()
  $LockWindowShapeValues = [Collections.Generic.HashSet[int]]::new()
  $FileWriteLockShapeCount = 0

  # Invalid opcodes and impossible operand semantics are fatal. Nonzero values
  # beyond a recognized command's source-defined operands are retained as
  # vendor-extension evidence and influence selection without disabling the
  # documented command subset.
  for ($EntryIndex = 0; $EntryIndex -lt $Entries.Count; $EntryIndex++) {
    $Entry = $Entries[$EntryIndex]
    if ($Entry.LayoutOpcode -in @($Script:NSIS_OPCODE_EXTRACT_STUB_FILE, $Script:NSIS_OPCODE_VERIFY_EXTERNAL_FILE)) { continue }
    $Opcode = Get-NSISNormalizedOpcode -Opcode $Entry.LayoutOpcode -Type $Type -Unicode $Unicode -LogCmdIsEnabled $LogCmdIsEnabled
    if ($Opcode -lt 0 -or $Opcode -ge $Script:NSIS_COMMAND_PARAMETER_COUNTS.Count) {
      $FatalInvalidCommandCount++
      continue
    }

    if ($Type -eq 'NSIS3') {
      if ($Opcode -eq $Script:NSIS_OPCODE_RESERVED) {
        $FatalInvalidCommandCount++
        continue
      }
    } elseif ($Opcode -eq $Script:NSIS_OPCODE_RESERVED -or $Opcode -eq $Script:NSIS_OPCODE_GET_OS_INFO) {
      $FatalInvalidCommandCount++
      continue
    }

    # EW_INSTTYPESET offsets[2] selects either install-type text (0) or the
    # current install type (1). A negative section-structure field selector is
    # emitted only by EW_SECTIONSET. This distinguishes official stubs with an
    # inserted EW_LOG slot even when the script contains no LogText/LogSet
    # instruction. Electron-builder's SectionSetSize output exercises this
    # route in otherwise stock NSIS 3 Unicode media.
    if ($Opcode -eq $Script:NSIS_OPCODE_INSTALL_TYPE_SET) {
      $Operation = [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$Entry.Raw[3]), 0)
      if ($Operation -notin @(0, 1)) {
        $FatalInvalidCommandCount++
        continue
      }
    }

    $LastNonZeroParameter = 0
    $MaximumOperand = if ($IsNsisBi) { 8 } else { 6 }
    for ($Index = $MaximumOperand; $Index -ge 1; $Index--) {
      if ($Entry.Raw[$Index] -ne 0) {
        $LastNonZeroParameter = $Index
        break
      }
    }
    # Park's FindProc command requires an output/process operand. The upstream
    # 7-Zip detector treats an all-zero record as impossible; without this
    # invariant Park 2.46.3 LockWindow records also appear valid under the
    # non-log layout and acquire a different canonical meaning.
    if ($Opcode -eq $Script:NSIS_OPCODE_FIND_PROC -and $LastNonZeroParameter -eq 0) {
      $FatalInvalidCommandCount++
      continue
    }
    if ($Opcode -eq $Script:NSIS_OPCODE_LOCK_WINDOW -and $Entry.Raw[1] -notin @(0, 1)) {
      $FatalInvalidCommandCount++
      continue
    }

    # A paired LockWindow on/off sequence is source-defined semantic evidence
    # for a log-enabled official command table. Interpreting the same two
    # one-operand records as FileWriteUTF16LE would produce two empty no-op
    # writes and is therefore retained only as a lower-ranked alternative.
    $HasLockWindowShape = $Entry.Raw[1] -in @(0, 1)
    for ($Index = 2; $HasLockWindowShape -and $Index -le $MaximumOperand; $Index++) {
      if ($Entry.Raw[$Index] -ne 0) { $HasLockWindowShape = $false }
    }
    if ($HasLockWindowShape -and $Opcode -in @($Script:NSIS_OPCODE_LOCK_WINDOW, $Script:NSIS_OPCODE_FILE_WRITE_UTF16)) {
      $null = $LockWindowShapeValues.Add([int]$Entry.Raw[1])
      if ($Opcode -eq $Script:NSIS_OPCODE_FILE_WRITE_UTF16) { $FileWriteLockShapeCount++ }
    }
    # NSISBI widens registry data and uninstaller records to carry 64-bit data
    # offsets plus per-file CRC values. Other canonical commands retain their
    # upstream arity after the two fork opcodes are normalized away.
    $ExpectedOperandCount = if ($IsNsisBi -and $Opcode -eq $Script:NSIS_OPCODE_EXTRACT_FILE) {
      8
    } elseif ($IsNsisBi -and $Opcode -eq $Script:NSIS_OPCODE_WRITE_REG) {
      7
    } elseif ($IsNsisBi -and $Opcode -eq $Script:NSIS_OPCODE_WRITE_UNINSTALLER) {
      # NSISBI serializes offsets[0..6]: name, data offset low/high, icon
      # length, full output path, icon CRC, and uninstaller-data CRC.
      7
    } else {
      $Script:NSIS_COMMAND_PARAMETER_COUNTS[$Opcode]
    }
    if ($ExpectedOperandCount -lt $LastNonZeroParameter) {
      $OperandIndexes = [Collections.Generic.List[int]]::new()
      for ($Index = $ExpectedOperandCount + 1; $Index -le $MaximumOperand; $Index++) {
        if ($Entry.Raw[$Index] -ne 0) { $OperandIndexes.Add($Index) }
      }
      $IgnoredExtensionOperandCount += $OperandIndexes.Count
      $IgnoredExtensionOperands.Add([pscustomobject][ordered]@{
          EntryIndex           = $EntryIndex
          RawOpcode            = [uint32]$Entry.RawOpcode
          CanonicalOpcode      = $Opcode
          ExpectedOperandCount = $ExpectedOperandCount
          OperandIndexes       = [int[]]$OperandIndexes.ToArray()
        })
    }
  }

  return [pscustomobject][ordered]@{
    FatalInvalidCommandCount     = $FatalInvalidCommandCount
    IgnoredExtensionOperandCount = $IgnoredExtensionOperandCount
    IgnoredExtensionOperands     = [object[]]$IgnoredExtensionOperands.ToArray()
    SemanticPenalty              = $LockWindowShapeValues.Count -eq 2 ? $FileWriteLockShapeCount : 0
  }
}

function Get-NSISStubArchitecture {
  <#
  .SYNOPSIS
    Map the NSIS executable stub machine to a readable architecture name.
  .PARAMETER PEInfo
    Parsed PE machine evidence from the NSIS stub.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][pscustomobject]$PEInfo)

  if ($PEInfo.IsArm64) { return 'arm64' }
  if ($PEInfo.IsAmd64) { return 'x64' }
  if ($PEInfo.IsX86) { return 'x86' }
  return $null
}

function Get-NSISFormatContext {
  <#
  .SYNOPSIS
    Parse an NSIS installer once into its catalog-selected structural context.
  .PARAMETER Path
    Path to the NSIS installer. Used when HeaderData is not supplied.
  .PARAMETER HeaderData
    Previously decoded header result, allowing simulation and extraction to
    reuse the same bounded archive read.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'HeaderData')][pscustomobject]$HeaderData
  )

  if ($PSCmdlet.ParameterSetName -eq 'Path') { $HeaderData = Get-NSISHeaderData -Path $Path }
  $HeaderBytes = $HeaderData.HeaderBytes
  $BlockHeaders = Get-NSISBlockHeaders -HeaderBytes $HeaderBytes -Is64Bit $HeaderData.PEInfo.Is64Bit
  $HeaderLayout = Get-NSISHeaderLayout -HeaderBytes $HeaderBytes -Is64Bit $HeaderData.PEInfo.Is64Bit
  $StringsBlock = Get-NSISBlockBytes -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Index 3
  $HasNsisBiExternalOpcodes = $HeaderData.IsNsisBi -and $HeaderData.FirstHeaderFlagRoute -ne 'nsisbi-pre-3.04.1'
  $Entries = Get-NSISEntries -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -IsNsisBi $HeaderData.IsNsisBi -HasNsisBiExternalOpcodes:$HasNsisBiExternalOpcodes
  $VersionInfo = Get-NSISVersionInfo -StringsBlock $StringsBlock -Entries $Entries -IsNsisBi $HeaderData.IsNsisBi

  # Store only canonical opcodes after the profile has been selected. Raw and
  # layout opcodes remain available for diagnostics and future catalog routes.
  foreach ($Entry in $Entries) {
    $Entry.Opcode = Get-NSISNormalizedOpcode -Opcode $Entry.LayoutOpcode -CatalogProfile $VersionInfo.Profile -LogCmdIsEnabled $VersionInfo.LogCmdIsEnabled
  }

  $VersionInfo | Add-Member -NotePropertyName FirstHeaderRoute -NotePropertyValue $VersionInfo.Profile.FirstHeaderRoute
  $VersionInfo | Add-Member -NotePropertyName FirstHeaderFlagRoute -NotePropertyValue $HeaderData.FirstHeaderFlagRoute
  $VersionInfo | Add-Member -NotePropertyName HeaderRoute -NotePropertyValue $VersionInfo.Profile.HeaderRoute
  $VersionInfo | Add-Member -NotePropertyName BlockHeaderRoute -NotePropertyValue $(if ($HeaderData.PEInfo.Is64Bit) { 'uint64-offset' } else { 'uint32-offset' })
  $VersionInfo | Add-Member -NotePropertyName EntryRoute -NotePropertyValue $VersionInfo.Profile.EntryRoute
  $VersionInfo | Add-Member -NotePropertyName StringRoute -NotePropertyValue $VersionInfo.Profile.StringRoute
  $VersionInfo | Add-Member -NotePropertyName OpcodeRoute -NotePropertyValue $VersionInfo.Profile.OpcodeRoute
  $VersionInfo | Add-Member -NotePropertyName VariableRoute -NotePropertyValue $VersionInfo.Profile.VariableRoute
  $VersionInfo | Add-Member -NotePropertyName CompressionRoute -NotePropertyValue $HeaderData.Compression
  $VersionInfo | Add-Member -NotePropertyName PayloadRoute -NotePropertyValue $(if ($HeaderData.Compression -like 'Mtw-*') { 'nsisbi-mtw' } elseif ($HeaderData.IsSolid) { 'solid' } else { 'non-solid' })
  $VersionInfo | Add-Member -NotePropertyName ChecksumRoute -NotePropertyValue $VersionInfo.Profile.ChecksumRoute
  # This is the uninstaller/loader stub architecture, not necessarily the
  # architecture of the payload selected by the compiled script.
  $VersionInfo | Add-Member -NotePropertyName StubArchitecture -NotePropertyValue (Get-NSISStubArchitecture -PEInfo $HeaderData.PEInfo)

  return [pscustomobject]@{
    HeaderData   = $HeaderData
    HeaderBytes  = $HeaderBytes
    BlockHeaders = $BlockHeaders
    HeaderLayout = $HeaderLayout
    StringsBlock = $StringsBlock
    Entries      = $Entries
    VersionInfo  = $VersionInfo
  }
}

function ConvertTo-NSISFormatInfo {
  <#
  .SYNOPSIS
    Project an internal NSIS format context into JSON-safe public evidence.
  .PARAMETER Context
    Catalog-selected context from Get-NSISFormatContext.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][pscustomobject]$Context)

  $VersionInfo = $Context.VersionInfo
  $HeaderData = $Context.HeaderData
  $Warnings = [System.Collections.Generic.List[object]]::new()
  $InformationMessages = [System.Collections.Generic.List[string]]::new()
  if ($VersionInfo.HasSemanticAmbiguity) {
    $Warnings.Add((New-InstallerDiagnostic -Id 'NSIS.Format.CommandLayoutAmbiguous' -Source 'NSISFormat' -Message 'Multiple equally valid NSIS command layouts assign different meanings to opcodes used by this installer. Static command simulation is disabled rather than guessing a compiler feature set or reordered command table.' -Kind Ambiguous -Areas Detection, Metadata))
  } elseif ($VersionInfo.DetectionConfidence -eq 'Ambiguous') {
    # NSIS 2 and NSIS 3 share most command numbers. When every tied candidate
    # gives all used opcodes the same meaning, generation uncertainty does not
    # make simulation uncertain and belongs in diagnostic evidence, not warnings.
    $InformationMessages.Add('The installer does not contain decisive generation control codes; equivalent command profiles were tied, so the earliest compatible profile was selected.')
  }
  if ($VersionInfo.BadCommandCount -gt 0) {
    $Warnings.Add((New-InstallerDiagnostic -Id 'NSIS.Format.InvalidCommandRecords' -Source 'NSISFormat' -Message "The selected command layout contains $($VersionInfo.BadCommandCount) command record(s) with invalid opcodes or source-defined operand semantics." -Kind Incomplete -Areas Detection, Metadata -Evidence ([ordered]@{ Count = $VersionInfo.BadCommandCount })))
  }
  if ($VersionInfo.IgnoredExtensionOperandCount -gt 0) {
    $InformationMessages.Add("The selected command layout contains $($VersionInfo.IgnoredExtensionOperandCount) nonzero trailing vendor-extension operand(s); the parser used the documented command operands and retained the opaque values as format evidence.")
  }
  if ($HeaderData.HasExternalFile) {
    $Warnings.Add((New-InstallerDiagnostic -Id 'NSIS.Extraction.ExternalPayloadRequired' -Source 'NSISFormat' -Message 'The NSISBI installer references an external payload sidecar; embedded format evidence does not describe the complete payload set.' -Kind Incomplete -Areas Extraction))
  }

  return [pscustomobject][ordered]@{
    Path                         = $HeaderData.Path
    InstallerType                = 'Nullsoft'
    EditionId                    = $VersionInfo.EditionId
    Edition                      = $VersionInfo.Edition
    CompilerVersion              = $VersionInfo.CompilerVersion
    VersionRange                 = $VersionInfo.VersionRange
    Generation                   = $VersionInfo.Generation
    CharacterMode                = $VersionInfo.CharacterMode
    StubArchitecture             = $VersionInfo.StubArchitecture
    CatalogProfileId             = $VersionInfo.CatalogProfileId
    FirstHeaderRoute             = $VersionInfo.FirstHeaderRoute
    FirstHeaderFlagRoute         = $VersionInfo.FirstHeaderFlagRoute
    HeaderRoute                  = $VersionInfo.HeaderRoute
    BlockHeaderRoute             = $VersionInfo.BlockHeaderRoute
    EntryRoute                   = $VersionInfo.EntryRoute
    StringRoute                  = $VersionInfo.StringRoute
    OpcodeRoute                  = $VersionInfo.OpcodeRoute
    VariableRoute                = $VersionInfo.VariableRoute
    CompressionRoute             = $VersionInfo.CompressionRoute
    PayloadRoute                 = $VersionInfo.PayloadRoute
    ChecksumRoute                = $VersionInfo.ChecksumRoute
    ArchiveCrcStatus             = $HeaderData.ArchiveCrcInfo.Status
    ArchiveCrcVerified           = $HeaderData.ArchiveCrcInfo.IsVerified
    LogCommandEnabled            = $VersionInfo.LogCmdIsEnabled
    IsSolid                      = $HeaderData.IsSolid
    IsNsisBi                     = $HeaderData.IsNsisBi
    SupportsExternalFiles        = $HeaderData.SupportsExternalFiles
    HasExternalFile              = $HeaderData.HasExternalFile
    IsStubInstaller              = $HeaderData.IsStubInstaller
    ExternalFileCount            = $HeaderData.ExternalFileCount
    ExternalSegmentSize          = $HeaderData.ExternalSegmentSize
    DetectionConfidence          = $VersionInfo.DetectionConfidence
    HasSemanticAmbiguity         = [bool]$VersionInfo.HasSemanticAmbiguity
    CandidateLayouts             = $VersionInfo.CandidateLayouts
    FatalInvalidCommandCount     = $VersionInfo.FatalInvalidCommandCount
    IgnoredExtensionOperandCount = $VersionInfo.IgnoredExtensionOperandCount
    IgnoredExtensionOperands     = $VersionInfo.IgnoredExtensionOperands
    IsSupported                  = [bool]$VersionInfo.Profile.Supported -and $VersionInfo.BadCommandCount -eq 0 -and -not $VersionInfo.HasSemanticAmbiguity
    Diagnostics                  = @(Merge-InstallerDiagnostics -Diagnostic @(@(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings.ToArray()) -Source 'NSISFormat' -Kind Incomplete -Areas Metadata), @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$InformationMessages.ToArray()) -Source 'NSISFormat' -Kind Information -Areas Metadata)))

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

function Assert-NSISPayloadCrc32 {
  <#
  .SYNOPSIS
    Verify a decoded solid-record CRC serialized by NSISBI extraction commands.
  .PARAMETER Path
    Extracted file containing the serialized record body after solid decoding.
  .PARAMETER Expected
    Optional uint32 CRC operand from EW_EXTRACTFILE/EW_EXTRACTSTUBFILE.
  .PARAMETER PackedValue
    Original unpacked length field whose little-endian bytes follow the body in
    the NSISBI checksum calculation.
  .PARAMETER PackedSizeWidth
    Width of the serialized length field in bytes.
  .PARAMETER IncludePackedSize
    Apply the compact NSISBI 3.12 checksum suffix after the decoded body.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [AllowNull()][Nullable[uint32]]$Expected,
    [Parameter(Mandatory)][uint64]$PackedValue,
    [Parameter(Mandatory)][ValidateSet(4, 8)][int]$PackedSizeWidth,
    [switch]$IncludePackedSize
  )

  if ($null -eq $Expected) { return }
  # PowerShell unboxes a populated Nullable[uint32] during parameter binding,
  # so do not access Nullable.Value here. Normalize either representation to
  # the serialized unsigned checksum before comparing it.
  $ExpectedValue = [uint32]$Expected
  $File = Get-Item -LiteralPath $Path -Force
  $CrcArguments = @{ Path = $File.FullName; MaximumBytes = $File.Length }
  if ($IncludePackedSize) {
    $CrcArguments.SuffixBytes = if ($PackedSizeWidth -eq 8) { [BitConverter]::GetBytes($PackedValue) } else { [BitConverter]::GetBytes([uint32]$PackedValue) }
  }
  $Actual = Get-BinaryCrc32 @CrcArguments
  if ($Actual -ne $ExpectedValue) {
    Remove-Item -LiteralPath $File.FullName -Force -ErrorAction SilentlyContinue
    throw "The NSISBI payload CRC32 does not match for '$Path': expected $($ExpectedValue.ToString('X8')), got $($Actual.ToString('X8'))."
  }
}

function Assert-NSISSerializedPayloadCrc32 {
  <#
  .SYNOPSIS
    Verify the source-defined NSISBI CRC over a non-solid serialized record.
  .PARAMETER Stream
    Caller-owned seekable data-block stream.
  .PARAMETER BodyOffset
    Absolute stream offset immediately after the packed-size field.
  .PARAMETER BodyLength
    Serialized compressed or stored body length.
  .PARAMETER PackedValue
    Original packed-size value, including its compressed flag.
  .PARAMETER PackedSizeWidth
    Width of the packed-size field in bytes.
  .PARAMETER Expected
    Optional uint32 checksum operand from the extraction command.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$BodyOffset,
    [Parameter(Mandatory)][long]$BodyLength,
    [Parameter(Mandatory)][uint64]$PackedValue,
    [Parameter(Mandatory)][ValidateSet(4, 8)][int]$PackedSizeWidth,
    [AllowNull()][Nullable[uint32]]$Expected
  )

  if ($null -eq $Expected) { return }
  $ExpectedValue = [uint32]$Expected
  $PackedBytes = if ($PackedSizeWidth -eq 8) { [BitConverter]::GetBytes($PackedValue) } else { [BitConverter]::GetBytes([uint32]$PackedValue) }
  $Body = New-BoundedReadStream -Stream $Stream -Offset $BodyOffset -Length $BodyLength -LeaveOpen
  try { $Actual = Get-BinaryCrc32 -Stream $Body -MaximumBytes $BodyLength -SuffixBytes $PackedBytes }
  finally { $Body.Dispose() }
  if ($Actual -ne $ExpectedValue) {
    throw "The NSISBI serialized payload CRC32 does not match: expected $($ExpectedValue.ToString('X8')), got $($Actual.ToString('X8'))."
  }
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

function Write-NSISMtwRecordStream {
  <#
  .SYNOPSIS
    Atomically decode one complete NSISBI MTW record to disk.
  .PARAMETER Stream
    Seekable bounded stream containing the MTW block sequence after the outer
    packed-size field. The caller owns the stream and this function leaves it open.
  .PARAMETER OutputPath
    Safe absolute output path selected by the extraction map.
  .PARAMETER MaximumBytes
    Hard maximum number of decompressed bytes accepted for this file.
  .PARAMETER Compression
    Codec selected while decoding the NSIS header, without the Mtw- prefix.
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$MaximumBytes,
    [Parameter(Mandatory)][ValidateSet('BZip2', 'Deflate', 'Lz4', 'Lzma', 'Zlib')][string]$Compression
  )

  if (-not $Stream.CanSeek) { throw 'NSISBI MTW record extraction requires a seekable bounded stream' }
  $Directory = Split-Path -Path $OutputPath -Parent
  $null = New-Item -Path $Directory -ItemType Directory -Force
  $PartialPath = Join-Path $Directory ('.' + [IO.Path]::GetFileName($OutputPath) + '.partial-' + [Guid]::NewGuid().ToString('N'))
  $Output = [IO.File]::Open($PartialPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  $RecordOffset = 0L
  $ExpandedBytes = 0L
  try {
    while ($true) {
      $Block = Read-NSISMtwBlock -Stream $Stream -RecordOffset $RecordOffset -Compression $Compression
      if ($Block.IsEnd) {
        # The packed record length includes the MTW zero terminator. Reject
        # trailing bytes so a corrupt size cannot bleed into the next record.
        if ($Block.NextOffset -ne $Stream.Length) { throw 'The NSISBI MTW record contains trailing bytes after its end marker' }
        break
      }

      if ($Block.Bytes.Length -gt $MaximumBytes - $ExpandedBytes) {
        throw "The NSISBI MTW record exceeds the $MaximumBytes-byte output limit"
      }
      $Output.Write($Block.Bytes, 0, $Block.Bytes.Length)
      $ExpandedBytes += $Block.Bytes.Length
      $RecordOffset = $Block.NextOffset
    }
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
  .PARAMETER DataBlockOffset
    Absolute stream offset of the data block. Defaults to the embedded block.
  .PARAMETER DataBlockLength
    Available data-block bytes. Defaults to the remainder of the embedded archive.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][pscustomobject]$HeaderData,
    [Parameter(Mandatory)][pscustomobject[]]$Payload,
    [Parameter(Mandatory)][long]$MaximumExpandedBytes,
    [long]$DataBlockOffset = -1,
    [long]$DataBlockLength = -1
  )

  $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
  $ExpandedBytes = 0L
  if ($DataBlockOffset -lt 0) { $DataBlockOffset = $HeaderData.PayloadOffset + $HeaderData.PackedSizeWidth + $HeaderData.CompressedHeaderSize }
  if ($DataBlockLength -lt 0) { $DataBlockLength = ($HeaderData.FirstHeaderOffset + $HeaderData.ArchiveSize) - $DataBlockOffset }
  $ArchiveEnd = $DataBlockOffset + $DataBlockLength
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

    # NSISBI checksums the serialized body first and the original packed-size
    # field second. For compressed records this deliberately differs from the
    # CRC of the extracted file.
    $UsesSerializedCrc = $HeaderData.FirstHeaderFlagRoute -eq 'nsisbi-compact-3.12'
    if ($UsesSerializedCrc) {
      Assert-NSISSerializedPayloadCrc32 -Stream $Stream -BodyOffset ([long]$BodyOffset) -BodyLength ([long]$PackedLength) `
        -PackedValue $PackedValue -PackedSizeWidth $HeaderData.PackedSizeWidth -Expected $Items[0].Crc32
    }

    $Remaining = $MaximumExpandedBytes - $ExpandedBytes
    $PerOutputLimit = [long][Math]::Floor($Remaining / $Items.Count)
    $Body = New-BoundedReadStream -Stream $Stream -Offset ([long]$BodyOffset) -Length ([long]$PackedLength) -LeaveOpen
    $Decoder = $null
    try {
      $Source = $Body
      $ExpectedBytes = [long]$PackedLength
      if ($IsCompressed -and $HeaderData.Compression -like 'Mtw-*') {
        # NSISBI non-solid records have two framing layers: the outer wide
        # packed-size field and an inner sequence of three-byte MTW blocks.
        # Decode the complete inner record instead of handing its framing to a
        # stock single-codec stream.
        $File = Write-NSISMtwRecordStream -Stream $Body -OutputPath $Items[0].OutputPath `
          -MaximumBytes $PerOutputLimit -Compression ($HeaderData.Compression -replace '^Mtw-', '')
      } elseif ($IsCompressed) {
        $Probe = Read-BinaryBytes -Stream $Body -Offset 0 -Count ([int][Math]::Min(24L, [long]$PackedLength))
        $LzmaFilterLength = if ($HeaderData.Compression -eq 'Lzma') { Get-NSISLzmaFilterLength -Bytes $Probe } else { -1 }
        $Decoder = New-NSISDecoder -Compression $HeaderData.Compression -PayloadStream $Body `
          -LzmaFilterLength $LzmaFilterLength -ExpectedOutputBytes -1
        $Source = $Decoder
        $ExpectedBytes = -1
        $File = Write-NSISPayloadStream -Stream $Source -OutputPath $Items[0].OutputPath -MaximumBytes $PerOutputLimit -ExpectedBytes $ExpectedBytes
      } else {
        $File = Write-NSISPayloadStream -Stream $Source -OutputPath $Items[0].OutputPath -MaximumBytes $PerOutputLimit -ExpectedBytes $ExpectedBytes
      }
    } finally {
      if ($Decoder -is [System.IDisposable]) { $Decoder.Dispose() }
      $Body.Dispose()
    }

    if (-not $UsesSerializedCrc) {
      Assert-NSISPayloadCrc32 -Path $File.FullName -Expected $Items[0].Crc32 `
        -PackedValue $PackedValue -PackedSizeWidth $HeaderData.PackedSizeWidth
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
      Assert-NSISPayloadCrc32 -Path $File.FullName -Expected $Items[0].Crc32 `
        -PackedValue $UnpackedLength -PackedSizeWidth $HeaderData.PackedSizeWidth `
        -IncludePackedSize:($HeaderData.FirstHeaderFlagRoute -eq 'nsisbi-compact-3.12')
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
      Assert-NSISPayloadCrc32 -Path $File.FullName -Expected $Items[0].Crc32 `
        -PackedValue $UnpackedLength -PackedSizeWidth $HeaderData.PackedSizeWidth `
        -IncludePackedSize:($HeaderData.FirstHeaderFlagRoute -eq 'nsisbi-compact-3.12')
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

function Resolve-NSISExternalDataFiles {
  <#
  .SYNOPSIS
    Resolve legacy .nsisbin or current setupN.bin NSISBI payload sidecars.
  .PARAMETER InstallerPath
    Absolute path to the NSISBI executable.
  .PARAMETER HeaderData
    Parsed first-header route and split-file evidence.
  .PARAMETER ExternalDataPath
    Optional sidecar file or directory supplied by the caller.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory)][string]$InstallerPath,
    [Parameter(Mandatory)][pscustomobject]$HeaderData,
    [string[]]$ExternalDataPath
  )

  $Files = [System.Collections.Generic.List[string]]::new()
  if ($ExternalDataPath) {
    foreach ($Candidate in $ExternalDataPath) {
      $Resolved = Resolve-InstallerFileSystemPath -Path $Candidate
      if ([IO.Directory]::Exists($Resolved)) {
        foreach ($Item in @(Get-ChildItem -LiteralPath $Resolved -File | Where-Object Name -Match '^setup\d+\.bin$' | Sort-Object { [int]([regex]::Match($_.Name, '\d+').Value) })) { $Files.Add($Item.FullName) }
      } elseif ([IO.File]::Exists($Resolved)) { $Files.Add($Resolved) }
    }
  } elseif ($HeaderData.FirstHeaderFlagRoute -eq 'nsisbi-compact-3.12') {
    $Directory = [IO.Path]::GetDirectoryName($InstallerPath)
    $Count = [Math]::Max(1, [int]$HeaderData.ExternalFileCount)
    for ($Index = 1; $Index -le $Count; $Index++) {
      $Candidate = Join-Path $Directory "setup$Index.bin"
      if (-not [IO.File]::Exists($Candidate)) { throw "The NSISBI external sidecar is missing: $Candidate" }
      $Files.Add($Candidate)
    }
  } else {
    $Candidate = "$InstallerPath.nsisbin"
    if (-not [IO.File]::Exists($Candidate)) { throw "The NSISBI external sidecar is missing: $Candidate" }
    $Files.Add($Candidate)
  }

  if ($Files.Count -eq 0) { throw 'No NSISBI external payload sidecar was resolved.' }
  if ($HeaderData.ExternalFileCount -gt 0 -and $Files.Count -ne $HeaderData.ExternalFileCount) {
    throw "The NSISBI first header declares $($HeaderData.ExternalFileCount) external segment(s), but $($Files.Count) were supplied."
  }
  return $Files.ToArray()
}

function New-NSISExternalDataStream {
  <#
  .SYNOPSIS
    Open one logical seekable stream over resolved NSISBI sidecars.
  .PARAMETER Path
    Ordered absolute sidecar paths.
  #>
  [OutputType([System.IO.Stream])]
  param ([Parameter(Mandatory)][string[]]$Path)

  if ($Path.Count -eq 1) { return [IO.File]::Open($Path[0], [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite) }
  Import-NSISSegmentedReadStream
  return [Dumplings.InstallerParsers.NSIS.NsisSegmentedReadStream]::new($Path)
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
    Facade-owned callback that creates simulator state from the shared catalog-selected context.
  .PARAMETER PayloadSelector
    Facade-owned callback that projects simulated File commands into extraction records.
  .PARAMETER ExternalDataPath
    Optional legacy .nsisbin file, current setupN.bin files, or their directory.
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
    [Parameter(Mandatory)][scriptblock]$PayloadSelector,
    [string[]]$ExternalDataPath
  )

  process {
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $ResolvedDestinationPath = $DestinationPath
    if ([string]::IsNullOrWhiteSpace($ResolvedDestinationPath)) {
      $ResolvedDestinationPath = Join-Path ([IO.Path]::GetTempPath()) ('Dumplings-NSIS-' + [Guid]::NewGuid().ToString('N'))
    }
    $ResolvedDestinationPath = Resolve-InstallerFileSystemPath -Path $ResolvedDestinationPath -AllowNonexistent
    $ResolvedDestinationPath = (New-Item -Path $ResolvedDestinationPath -ItemType Directory -Force).FullName

    $FormatContext = Get-NSISFormatContext -Path $InstallerPath
    $FormatInfo = ConvertTo-NSISFormatInfo -Context $FormatContext
    if (-not $FormatInfo.IsSupported) {
      throw "The NSIS command layout '$($FormatInfo.CatalogProfileId)' is unsupported: $([string]::Join(' ', $FormatInfo.Diagnostics))"
    }
    $HeaderData = $FormatContext.HeaderData
    $Initialized = & $StateInitializer $FormatContext
    $Selected = & $PayloadSelector $Initialized.State $HeaderData $Name
    if ($Selected.Count -eq 0) { throw "No NSIS payload matched '$Name'" }
    $Mapped = New-NSISExtractionOutputMap -Payload $Selected -DestinationPath $ResolvedDestinationPath -CollisionAction $CollisionAction
    if ($Mapped.Count -eq 0) { return }

    $InstallerStream = [IO.File]::Open($InstallerPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $ExternalStream = $null
    try {
      if (-not $HeaderData.IsSolid) {
        $Results = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
        $Embedded = [pscustomobject[]]@($Mapped | Where-Object DataSource -CEQ 'Embedded')
        if ($Embedded.Count -gt 0) {
          foreach ($File in @(Expand-NSISNonSolidPayloads -Stream $InstallerStream -HeaderData $HeaderData -Payload $Embedded -MaximumExpandedBytes $MaximumExpandedBytes)) { $Results.Add($File) }
        }
        $External = [pscustomobject[]]@($Mapped | Where-Object DataSource -CEQ 'External')
        if ($External.Count -gt 0) {
          $ExternalFiles = Resolve-NSISExternalDataFiles -InstallerPath $InstallerPath -HeaderData $HeaderData -ExternalDataPath $ExternalDataPath
          $ExternalStream = New-NSISExternalDataStream -Path $ExternalFiles
          $Remaining = $MaximumExpandedBytes - ($Results | Measure-Object Length -Sum).Sum
          foreach ($File in @(Expand-NSISNonSolidPayloads -Stream $ExternalStream -HeaderData $HeaderData -Payload $External -MaximumExpandedBytes $Remaining -DataBlockOffset 0 -DataBlockLength $ExternalStream.Length)) { $Results.Add($File) }
        }
        return $Results.ToArray()
      }
      if ($HeaderData.HasExternalFile) { throw 'NSISBI does not support solid compression with external payload sidecars.' }
      if ($HeaderData.Compression -like 'Mtw-*') {
        return Expand-NSISMtwPayloads -Stream $InstallerStream -HeaderData $HeaderData -Payload $Mapped -MaximumExpandedBytes $MaximumExpandedBytes
      }
      return Expand-NSISSolidPayloads -Stream $InstallerStream -HeaderData $HeaderData -Payload $Mapped -MaximumExpandedBytes $MaximumExpandedBytes
    } finally {
      if ($ExternalStream) { $ExternalStream.Dispose() }
      $InstallerStream.Dispose()
    }
  }
}

# Internal format functions and constants are exported for the simulation and facade modules.
Export-ModuleMember -Function * -Variable 'NSIS*'
