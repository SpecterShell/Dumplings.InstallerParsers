# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# Format sources: https://github.com/NSIS-Dev/nsis, https://sourceforge.net/projects/nsisbi/, https://github.com/ip7z/7zip, https://github.com/russellbanks/Komac, and https://github.com/electron-userland/electron-builder
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
#     `-- packed-size word -> compressed logical header -> eight block tables
#         -> 28-byte standard or 36-byte NSISBI command entries -> payloads
#
# The packed-size high bit marks a solid archive. Opcode numbering is normalized
# for NSIS 2/3, Unicode/Park, log-enabled, and NSISBI layouts before simulation.
# Explicit EW_WRITEREG commands are authoritative; arbitrary strings are not.

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

  $Header = ($Bytes[0] -shl 8) -bor $Bytes[1]
  return ($Header % 31) -eq 0
}

function Get-NSISCompressionCandidates {
  <#
  .SYNOPSIS
    Get the ordered list of decoder candidates for a compressed NSIS header
  .PARAMETER Bytes
    The candidate compressed header bytes
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate compressed header bytes')]
    [byte[]]$Bytes
  )

  $LzmaFilterLength = Get-NSISLzmaFilterLength -Bytes $Bytes
  if ($LzmaFilterLength -ge 0) { return @('Lzma') }
  if (Test-NSISBZip2Header -Bytes $Bytes) { return @('BZip2') }

  # Recent KDE/Prowise NSIS stubs store the payload as raw DEFLATE without the RFC1950 zlib wrapper.
  if (Test-NSISZlibHeader -Bytes $Bytes) {
    return @('Zlib', 'Deflate')
  } else {
    return @('Deflate', 'Zlib')
  }
}

function New-NSISDecoder {
  <#
  .SYNOPSIS
    Create a decoder stream for a compressed NSIS header payload
  .PARAMETER Compression
    The NSIS compression format
  .PARAMETER PayloadStream
    The compressed header payload stream
  .PARAMETER IsSolid
    Whether the NSIS header uses the solid layout
  .PARAMETER LzmaFilterLength
    The optional NSIS LZMA filter marker length
  #>
  [OutputType([System.IDisposable])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The NSIS compression format')]
    [ValidateSet('None', 'Lzma', 'BZip2', 'Zlib', 'Deflate')]
    [string]$Compression,

    [Parameter(Mandatory, HelpMessage = 'The compressed header payload stream')]
    [System.IO.Stream]$PayloadStream,

    [Parameter(Mandatory, HelpMessage = 'Whether the NSIS header uses the solid layout')]
    [bool]$IsSolid,

    [Parameter(HelpMessage = 'The optional NSIS LZMA filter marker length')]
    [int]$LzmaFilterLength = -1
  )

  switch ($Compression) {
    'Lzma' {
      if (-not $IsSolid -and $LzmaFilterLength -gt 0) { $null = $PayloadStream.ReadByte() }
      $Properties = New-Object 'byte[]' 5
      if ($PayloadStream.Read($Properties, 0, $Properties.Length) -ne $Properties.Length) { throw 'The NSIS LZMA properties are truncated' }
      return New-InstallerDecompressionStream -Algorithm Lzma -Stream $PayloadStream -Properties $Properties -LeaveOpen
    }
    'BZip2' { return New-InstallerDecompressionStream -Algorithm BZip2 -Stream $PayloadStream -LeaveOpen }
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
    $ProbeLength = [int][Math]::Min(24, $PayloadLength)
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

    # Distinguish stored non-solid, solid codec streams, and packed-size-prefixed
    # non-solid headers using the exact first bytes consumed by the NSIS stub.
    if ($PackedHeaderSize -eq $LengthOfHeader) {
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
      $CompressionCandidates = Get-NSISCompressionCandidates -Bytes $CandidateHeader
    } else {
      $CompressionCandidates = Get-NSISCompressionCandidates -Bytes $CandidateHeader
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
        $Decoder = New-NSISDecoder -Compression $Compression -PayloadStream $PayloadStream -IsSolid $IsSolid -LzmaFilterLength $LzmaFilterLength

        if ($IsSolid -and $Compression -ne 'None') {
          $HeaderSizeBytes = New-Object 'byte[]' 4
          if ($Decoder.Read($HeaderSizeBytes, 0, $HeaderSizeBytes.Length) -ne $HeaderSizeBytes.Length) { throw 'The NSIS solid header length is truncated' }
          $EmbeddedHeaderLength = [System.BitConverter]::ToUInt32($HeaderSizeBytes, 0)
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
          Compression             = $Compression
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

function Get-NSISPrimaryLanguageTable {
  <#
  .SYNOPSIS
    Select the primary NSIS language table used for string resolution
  .PARAMETER HeaderBytes
    The decompressed NSIS header bytes
  .PARAMETER BlockHeaders
    The parsed NSIS block headers
  .PARAMETER Layout
    The parsed NSIS header layout
  #>
  [OutputType([pscustomobject])]
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

  # Prefer the compiler's default English table for deterministic static string
  # resolution; otherwise retain the first authored language rather than merging.
  $PreferredTable = $CandidateTables.Where({ $_.LanguageId -eq $Script:NSIS_DEFAULT_LANGUAGE }, 'First')
  if ($PreferredTable) {
    return $PreferredTable[0]
  } else {
    return $CandidateTables | Select-Object -First 1
  }
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
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The normalized NSIS command entry')]
    [pscustomobject]$Entry
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
  $Key = Get-NSISString -State $State -RelativeOffset $Entry.Values[2]
  $Name = Get-NSISString -State $State -RelativeOffset $Entry.Values[3]
  $Value = if ($RegistryKind -eq 'REG_DWORD') {
    [string](Get-NSISInt -State $State -RelativeOffset $Entry.Values[4])
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
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header data')]
    [pscustomobject]$HeaderData
  )

  $HeaderBytes = $HeaderData.HeaderBytes
  $BlockHeaders = Get-NSISBlockHeaders -HeaderBytes $HeaderBytes -Is64Bit $HeaderData.PEInfo.Is64Bit
  $Layout = Get-NSISHeaderLayout -HeaderBytes $HeaderBytes -Is64Bit $HeaderData.PEInfo.Is64Bit
  $StringsBlock = Get-NSISBlockBytes -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Index 3
  $LanguageTable = Get-NSISPrimaryLanguageTable -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Layout $Layout
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
    Path             = $HeaderData.Path
    Entries          = $Entries
    Sections         = Get-NSISSections -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders
    StringsBlock     = $StringsBlock
    LanguageTable    = $LanguageTable
    VersionInfo      = $VersionInfo
    Variables        = @{}
    Registry         = @{}
    RegistryWrites   = [System.Collections.Generic.List[object]]::new()
    ExecutedPayloads = [System.Collections.Generic.List[object]]::new()
    Warnings         = [System.Collections.Generic.List[string]]::new()
    Stack            = [System.Collections.Generic.List[string]]::new()
    Directories      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Files            = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    ExecFlags        = @{}
    LastExecFlags    = @{}
    ShellVarContext  = $null
    Metadata         = [ordered]@{
      Path                          = $HeaderData.Path
      InstallerType                 = 'Nullsoft'
      DisplayVersion                = $null
      DisplayName                   = $null
      Publisher                     = $null
      ProductCode                   = $null
      DefaultInstallLocation        = $null
      UninstallString               = $null
      QuietUninstallString          = $null
      DisplayIcon                   = $null
      SystemComponent               = $null
      Scope                         = $null
      WritesAppsAndFeaturesEntry    = $false
      DelegatesAppsAndFeaturesEntry = $false
      RegistryValues                = @{}
      RegistryWrites                = @()
      ExtractedFiles                = @()
      ExecutedPayloads              = @()
      Warnings                      = @()
      ParserVersionInfo             = $null
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

  foreach ($Entry in $State.Entries) {
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_WRITE_REG) { continue }
    $Write = Get-NSISRegistryWriteFromEntry -State $State -Entry $Entry
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
      # Reproduce NSIS substring assignment, including negative start offsets and
      # packed maximum-length fields, before updating derived install paths.
      $Result = Get-NSISString -State $State -RelativeOffset $Values[2]
      $Start = $Values[4]
      $MaxLengthLow = $Values[3] -band 0xFFFF
      $MaxLengthHigh = ($Values[3] -shr 16) -band 0xFFFF
      $NewLength = if ($MaxLengthHigh -eq 0) { $Result.Length } else { $MaxLengthLow }

      if ($NewLength -le 0) {
        $null = $State.Variables.Remove([Math]::Abs($Values[1]))
        return $Script:NSIS_CONTINUE_RESULT
      }

      if ($Start -lt 0) { $Start += $Result.Length }
      if ($Start -lt 0) { $Start = 0 }
      if ($Start -gt $Result.Length) { $Start = $Result.Length }

      $Result = $Result.Substring($Start)
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

function Complete-NSISMetadata {
  <#
  .SYNOPSIS
    Apply deterministic fallbacks after the NSIS simulation completes
  .PARAMETER State
    The mutable NSIS execution state
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
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

  if ($State.Metadata.SystemComponent -eq '1' -or $State.Metadata.SystemComponent -eq '0x00000001') {
    $State.Metadata.WritesAppsAndFeaturesEntry = $false
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
    $State.Metadata.DelegatesAppsAndFeaturesEntry = $true
  }

  $State.Metadata.RegistryWrites = @($RegistryWrites)
  $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
  foreach ($Warning in @($RegistryAssociationInfo.Warnings)) { $State.Warnings.Add($Warning) }
  $State.Metadata.RegistryAssociationInfo = $RegistryAssociationInfo
  $State.Metadata.Protocols = $RegistryAssociationInfo.Protocols
  $State.Metadata.FileExtensions = $RegistryAssociationInfo.FileExtensions
  $State.Metadata.ExtractedFiles = @($ExtractedFiles)
  $State.Metadata.ExecutedPayloads = @($ExecutedPayloads)
  $State.Metadata.Warnings = @($State.Warnings | Select-Object -Unique)
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
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The simulation mode')]
    [ValidateSet('Full', 'Fast')]
    [string]$Mode = 'Full'
  )

  process {
    # Parse and normalize the compiled header once; all later phases share the
    # same mutable state so callbacks and sections observe prior variable writes.
    $HeaderData = Get-NSISHeaderData -Path $Path
    $InitializedState = Initialize-NSISState -HeaderData $HeaderData
    $State = $InitializedState.State
    $Layout = $InitializedState.Layout

    # Prefer direct uninstall registry writes when they already expose a single deterministic ARP identity.
    Add-NSISDirectUninstallWrites -State $State
    $Metadata = Complete-NSISMetadata -State $State
    if ($Mode -eq 'Fast' -and -not [string]::IsNullOrWhiteSpace($Metadata.DisplayName) -and -not [string]::IsNullOrWhiteSpace($Metadata.DisplayVersion) -and -not [string]::IsNullOrWhiteSpace($Metadata.ProductCode)) {
      # Fast mode is an explicit optimization: direct uninstall writes must
      # already provide complete deterministic identity before callbacks are skipped.
      return [pscustomobject]@{
        State       = $State
        Layout      = $Layout
        HeaderData  = $HeaderData
        Metadata    = $Metadata
        IsEarlyExit = $true
      }
    }

    if ($Layout.CodeOnInit -ge 0) {
      try {
        $null = Invoke-NSISCodeSegment -State $State -Position $Layout.CodeOnInit
      } catch {
        # Continue parsing when non-metadata callbacks loop or rely on unsupported runtime state.
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

    if ([string]::IsNullOrWhiteSpace($State.Metadata.DisplayVersion) -or [string]::IsNullOrWhiteSpace($State.Metadata.ProductCode)) {
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
    $Switches = [System.Collections.Generic.List[object]]::new()
    $RejectedSwitches = [System.Collections.Generic.List[object]]::new()
    $Seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $Pattern = '(?<![A-Za-z0-9_./\\-])(?:--[A-Za-z][A-Za-z0-9][A-Za-z0-9._-]*|/[A-Za-z][A-Za-z0-9][A-Za-z0-9._-]*)(?::[^\s"''<>]+|=[^\s"''<>]+)?'
    $DefaultSwitches = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Switch in @('/S', '/NCRC', '/D', '/SD', '/LANG', '/LOG')) { $null = $DefaultSwitches.Add($Switch) }
    $ScopeSwitches = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Switch in @('/CURRENTUSER', '/currentuser', '/AllUsers', '/ALLUSERS', '/allusers', '--all-users', '--current-user')) { $null = $ScopeSwitches.Add($Switch) }
    $SilentSwitches = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Switch in @('/S', '/silent', '/verysilent', '--silent', '--updated')) { $null = $SilentSwitches.Add($Switch) }
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

        $IsKnownSwitch = $DefaultSwitches.Contains($Name) -or $ScopeSwitches.Contains($Name) -or $SilentSwitches.Contains($Name)
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
            IsCustomCandidate   = -not $DefaultSwitches.Contains($Name)
            Evidence            = $Evidence
          })
      }
    }

    $AdditionalSwitches = @($Switches | Where-Object { $_.IsCustomCandidate } | Select-Object -ExpandProperty Switch)

    [pscustomobject]@{
      Path                       = (Get-Item -Path $Path -Force).FullName
      InstallerType              = 'Nullsoft'
      Switches                   = $Switches.ToArray()
      AdditionalSwitches         = $AdditionalSwitches
      ScopeSwitches              = @($Switches | Where-Object { $_.IsScopeSwitch } | Select-Object -ExpandProperty Switch)
      SilentSwitches             = @($Switches | Where-Object { $_.IsSilentSwitch } | Select-Object -ExpandProperty Switch)
      CommandLineParsingEvidence = $ParsingMarkers
      RejectedSwitchCandidates   = $RejectedSwitches.ToArray()
      Warnings                   = @('Switch extraction is static string evidence. Confirm switch control-flow in the NSIS script or a VM before using custom switches in manifests.')
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

  return [pscustomobject]@{
    IsElectronBuilder = $Architectures.Count -gt 0
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
      }
    }
  }
}

function Get-NSISInfo {
  <#
  .SYNOPSIS
    Get static metadata from a Nullsoft Scriptable Install System installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Metadata = (Invoke-NSISStaticSimulation -Path $Path).Metadata
    if ([string]::IsNullOrWhiteSpace($Metadata.DisplayName) -and [string]::IsNullOrWhiteSpace($Metadata.DisplayVersion)) {
      throw 'The NSIS installer does not expose deterministic uninstall metadata'
    }

    return $Metadata
  }
}

function Read-ProductVersionFromNSIS {
  <#
  .SYNOPSIS
    Read the product version from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Info = Get-NSISInfo -Path $Path
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
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Info = Get-NSISInfo -Path $Path
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
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Info = Get-NSISInfo -Path $Path
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
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Info = Get-NSISInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.ProductCode)) { throw 'The NSIS installer does not expose an uninstall registry key' }
    return $Info.ProductCode
  }
}

Export-ModuleMember -Function Get-NSISInfo, Get-NSISInstallerSwitchInfo, Read-AdditionalInstallerSwitchesFromNSIS, Test-ElectronBuilder, Get-ElectronBuilderNSISInfo, Read-ProductVersionFromNSIS, Read-ProductNameFromNSIS, Read-PublisherFromNSIS, Read-ProductCodeFromNSIS
