BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  $LibraryPath = Join-Path $PSScriptRoot '..\Libraries'
  foreach ($ModuleName in @('Runtime', 'Binary', 'Compression', 'Archive', 'PE', 'RegistryAssociations', 'NSIS')) {
    Import-Module (Join-Path $LibraryPath "$ModuleName.psm1") -Force
  }

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'InstallerParsers\Main'

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url,

      [string]$Sha256,

      [switch]$UseSourceForgeMetaRefresh
    )

    $Arguments = @{
      Directory                 = $Script:FixtureDirectory
      Name                      = $Name
      Uri                       = $Url
      UseSourceForgeMetaRefresh = $UseSourceForgeMetaRefresh
    }
    if ($Sha256) { $Arguments.Sha256 = $Sha256 }
    Get-DumplingsTestFixture @Arguments
  }
}

Describe 'NSIS parser' {
  It 'Should keep NSIS blocks as byte arrays for fast entry parsing' {
    $Fixture = Get-InstallerFixture -Name 'alist-desktop_3.60.0_x64-setup.exe' -Url 'https://github.com/AlistGo/desktop-release/releases/download/v3.60.0/alist-desktop_3.60.0_x64-setup.exe'
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      param($Fixture)

      $HeaderData = Get-NSISHeaderData -Path $Fixture
      $BlockHeaders = Get-NSISBlockHeaders -HeaderBytes $HeaderData.HeaderBytes -Is64Bit $HeaderData.PEInfo.Is64Bit
      $EntryBlock = Get-NSISBlockBytes -HeaderBytes $HeaderData.HeaderBytes -BlockHeaders $BlockHeaders -Index 2

      [pscustomobject]@{
        IsByteArray = $EntryBlock -is [byte[]]
        Length      = $EntryBlock.Length
      }
    } $Fixture

    $Result.IsByteArray | Should -BeTrue
    $Result.Length | Should -BeGreaterThan 0
  }

  It 'Should recognize the source-backed NSISBI first-header layout' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $Bytes = [byte[]]::new(1024)
      $Bytes[0] = 0x4D
      $Bytes[1] = 0x5A
      [Array]::Copy([BitConverter]::GetBytes([uint32]0x40), 0, $Bytes, 0x3C, 4)
      [Array]::Copy([BitConverter]::GetBytes([uint32]0x00004550), 0, $Bytes, 0x40, 4)
      [Array]::Copy([BitConverter]::GetBytes([uint16]96), 0, $Bytes, 0x54, 2)

      $HeaderOffset = 512
      [Array]::Copy([BitConverter]::GetBytes([uint32]0x50), 0, $Bytes, $HeaderOffset, 4)
      [Array]::Copy($Script:NSIS_FIRST_HEADER_SIGNATURE, 0, $Bytes, $HeaderOffset + 4, $Script:NSIS_FIRST_HEADER_SIGNATURE.Length)
      [Array]::Copy([BitConverter]::GetBytes([uint32]128), 0, $Bytes, $HeaderOffset + 20, 4)
      [Array]::Copy([BitConverter]::GetBytes([uint32]512), 0, $Bytes, $HeaderOffset + 24, 4)

      $Candidate = Get-NSISFirstHeaderCandidate -Bytes $Bytes
      [Array]::Copy([BitConverter]::GetBytes([uint32]0x250), 0, $Bytes, $HeaderOffset, 4)
      $InvalidCandidate = Get-NSISFirstHeaderCandidate -Bytes $Bytes

      [pscustomobject]@{
        IsNsisBi                = $Candidate.IsNsisBi
        FirstHeaderSize         = $Candidate.FirstHeaderSize
        HasLongDataBlockOffsets = $Candidate.HasLongDataBlockOffsets
        SupportsExternalFiles   = $Candidate.SupportsExternalFiles
        InvalidCandidate        = $InvalidCandidate
      }
    }

    $Result.IsNsisBi | Should -BeTrue
    $Result.FirstHeaderSize | Should -Be 36
    $Result.HasLongDataBlockOffsets | Should -BeTrue
    $Result.SupportsExternalFiles | Should -BeTrue
    $Result.InvalidCandidate | Should -BeNullOrEmpty
  }

  It 'Should decode independently compressed NSISBI multithread-wrapper records' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $Expected = [System.Text.Encoding]::UTF8.GetBytes((('Unity-NSISBI-MTW-' * 5000) -join ''))
      $Payload = [System.Collections.Generic.List[byte]]::new()

      # The fixture uses two independently compressed zlib records. NSISBI uses
      # this same MTW framing around its selected build-time codec; Unity uses LZMA.
      $Ranges = @(
        [pscustomobject]@{ Offset = 0; Length = 40000 }
        [pscustomobject]@{ Offset = 40000; Length = $Expected.Length - 40000 }
      )
      foreach ($Range in $Ranges) {
        $CompressedBuffer = [System.IO.MemoryStream]::new()
        $Encoder = [System.IO.Compression.ZLibStream]::new(
          $CompressedBuffer,
          [System.IO.Compression.CompressionLevel]::Optimal,
          $true)
        try { $Encoder.Write($Expected, $Range.Offset, $Range.Length) } finally { $Encoder.Dispose() }
        $Compressed = $CompressedBuffer.ToArray()
        $CompressedBuffer.Dispose()

        $Payload.Add([byte]($Compressed.Length -band 0xFF))
        $Payload.Add([byte](($Compressed.Length -shr 8) -band 0xFF))
        $Payload.Add([byte](($Compressed.Length -shr 16) -band 0xFF))
        $Payload.AddRange($Compressed)
      }
      $Payload.AddRange([byte[]](0, 0, 0))

      $Stream = [System.IO.MemoryStream]::new($Payload.ToArray(), $false)
      try {
        $Probe = Read-BinaryBytes -Stream $Stream -Offset 0 -Count ([Math]::Min(24, $Stream.Length))
        $IsMtw = Test-NSISMtwHeader -Bytes $Probe -CompressedSize $Stream.Length
        $Decoded = Read-NSISMtwHeaderData -Stream $Stream -ExpectedOutputBytes $Expected.Length
      } finally { $Stream.Dispose() }

      [pscustomobject]@{
        IsMtw       = $IsMtw
        Compression = $Decoded.Compression
        BlockCount  = $Decoded.BlockCount
        Matches     = [System.Linq.Enumerable]::SequenceEqual([byte[]]$Expected, [byte[]]$Decoded.Bytes)
      }
    }

    $Result.IsMtw | Should -BeTrue
    $Result.Compression | Should -Be 'Zlib'
    $Result.BlockCount | Should -Be 2
    $Result.Matches | Should -BeTrue
  }

  It 'Should extract a selected NSISBI payload across MTW record boundaries' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'nsis-expanded-mtw'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Result = & $Module {
        param($ExpandedPath)

        $FileBytes = [Text.Encoding]::UTF8.GetBytes((('MTW payload data ' * 6000) -join ''))
        $HeaderSize = 32
        $DataOffset = 7
        $Logical = [IO.MemoryStream]::new()
        $Logical.Write([BitConverter]::GetBytes([uint64]$HeaderSize))
        $Logical.Write([byte[]]::new($HeaderSize + $DataOffset))
        $Logical.Write([BitConverter]::GetBytes([uint64]$FileBytes.Length))
        $Logical.Write($FileBytes)
        $LogicalBytes = $Logical.ToArray()
        $Logical.Dispose()

        $MtwBytes = [Collections.Generic.List[byte]]::new()
        for ($Offset = 0; $Offset -lt $LogicalBytes.Length; $Offset += 30000) {
          $Length = [Math]::Min(30000, $LogicalBytes.Length - $Offset)
          $CompressedBuffer = [IO.MemoryStream]::new()
          $Encoder = [IO.Compression.ZLibStream]::new($CompressedBuffer, [IO.Compression.CompressionLevel]::Optimal, $true)
          try { $Encoder.Write($LogicalBytes, $Offset, $Length) } finally { $Encoder.Dispose() }
          $Compressed = $CompressedBuffer.ToArray()
          $CompressedBuffer.Dispose()
          $MtwBytes.Add([byte]($Compressed.Length -band 0xFF))
          $MtwBytes.Add([byte](($Compressed.Length -shr 8) -band 0xFF))
          $MtwBytes.Add([byte](($Compressed.Length -shr 16) -band 0xFF))
          $MtwBytes.AddRange($Compressed)
        }
        $MtwBytes.AddRange([byte[]](0, 0, 0))

        $Stream = [IO.MemoryStream]::new($MtwBytes.ToArray(), $false)
        $OutputPath = Join-Path $ExpandedPath 'payload.bin'
        $HeaderData = [pscustomobject]@{
          PayloadDataOffset = 0L
          PayloadDataLength = $Stream.Length
          PackedSizeWidth   = 8
          HeaderSize        = $HeaderSize
          Compression       = 'Mtw-Zlib'
        }
        $Payload = [pscustomobject]@{
          SourcePath = 'payload.bin'; RelativePath = 'payload.bin'; OutputPath = $OutputPath
          DataOffset = [uint64]$DataOffset; TimeLow = [uint32]0; TimeHigh = [uint32]0; Crc32 = $null
        }
        try {
          $File = @(Expand-NSISMtwPayloads -Stream $Stream -HeaderData $HeaderData -Payload @($Payload) -MaximumExpandedBytes 1048576)[0]
        } finally { $Stream.Dispose() }
        $OutputStream = [IO.File]::OpenRead($File.FullName)
        try { $ActualBytes = Read-BinaryBytes -Stream $OutputStream -Offset 0 -Count ([int]$OutputStream.Length) } finally { $OutputStream.Dispose() }

        [pscustomobject]@{
          Length  = $File.Length
          Matches = [Linq.Enumerable]::SequenceEqual([byte[]]$FileBytes, [byte[]]$ActualBytes)
        }
      } $ExpandedPath

      $Result.Length | Should -BeGreaterThan 30000
      $Result.Matches | Should -BeTrue
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract stored non-solid aliases within the exact output budget' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'nsis-expanded-stored-alias'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Result = & $Module {
        param($ExpandedPath)

        $FileBytes = [Text.Encoding]::UTF8.GetBytes('one physical record with two compiled names')
        $Archive = [IO.MemoryStream]::new()
        $Archive.Write([byte[]]::new(4))
        $Archive.Write([BitConverter]::GetBytes([uint32]$FileBytes.Length))
        $Archive.Write($FileBytes)
        $Archive.Position = 0
        $HeaderData = [pscustomobject]@{
          FirstHeaderOffset    = 0L
          ArchiveSize          = $Archive.Length
          PayloadOffset        = 0L
          PackedSizeWidth      = 4
          CompressedHeaderSize = 0L
          Compression          = 'None'
        }
        $Payload = @(
          [pscustomobject]@{ SourcePath = 'first.bin'; RelativePath = 'first.bin'; OutputPath = (Join-Path $ExpandedPath 'first.bin'); DataOffset = [uint64]0; TimeLow = [uint32]0; TimeHigh = [uint32]0; Crc32 = $null }
          [pscustomobject]@{ SourcePath = 'second.bin'; RelativePath = 'second.bin'; OutputPath = (Join-Path $ExpandedPath 'second.bin'); DataOffset = [uint64]0; TimeLow = [uint32]0; TimeHigh = [uint32]0; Crc32 = $null }
        )
        try {
          $Files = @(Expand-NSISNonSolidPayloads -Stream $Archive -HeaderData $HeaderData -Payload $Payload -MaximumExpandedBytes ($FileBytes.Length * 2))
        } finally { $Archive.Dispose() }

        [pscustomobject]@{
          Count   = $Files.Count
          Lengths = @($Files | ForEach-Object Length)
          First   = Get-Content -LiteralPath $Files[0].FullName -Raw
          Second  = Get-Content -LiteralPath $Files[1].FullName -Raw
        }
      } $ExpandedPath

      $Result.Count | Should -Be 2
      $Result.Lengths | Should -Be @(43, 43)
      $Result.First | Should -Be 'one physical record with two compiled names'
      $Result.Second | Should -Be $Result.First
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should recover uninstall metadata from source-accurate EW_WRITEREG entries' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $StringBytes = [System.Collections.Generic.List[byte]]::new()

      function Add-TestString {
        param([string]$Text)

        $Offset = [int]($StringBytes.Count / 2)
        $StringBytes.AddRange([System.Text.Encoding]::Unicode.GetBytes($Text + [char]0))
        return $Offset
      }

      $KeyOffset = Add-TestString 'Software\Microsoft\Windows\CurrentVersion\Uninstall\CCFLink'
      $NameOffset = Add-TestString 'DisplayVersion'
      $ValueOffset = Add-TestString '7.7.0-Release.80131'
      $HklmRawValue = [uint32]$Script:NSIS_REG_ROOT_HKLM
      $HklmSignedValue = [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes($HklmRawValue), 0)

      $State = [pscustomobject]@{
        Entries          = @(
          [pscustomobject]@{
            Opcode    = $Script:NSIS_OPCODE_WRITE_REG
            RawOpcode = $Script:NSIS_OPCODE_WRITE_REG
            Raw       = [uint32[]]@($Script:NSIS_OPCODE_WRITE_REG, $HklmRawValue, $KeyOffset, $NameOffset, $ValueOffset, 1, 1)
            Values    = [int[]]@($Script:NSIS_OPCODE_WRITE_REG, $HklmSignedValue, $KeyOffset, $NameOffset, $ValueOffset, 1, 1)
          }
        )
        StringsBlock     = $StringBytes.ToArray()
        VersionInfo      = [pscustomobject]@{
          Unicode = $true
          IsV3    = $true
          Type    = 'NSIS3'
        }
        Variables        = @{}
        Registry         = @{}
        RegistryWrites   = [System.Collections.Generic.List[object]]::new()
        ExecutedPayloads = [System.Collections.Generic.List[object]]::new()
        Warnings         = [System.Collections.Generic.List[string]]::new()
        Files            = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        ShellVarContext  = 'HKLM'
        Metadata         = [ordered]@{
          DisplayVersion             = $null
          DisplayName                = $null
          Publisher                  = $null
          ProductCode                = $null
          DefaultInstallLocation     = $null
          UninstallString            = $null
          QuietUninstallString       = $null
          DisplayIcon                = $null
          SystemComponent            = $null
          Scope                      = $null
          WritesAppsAndFeaturesEntry = $false
          RegistryValues             = @{}
          RegistryWrites             = @()
          ExtractedFiles             = @()
          ExecutedPayloads           = @()
          Warnings                   = @()
          ParserVersionInfo          = $null
        }
      }

      Add-NSISDirectUninstallWrites -State $State
      [pscustomobject]@{
        DisplayVersion = $State.Metadata.DisplayVersion
        ProductCode    = $State.Metadata.ProductCode
        Scope          = $State.Metadata.Scope
      }
    }

    $Result.DisplayVersion | Should -Be '7.7.0-Release.80131'
    $Result.ProductCode | Should -Be 'CCFLink'
    $Result.Scope | Should -Be 'machine'
  }

  It 'Should normalize NSISBI opcodes and shifted EW_WRITEREG operands' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $StringBytes = [System.Collections.Generic.List[byte]]::new()

      function Add-TestString {
        param([string]$Text)

        $Offset = [int]($StringBytes.Count / 2)
        $StringBytes.AddRange([System.Text.Encoding]::Unicode.GetBytes($Text + [char]0))
        return $Offset
      }

      $KeyOffset = Add-TestString 'Software\Microsoft\Windows\CurrentVersion\Uninstall\NSISBIApp'
      $NameOffset = Add-TestString 'DisplayVersion'
      $ValueOffset = Add-TestString '6.7.3.0'
      $HklmRawValue = [uint32]$Script:NSIS_REG_ROOT_HKLM
      $HklmSignedValue = [BitConverter]::ToInt32([BitConverter]::GetBytes($HklmRawValue), 0)
      $RawOpcode = [uint32]53
      $LayoutOpcode = ConvertFrom-NSISBiOpcode -Opcode $RawOpcode
      $State = [pscustomobject]@{
        Entries          = @([pscustomobject]@{
            Opcode       = $LayoutOpcode
            RawOpcode    = $RawOpcode
            LayoutOpcode = $LayoutOpcode
            Raw          = [uint32[]]@($RawOpcode, $HklmRawValue, $KeyOffset, $NameOffset, $ValueOffset, 0, 1, 1, 0)
            Values       = [int[]]@($RawOpcode, $HklmSignedValue, $KeyOffset, $NameOffset, $ValueOffset, 0, 1, 1, 0)
          })
        StringsBlock     = $StringBytes.ToArray()
        VersionInfo      = [pscustomobject]@{ Unicode = $true; IsV3 = $true; Type = 'NSIS3'; IsNsisBi = $true }
        Variables        = @{}
        Registry         = @{}
        RegistryWrites   = [System.Collections.Generic.List[object]]::new()
        ExecutedPayloads = [System.Collections.Generic.List[object]]::new()
        Warnings         = [System.Collections.Generic.List[string]]::new()
        Files            = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        ShellVarContext  = 'HKLM'
        Metadata         = [ordered]@{
          DisplayVersion = $null; DisplayName = $null; Publisher = $null; ProductCode = $null
          DefaultInstallLocation = $null; UninstallString = $null; QuietUninstallString = $null
          DisplayIcon = $null; SystemComponent = $null; Scope = $null; WritesAppsAndFeaturesEntry = $false
          RegistryValues = @{}; RegistryWrites = @(); ExtractedFiles = @(); ExecutedPayloads = @()
          Warnings = @(); ParserVersionInfo = $null
        }
      }

      Add-NSISDirectUninstallWrites -State $State
      [pscustomobject]@{
        LayoutOpcode   = $LayoutOpcode
        DisplayVersion = $State.Metadata.DisplayVersion
        ProductCode    = $State.Metadata.ProductCode
        RegistryType   = $State.RegistryWrites[0].Type
      }
    }

    $Result.LayoutOpcode | Should -Be 51
    $Result.DisplayVersion | Should -Be '6.7.3.0'
    $Result.ProductCode | Should -Be 'NSISBIApp'
    $Result.RegistryType | Should -Be 'REG_SZ'
  }

  It 'Should not treat the old fake opcode 53 as a registry write' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $StringBytes = [System.Collections.Generic.List[byte]]::new()

      function Add-TestString {
        param([string]$Text)

        $Offset = [int]($StringBytes.Count / 2)
        $StringBytes.AddRange([System.Text.Encoding]::Unicode.GetBytes($Text + [char]0))
        return $Offset
      }

      $KeyOffset = Add-TestString 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Fake'
      $NameOffset = Add-TestString 'DisplayVersion'
      $ValueOffset = Add-TestString '9.9.9'
      $RegEnumOpcode = [uint32]53
      $HklmRawValue = [uint32]$Script:NSIS_REG_ROOT_HKLM
      $HklmSignedValue = [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes($HklmRawValue), 0)

      $State = [pscustomobject]@{
        Entries          = @(
          [pscustomobject]@{
            Opcode    = $RegEnumOpcode
            RawOpcode = $RegEnumOpcode
            Raw       = [uint32[]]@($RegEnumOpcode, $HklmRawValue, $KeyOffset, $NameOffset, $ValueOffset, 1, 1)
            Values    = [int[]]@($RegEnumOpcode, $HklmSignedValue, $KeyOffset, $NameOffset, $ValueOffset, 1, 1)
          }
        )
        StringsBlock     = $StringBytes.ToArray()
        VersionInfo      = [pscustomobject]@{ Unicode = $true; IsV3 = $true; Type = 'NSIS3' }
        Variables        = @{}
        Registry         = @{}
        RegistryWrites   = [System.Collections.Generic.List[object]]::new()
        ExecutedPayloads = [System.Collections.Generic.List[object]]::new()
        Warnings         = [System.Collections.Generic.List[string]]::new()
        Files            = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        ShellVarContext  = 'HKLM'
        Metadata         = [ordered]@{
          DisplayVersion             = $null
          DisplayName                = $null
          Publisher                  = $null
          ProductCode                = $null
          DefaultInstallLocation     = $null
          UninstallString            = $null
          QuietUninstallString       = $null
          DisplayIcon                = $null
          SystemComponent            = $null
          Scope                      = $null
          WritesAppsAndFeaturesEntry = $false
          RegistryValues             = @{}
          RegistryWrites             = @()
          ExtractedFiles             = @()
          ExecutedPayloads           = @()
          Warnings                   = @()
          ParserVersionInfo          = $null
        }
      }

      Add-NSISDirectUninstallWrites -State $State
      [pscustomobject]@{
        DisplayVersion = $State.Metadata.DisplayVersion
        RegistryWrites = $State.RegistryWrites.Count
      }
    }

    $Result.DisplayVersion | Should -BeNullOrEmpty
    $Result.RegistryWrites | Should -Be 0
  }

  It 'Should preserve EW_WRITEREG type, scope, and hidden-entry evidence' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $StringBytes = [System.Collections.Generic.List[byte]]::new()

      function Add-TestString {
        param([string]$Text)

        $Offset = [int]($StringBytes.Count / 2)
        $StringBytes.AddRange([System.Text.Encoding]::Unicode.GetBytes($Text + [char]0))
        return $Offset
      }

      $KeyOffset = Add-TestString 'Software\Microsoft\Windows\CurrentVersion\Uninstall\UnitApp'
      $DisplayNameOffset = Add-TestString 'DisplayName'
      $DisplayVersionOffset = Add-TestString 'DisplayVersion'
      $SystemComponentOffset = Add-TestString 'SystemComponent'
      $NameValueOffset = Add-TestString 'Unit App'
      $VersionValueOffset = Add-TestString '%VERSION%'
      $HiddenValueOffset = Add-TestString '1'
      $ShctxRawValue = [uint32]$Script:NSIS_REG_ROOT_SHCTX
      $HkcuRawValue = [uint32]$Script:NSIS_REG_ROOT_HKCU
      $ShctxSignedValue = [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes($ShctxRawValue), 0)
      $HkcuSignedValue = [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes($HkcuRawValue), 0)

      $State = [pscustomobject]@{
        Entries          = @(
          [pscustomobject]@{
            Opcode    = $Script:NSIS_OPCODE_WRITE_REG
            RawOpcode = $Script:NSIS_OPCODE_WRITE_REG
            Raw       = [uint32[]]@($Script:NSIS_OPCODE_WRITE_REG, $ShctxRawValue, $KeyOffset, $DisplayNameOffset, $NameValueOffset, $Script:NSIS_REG_TYPE_STRING, $Script:NSIS_REG_TYPE_STRING)
            Values    = [int[]]@($Script:NSIS_OPCODE_WRITE_REG, $ShctxSignedValue, $KeyOffset, $DisplayNameOffset, $NameValueOffset, $Script:NSIS_REG_TYPE_STRING, $Script:NSIS_REG_TYPE_STRING)
          },
          [pscustomobject]@{
            Opcode    = $Script:NSIS_OPCODE_WRITE_REG
            RawOpcode = $Script:NSIS_OPCODE_WRITE_REG
            Raw       = [uint32[]]@($Script:NSIS_OPCODE_WRITE_REG, $HkcuRawValue, $KeyOffset, $DisplayVersionOffset, $VersionValueOffset, $Script:NSIS_REG_TYPE_STRING, $Script:NSIS_REG_TYPE_EXPAND_STRING)
            Values    = [int[]]@($Script:NSIS_OPCODE_WRITE_REG, $HkcuSignedValue, $KeyOffset, $DisplayVersionOffset, $VersionValueOffset, $Script:NSIS_REG_TYPE_STRING, $Script:NSIS_REG_TYPE_EXPAND_STRING)
          },
          [pscustomobject]@{
            Opcode    = $Script:NSIS_OPCODE_WRITE_REG
            RawOpcode = $Script:NSIS_OPCODE_WRITE_REG
            Raw       = [uint32[]]@($Script:NSIS_OPCODE_WRITE_REG, $HkcuRawValue, $KeyOffset, $SystemComponentOffset, $HiddenValueOffset, $Script:NSIS_REG_TYPE_DWORD, $Script:NSIS_REG_TYPE_DWORD)
            Values    = [int[]]@($Script:NSIS_OPCODE_WRITE_REG, $HkcuSignedValue, $KeyOffset, $SystemComponentOffset, $HiddenValueOffset, $Script:NSIS_REG_TYPE_DWORD, $Script:NSIS_REG_TYPE_DWORD)
          }
        )
        StringsBlock     = $StringBytes.ToArray()
        VersionInfo      = [pscustomobject]@{ Unicode = $true; IsV3 = $true; Type = 'NSIS3' }
        Variables        = @{}
        Registry         = @{}
        RegistryWrites   = [System.Collections.Generic.List[object]]::new()
        ExecutedPayloads = [System.Collections.Generic.List[object]]::new()
        Warnings         = [System.Collections.Generic.List[string]]::new()
        Files            = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        ShellVarContext  = 'HKCU'
        Metadata         = [ordered]@{
          DisplayVersion             = $null
          DisplayName                = $null
          Publisher                  = $null
          ProductCode                = $null
          DefaultInstallLocation     = $null
          UninstallString            = $null
          QuietUninstallString       = $null
          DisplayIcon                = $null
          SystemComponent            = $null
          Scope                      = $null
          WritesAppsAndFeaturesEntry = $false
          RegistryValues             = @{}
          RegistryWrites             = @()
          ExtractedFiles             = @()
          ExecutedPayloads           = @()
          Warnings                   = @()
          ParserVersionInfo          = $null
        }
      }

      Add-NSISDirectUninstallWrites -State $State
      Complete-NSISMetadata -State $State
    }

    $Result.DisplayName | Should -Be 'Unit App'
    $Result.DisplayVersion | Should -Be '%VERSION%'
    $Result.ProductCode | Should -Be 'UnitApp'
    $Result.Scope | Should -Be 'user'
    $Result.WritesAppsAndFeaturesEntry | Should -BeFalse
    $Result.RegistryWrites.Type | Should -Contain 'REG_SZ'
    $Result.RegistryWrites.Type | Should -Contain 'REG_EXPAND_SZ'
    $Result.RegistryWrites.Type | Should -Contain 'REG_DWORD'
    $Result.SystemComponent | Should -Be '1'
  }

  It 'Should normalize source-backed NSIS command layouts' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      [pscustomobject]@{
        LogOpcode      = Get-NSISNormalizedOpcode -Opcode $Script:NSIS_OPCODE_SECTION_SET -Type 'NSIS3' -Unicode $true -LogCmdIsEnabled $true
        ShiftedSection = Get-NSISNormalizedOpcode -Opcode ($Script:NSIS_OPCODE_SECTION_SET + 1) -Type 'NSIS3' -Unicode $true -LogCmdIsEnabled $true
        ParkFileWrite  = Get-NSISNormalizedOpcode -Opcode $Script:NSIS_OPCODE_FILE_SEEK -Type 'Park1' -Unicode $true -LogCmdIsEnabled $false
        RegEnum        = Get-NSISNormalizedOpcode -Opcode 53 -Type 'NSIS3' -Unicode $true -LogCmdIsEnabled $false
        NsisBiWriteReg = ConvertFrom-NSISBiOpcode -Opcode 53
      }
    }

    $Result.LogOpcode | Should -Be 70
    $Result.ShiftedSection | Should -Be 63
    $Result.ParkFileWrite | Should -Be 68
    $Result.RegEnum | Should -Be 53
    $Result.NsisBiWriteReg | Should -Be 51
  }

  It 'Should recognize bounded vendor LZMA2 header framing' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      # Property 0x18 selects a 16 MiB dictionary. Control 0xE3 declares a
      # 241,198-byte output chunk containing 20,522 compressed bytes and a new
      # LZMA property (0x5D), exactly filling a 20,530-byte NSIS block.
      $Bytes = [byte[]](0x18, 0xE3, 0xAE, 0x2D, 0x50, 0x29, 0x5D)
      [pscustomobject]@{
        IsLzma2         = Test-NSISLzma2Header -Bytes $Bytes -CompressedSize 20530 -ExpectedUncompressedSize 241198
        Truncated       = Test-NSISLzma2Header -Bytes $Bytes -CompressedSize 20528 -ExpectedUncompressedSize 241198
        OversizedOutput = Test-NSISLzma2Header -Bytes $Bytes -CompressedSize 20530 -ExpectedUncompressedSize 241197
        FirstCandidate  = (Get-NSISCompressionCandidates -Bytes $Bytes -CompressedSize 20530 -ExpectedUncompressedSize 241198)[0]
      }
    }

    $Result.IsLzma2 | Should -BeTrue
    $Result.Truncated | Should -BeFalse
    $Result.OversizedOutput | Should -BeFalse
    $Result.FirstCandidate | Should -Be 'Lzma2'
  }

  It 'Should fail quickly on malformed NSIS headers' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Fixture = Join-Path $Script:FixtureDirectory 'malformed-nsis.exe'
    [System.IO.File]::WriteAllBytes($Fixture, [byte[]](0x4D, 0x5A, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE))
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    & $Module {
      param($Fixture)
      { Get-NSISHeaderData -Path $Fixture } | Should -Throw
    } $Fixture

    $Stopwatch.Stop()
    $Stopwatch.Elapsed.TotalSeconds | Should -BeLessThan 2
  }

  It 'Should read static metadata from the AList installer' {
    $Fixture = Get-InstallerFixture -Name 'alist-desktop_3.60.0_x64-setup.exe' -Url 'https://github.com/AlistGo/desktop-release/releases/download/v3.60.0/alist-desktop_3.60.0_x64-setup.exe'
    $Info = Get-NSISInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be 'alist-desktop'
    $Info.DisplayVersion | Should -Be '3.60.0'
    $Info.ProductCode | Should -Be 'alist-desktop'
  }

  It 'Should extract a selected executable from a solid LZMA AList installer' {
    $Fixture = Get-InstallerFixture -Name 'alist-desktop_3.60.0_x64-setup.exe' -Url 'https://github.com/AlistGo/desktop-release/releases/download/v3.60.0/alist-desktop_3.60.0_x64-setup.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'nsis-expanded-alist'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = @(Expand-NSISInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'alist-desktop.exe' -MaximumExpandedBytes 33554432 -CollisionAction Rename)

      $Extracted | Should -HaveCount 1
      $Extracted[0].VersionInfo.FileVersion | Should -Be '3.60.0'
      $Signature = [byte[]]::new(2)
      $ExtractedStream = [IO.File]::OpenRead($Extracted[0].FullName)
      try { $null = $ExtractedStream.Read($Signature, 0, $Signature.Length) } finally { $ExtractedStream.Dispose() }
      $Signature | Should -Be @(0x4D, 0x5A)
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract every catalogued AList payload when Name is omitted' {
    $Fixture = Get-InstallerFixture -Name 'alist-desktop_3.60.0_x64-setup.exe' -Url 'https://github.com/AlistGo/desktop-release/releases/download/v3.60.0/alist-desktop_3.60.0_x64-setup.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'nsis-expanded-alist-all'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = @(Expand-NSISInstaller -Path $Fixture -DestinationPath $ExpandedPath -MaximumExpandedBytes 1073741824 -CollisionAction Rename)

      $Extracted.Count | Should -BeGreaterThan 1
      $Extracted.Name | Should -Contain 'alist-desktop.exe'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should read static metadata from a dual-scope BongoCat NSIS installer' {
    $Fixture = Get-InstallerFixture -Name 'BongoCat_1.1.0_x64-setup.exe' -Url 'https://github.com/ayangweb/BongoCat/releases/download/v1.1.0/BongoCat_1.1.0_x64-setup.exe'
    $Info = Get-NSISInfo -Path $Fixture
    $IsElectronBuilder = Test-ElectronBuilder -Path $Fixture

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be 'BongoCat'
    $Info.DisplayVersion | Should -Be '1.1.0'
    $Info.ProductCode | Should -Be 'BongoCat'
    $Info.Publisher | Should -Be 'ayangweb'
    $IsElectronBuilder | Should -BeFalse
  }

  It 'Should extract a selected executable after skipping earlier solid BongoCat records' {
    $Fixture = Get-InstallerFixture -Name 'BongoCat_1.1.0_x64-setup.exe' -Url 'https://github.com/ayangweb/BongoCat/releases/download/v1.1.0/BongoCat_1.1.0_x64-setup.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'nsis-expanded-bongocat'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = @(Expand-NSISInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'bongo-cat.exe' -MaximumExpandedBytes 33554432 -CollisionAction Rename)

      $Extracted | Should -HaveCount 1
      $Extracted[0].VersionInfo.FileVersion | Should -Be '1.1.0'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should read static metadata from a dual-scope RedPanda C++ NSIS installer' {
    $Fixture = Get-InstallerFixture -Name 'RedPanda.C++.3.4.win64.MinGW64_11.5.0.Setup.exe' -Url 'https://sourceforge.net/projects/redpanda-cpp/files/v3.4/RedPanda.C++.3.4.win64.MinGW64_11.5.0.Setup.exe/download' -UseSourceForgeMetaRefresh
    $Info = Get-NSISInfo -Path $Fixture
    $IsElectronBuilder = Test-ElectronBuilder -Path $Fixture

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be 'Red Panda C++ (x64)'
    $Info.DisplayVersion | Should -Be '3.4'
    $Info.ProductCode | Should -Be 'RedPanda-C++'
    $Info.Publisher | Should -Be 'Roy Qu (royqh1979@gmail.com)'
    $IsElectronBuilder | Should -BeFalse
  }

  It 'Should read CCFLink metadata and reject nested command switches' {
    $Fixture = Get-InstallerFixture -Name 'CCFLink_v7.7.0.80131.exe' -Url 'https://exclusive-app-cdn.dingtalk.com/CCFLink_v7.7.0.80131.exe'
    $Info = Get-NSISInfo -Path $Fixture
    $SwitchInfo = Get-NSISInstallerSwitchInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be 'CCFLink'
    $Info.DisplayVersion | Should -Be '7.7.0-Release.80131'
    $Info.ProductCode | Should -Be 'CCFLink'
    $Info.Scope | Should -Be 'machine'
    $SwitchInfo.AdditionalSwitches | Should -BeNullOrEmpty
    $SwitchInfo.RejectedSwitchCandidates.Switch | Should -Contain '/IM'
  }

  It 'Should read NetEase UU Remote metadata from a vendor LZMA2 NSIS header' {
    $Fixture = Get-InstallerFixture -Name 'UURemote_Setup_4.34.0.8979.exe' `
      -Url 'https://a56.gdl.netease.com/UURemote_Setup_4.34.0.8979_0723104500_gwqd.exe' `
      -Sha256 '237EB74939A62935AE3E2B1FD43C484D634CCD96FB1094BA764C8CB64065DC9A'
    $Info = Get-NSISInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be 'UU远程'
    $Info.DisplayVersion | Should -Be '4.34.0.8979'
    $Info.ProductCode | Should -Be 'GameViewer'
    $Info.Publisher | Should -Be 'Netease'
    $Info.Scope | Should -Be 'user'
    $Info.Warnings | Should -BeNullOrEmpty
  }

  It 'Should extract a selected non-solid vendor LZMA2 payload from UU Remote' {
    $Fixture = Get-InstallerFixture -Name 'UURemote_Setup_4.34.0.8979.exe' `
      -Url 'https://a56.gdl.netease.com/UURemote_Setup_4.34.0.8979_0723104500_gwqd.exe' `
      -Sha256 '237EB74939A62935AE3E2B1FD43C484D634CCD96FB1094BA764C8CB64065DC9A'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'nsis-expanded-uuremote'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = @(Expand-NSISInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'QtLGPL3License.txt' -MaximumExpandedBytes 1048576 -CollisionAction Rename)

      $Extracted | Should -HaveCount 1
      $Extracted[0].Length | Should -Be 7793
      Get-Content -LiteralPath $Extracted[0].FullName -TotalCount 1 | Should -Be 'GNU LESSER GENERAL PUBLIC LICENSE'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should decode and extract a solid raw-BZip2 Exr-IO installer' {
    $Fixture = Get-InstallerFixture -Name 'Exr-IO_2.06.00.exe' `
      -Url 'https://www.exr-io.com/wp-content/uploads/Exr-IO_2.06.00.exe' `
      -Sha256 '4BAE349608064A28806C81554C1D8867AFCCF2883BCE4112568A3F3715AC1E87'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'nsis-expanded-exr-io'
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Header = & $Module { param($Path) Get-NSISHeaderData -Path $Path } $Fixture
      $Info = Get-NSISInfo -Path $Fixture
      $Extracted = @(Expand-NSISInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'Exr-IO.8bi' -MaximumExpandedBytes 16777216 -CollisionAction Rename)

      $Header.Compression | Should -Be 'BZip2'
      $Header.IsSolid | Should -BeTrue
      $Info.DisplayName | Should -Be '3d-io Exr-IO 2.06.00'
      $Info.DisplayVersion | Should -Be '2.06.00'
      # The installer contains x86 and x64 plug-ins with the same logical
      # filename. Rename collision handling must preserve both payloads.
      $Extracted | Should -HaveCount 2
      $Extracted.Name | Should -Contain 'Exr-IO.8bi'
      $Extracted.Name | Should -Contain 'Exr-IO (1).8bi'
      $Hashes = @($Extracted | ForEach-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash })
      $Hashes | Should -Contain 'D773AFBCC6061FD75D2B15B54F6294FC85A219C57E11E454B6B97B27CA5C7F27'
      $Hashes | Should -Contain 'D6BACFCE8458406844683CFCCA32D8446B0995A0FBF21052CDE89ED61A935F9D'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should decode and extract a non-solid raw-BZip2 Visual C++ libjpeg-turbo installer' {
    $Fixture = Get-InstallerFixture -Name 'libjpeg-turbo-3.2.0-vc-x64.exe' `
      -Url 'https://github.com/libjpeg-turbo/libjpeg-turbo/releases/download/3.2.0/libjpeg-turbo-3.2.0-vc-x64.exe' `
      -Sha256 '662761D8BA8DAE04AEC74023EBAECEB856C2B56B9B59CFD180759D26300DDA42'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'nsis-expanded-libjpeg-vc'
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Header = & $Module { param($Path) Get-NSISHeaderData -Path $Path } $Fixture
      $Info = Get-NSISInfo -Path $Fixture
      $Extracted = @(Expand-NSISInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'cjpeg.exe' -MaximumExpandedBytes 1048576 -CollisionAction Rename)

      $Header.Compression | Should -Be 'BZip2'
      $Header.IsSolid | Should -BeFalse
      $Info.DisplayName | Should -Be 'libjpeg-turbo SDK v3.2.0 for Visual C++ 64-bit'
      $Info.ProductCode | Should -Be 'libjpeg-turbo64 3.2.0'
      $Extracted | Should -HaveCount 1
      $Extracted[0].Length | Should -Be 185856
      (Get-FileHash -LiteralPath $Extracted[0].FullName -Algorithm SHA256).Hash | Should -Be '97C382C511F6D597E97141F4064C8E67ED64617D1D51793C1DF183004E21BF0F'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should decode and extract a non-solid raw-BZip2 GCC libjpeg-turbo installer' {
    $Fixture = Get-InstallerFixture -Name 'libjpeg-turbo-3.2.0-gcc-x64.exe' `
      -Url 'https://github.com/libjpeg-turbo/libjpeg-turbo/releases/download/3.2.0/libjpeg-turbo-3.2.0-gcc-x64.exe' `
      -Sha256 '5A71EA596C573EA3B44C8E7B5E78613D3A28DC9490DC714E7222C9F63F55E454'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'nsis-expanded-libjpeg-gcc'
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Header = & $Module { param($Path) Get-NSISHeaderData -Path $Path } $Fixture
      $Info = Get-NSISInfo -Path $Fixture
      $Extracted = @(Expand-NSISInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'cjpeg.exe' -MaximumExpandedBytes 1048576 -CollisionAction Rename)

      $Header.Compression | Should -Be 'BZip2'
      $Header.IsSolid | Should -BeFalse
      $Info.DisplayName | Should -Be 'libjpeg-turbo SDK v3.2.0 for GCC 64-bit'
      $Info.ProductCode | Should -Be 'libjpeg-turbo-gcc64 3.2.0'
      $Extracted | Should -HaveCount 1
      $Extracted[0].Length | Should -Be 315480
      (Get-FileHash -LiteralPath $Extracted[0].FullName -Algorithm SHA256).Hash | Should -Be '7C6A635A946449A55BAE4B193FFC5176EAE0ADFEC16C30692ED7D03817AE534A'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should reject payload output beyond the extraction limit without retaining a partial file' {
    $Fixture = Get-InstallerFixture -Name 'alist-desktop_3.60.0_x64-setup.exe' -Url 'https://github.com/AlistGo/desktop-release/releases/download/v3.60.0/alist-desktop_3.60.0_x64-setup.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'nsis-expanded-limit'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      { Expand-NSISInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'alist-desktop.exe' -MaximumExpandedBytes 1024 -CollisionAction Rename } | Should -Throw
      @(Get-ChildItem -LiteralPath $ExpandedPath -File -Recurse -ErrorAction SilentlyContinue) | Should -HaveCount 0
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should locate an archive aligned relative to an embedded stub and reject orphan headers' {
    $Fixture = Get-InstallerFixture -Name 'alist-desktop_3.60.0_x64-setup.exe' -Url 'https://github.com/AlistGo/desktop-release/releases/download/v3.60.0/alist-desktop_3.60.0_x64-setup.exe'
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      param($Fixture)

      $InnerBytes = [IO.File]::ReadAllBytes($Fixture)
      $InnerStream = [IO.MemoryStream]::new($InnerBytes, $false)
      try {
        $InnerCandidate = Get-NSISFirstHeaderCandidate -Stream $InnerStream
      } finally { $InnerStream.Dispose() }

      # Embed the installer behind a non-alignment-sized prefix so its archive
      # stays aligned relative to its own stub but not to the file start.
      $PrefixLength = 280
      $OuterBytes = [byte[]]::new($PrefixLength + $InnerBytes.Length)
      [Array]::Copy($InnerBytes, 0, $OuterBytes, $PrefixLength, $InnerBytes.Length)
      $OuterStream = [IO.MemoryStream]::new($OuterBytes, $false)
      try {
        $EmbeddedCandidate = Get-NSISFirstHeaderCandidate -Stream $OuterStream
      } finally { $OuterStream.Dispose() }

      # A well-formed but non-aligned header without a PE stub a whole number
      # of alignment blocks earlier must still be rejected.
      $OrphanBytes = [byte[]]::new(8192)
      $OrphanOffset = 280
      [Array]::Copy($Script:NSIS_FIRST_HEADER_SIGNATURE, 0, $OrphanBytes, $OrphanOffset + 4, $Script:NSIS_FIRST_HEADER_SIGNATURE.Length)
      [Array]::Copy([BitConverter]::GetBytes([uint32]128), 0, $OrphanBytes, $OrphanOffset + 20, 4)
      [Array]::Copy([BitConverter]::GetBytes([uint32]1024), 0, $OrphanBytes, $OrphanOffset + 24, 4)
      $OrphanStream = [IO.MemoryStream]::new($OrphanBytes, $false)
      try {
        $OrphanCandidate = Get-NSISFirstHeaderCandidate -Stream $OrphanStream
      } finally { $OrphanStream.Dispose() }

      [pscustomobject]@{
        InnerOffset    = $InnerCandidate.Offset
        EmbeddedOffset = $EmbeddedCandidate.Offset
        Orphan         = $OrphanCandidate
      }
    } $Fixture

    $Result.EmbeddedOffset | Should -Be ($Result.InnerOffset + 280)
    $Result.Orphan | Should -BeNullOrEmpty
  }

  It 'Should report install roots as WinGet environment-variable paths' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      [pscustomobject]@{
        ProgramFiles   = ConvertTo-NSISManifestPath -Path "$env:ProgramFiles\Process Lasso"
        ProgramFiles86 = ConvertTo-NSISManifestPath -Path "${env:ProgramFiles(x86)}\App"
        LocalAppData   = ConvertTo-NSISManifestPath -Path "$env:LOCALAPPDATA\Programs\App"
        RootOnly       = ConvertTo-NSISManifestPath -Path $env:ProgramFiles
        NotAPrefix     = ConvertTo-NSISManifestPath -Path "$env:ProgramFiles.exe"
        Unrelated      = ConvertTo-NSISManifestPath -Path 'D:\Custom\App'
      }
    }

    $Result.ProgramFiles | Should -Be '%ProgramFiles%\Process Lasso'
    $Result.ProgramFiles86 | Should -Be '%ProgramFiles(x86)%\App'
    $Result.LocalAppData | Should -Be '%LocalAppData%\Programs\App'
    $Result.RootOnly | Should -Be '%ProgramFiles%'
    $Result.NotAPrefix | Should -Be "$env:ProgramFiles.exe"
    $Result.Unrelated | Should -Be 'D:\Custom\App'
  }

  It 'Should read static metadata from an NSIS payload embedded as a PE resource' {
    $Fixture = Get-InstallerFixture -Name 'FeiLian_Windows_x86_v3.2.16_r4828_a60997.exe' -Url 'https://cdn.isealsuite.com/windows/FeiLian_Windows_x86_v3.2.16_r4828_a60997.exe'
    $Info = Get-NSISInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be 'FeiLian'
    $Info.DisplayVersion | Should -Be '3.2.16.4828'
    $Info.ProductCode | Should -Be 'CorpLink'
    $Info.Publisher | Should -Be '北京火山引擎科技有限公司'
  }
}

