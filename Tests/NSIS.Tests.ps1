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

  It 'Should return distinct localized ARP identities from NSIS language strings' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $StringBytes = [System.Collections.Generic.List[byte]]::new()

      function Add-TestString {
        param([string]$Text)

        $Offset = [int]($StringBytes.Count / 2)
        $StringBytes.AddRange([System.Text.Encoding]::Unicode.GetBytes($Text + [char]0))
        return $Offset
      }

      $null = Add-TestString 'unused'
      $KeyOffset = Add-TestString 'Software\Microsoft\Windows\CurrentVersion\Uninstall\WeMeet'
      $DisplayNameOffset = Add-TestString 'DisplayName'
      $PublisherOffset = Add-TestString 'Publisher'
      $EnglishNameOffset = Add-TestString 'Tencent Meeting'
      $EnglishPublisherOffset = Add-TestString 'Tencent Technology (Shenzhen) Co. Ltd.'
      $ChineseNameOffset = Add-TestString '腾讯会议'
      $ChinesePublisherOffset = Add-TestString '腾讯科技（深圳）有限公司'
      $HklmRawValue = [uint32]$Script:NSIS_REG_ROOT_HKLM
      $HklmSignedValue = [BitConverter]::ToInt32([BitConverter]::GetBytes($HklmRawValue), 0)

      $Entries = @(
        [pscustomobject]@{
          Opcode = $Script:NSIS_OPCODE_WRITE_REG; RawOpcode = $Script:NSIS_OPCODE_WRITE_REG
          Raw = [uint32[]]@($Script:NSIS_OPCODE_WRITE_REG, $HklmRawValue, $KeyOffset, $DisplayNameOffset, 0, 1, 1)
          Values = [int[]]@($Script:NSIS_OPCODE_WRITE_REG, $HklmSignedValue, $KeyOffset, $DisplayNameOffset, -1, 1, 1)
        },
        [pscustomobject]@{
          Opcode = $Script:NSIS_OPCODE_WRITE_REG; RawOpcode = $Script:NSIS_OPCODE_WRITE_REG
          Raw = [uint32[]]@($Script:NSIS_OPCODE_WRITE_REG, $HklmRawValue, $KeyOffset, $PublisherOffset, 0, 1, 1)
          Values = [int[]]@($Script:NSIS_OPCODE_WRITE_REG, $HklmSignedValue, $KeyOffset, $PublisherOffset, -2, 1, 1)
        }
      )
      $State = [pscustomobject]@{
        Entries         = $Entries
        StringsBlock    = $StringBytes.ToArray()
        VersionInfo     = [pscustomobject]@{ Unicode = $true; IsV3 = $true; Type = 'NSIS3' }
        LanguageTable   = $null
        LanguageTables  = @(
          [pscustomobject]@{ LanguageId = [uint16]1033; StringOffsets = [int[]]@($EnglishNameOffset, $EnglishPublisherOffset) },
          [pscustomobject]@{ LanguageId = [uint16]2052; StringOffsets = [int[]]@($ChineseNameOffset, $ChinesePublisherOffset) }
        )
        Variables       = @{}
        ShellVarContext = 'HKLM'
      }

      Get-NSISAppsAndFeaturesEntryInfo -State $State
    }

    $Result.HasLocalizedEntries | Should -BeTrue
    @($Result.AppsAndFeaturesEntries).Count | Should -Be 2
    $Result.AppsAndFeaturesEntries.DisplayName | Should -Contain 'Tencent Meeting'
    $Result.AppsAndFeaturesEntries.DisplayName | Should -Contain '腾讯会议'
    $Result.AppsAndFeaturesEntries.Publisher | Should -Contain 'Tencent Technology (Shenzhen) Co. Ltd.'
    $Result.AppsAndFeaturesEntries.Publisher | Should -Contain '腾讯科技（深圳）有限公司'
    $Result.AppsAndFeaturesEntryEvidence.Locale | Should -Contain 'en-US'
    $Result.AppsAndFeaturesEntryEvidence.Locale | Should -Contain 'zh-CN'
    $Result.Notices | Should -HaveCount 1
    $Result.Notices[0] | Should -Match 'varies by installer language'
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

  It 'Should model the source-backed x64.nsh System plug-in architecture probes' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $Values = [ordered]@{}
      foreach ($Architecture in @('x86', 'x64', 'arm64')) {
        $State = [pscustomobject]@{
          TargetArchitecture = $Architecture
          Stack              = [System.Collections.Generic.List[string]]::new()
        }

        $State.Stack.Add('kernel32::GetCurrentProcess()p.s')
        $null = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Call'
        $State.Stack.Add('kernel32::IsWow64Process2(ps,*i0s,*i)')
        $null = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Call'
        $State.Stack.Add('|')
        $State.Stack.Add('kernel32::IsWow64Process(p-1,*i0s)')
        $null = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Call'
        $null = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Int64Op'
        $Values[$Architecture] = Pop-NSISStackValue -State $State
      }
      $Values
    }

    $Result.x86 | Should -Be '0'
    [int]$Result.x64 | Should -BeGreaterThan 0
    [int]$Result.arm64 | Should -BeGreaterThan 0
  }

  It 'Should model electron-builder System plug-in known-folder register outputs' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $State = [pscustomobject]@{
        Variables = @{}
        Stack     = [System.Collections.Generic.List[string]]::new()
        Metadata  = [ordered]@{ DefaultInstallLocation = $null }
      }

      # multiUser.nsh receives both SHGetKnownFolderPath outputs in direct NSIS
      # registers, then copies the returned pointer string into $0.
      $State.Stack.Add('SHELL32::SHGetKnownFolderPath(g "{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}", i 0, p 0, *p .r2)i.r1')
      $KnownFolderHandled = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Call'
      $State.Stack.Add('KERNEL32::lstrcpynW(w .r0, p r2, i 1024)')
      $CopyHandled = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Call'

      [pscustomobject]@{
        KnownFolderHandled = $KnownFolderHandled
        CopyHandled        = $CopyHandled
        Result             = $State.Variables[1]
        Pointer            = $State.Variables[2]
        Destination        = $State.Variables[0]
        StackCount         = $State.Stack.Count
      }
    }

    $ExpectedPath = Join-Path $env:LOCALAPPDATA 'Programs'
    $Result.KnownFolderHandled | Should -BeTrue
    $Result.CopyHandled | Should -BeTrue
    $Result.Result | Should -Be '0'
    $Result.Pointer | Should -Be $ExpectedPath
    $Result.Destination | Should -Be $ExpectedPath
    $Result.StackCount | Should -Be 0
  }

  It 'Should model the source-backed NSIS 3 GetKnownFolderPath opcode' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $FolderId = '{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}'
      $StringsBlock = [Text.Encoding]::ASCII.GetBytes("x`0$FolderId`0")
      $State = [pscustomobject]@{
        Variables     = @{}
        StringsBlock  = $StringsBlock
        LanguageTable = $null
        VersionInfo   = [pscustomobject]@{ Unicode = $false; IsV3 = $true; Type = 3 }
        Metadata      = [ordered]@{ DefaultInstallLocation = $null }
      }
      $Entry = [pscustomobject]@{
        Opcode = $Script:NSIS_OPCODE_GET_OS_INFO
        Raw    = [uint32[]](65, 0, 21, 2, 0, 0, 0)
        Values = [int[]](65, 0, 21, 2, 0, 0, 0)
      }

      $null = Invoke-NSISEntry -State $State -Entry $Entry
      $State.Variables[21]
    }

    $Result | Should -Be (Join-Path $env:LOCALAPPDATA 'Programs')
  }

  It 'Should resolve stable installer-related Windows known folders' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $WindowsDirectory = if ($env:windir) { $env:windir } else { 'C:\Windows' }
    $SystemDirectory = Join-Path $WindowsDirectory 'System32'
    $SystemX86Directory = if ([Environment]::Is64BitOperatingSystem) { Join-Path $WindowsDirectory 'SysWOW64' } else { $SystemDirectory }
    $ProgramFiles64 = if (${env:ProgramW6432}) { ${env:ProgramW6432} } else { $env:ProgramFiles }
    $ProgramFilesX86 = if (${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} } else { $ProgramFiles64 }
    $CommonProgramFiles64 = if (${env:CommonProgramW6432}) { ${env:CommonProgramW6432} } else { $env:CommonProgramFiles }
    $CommonProgramFilesX86 = if (${env:CommonProgramFiles(x86)}) { ${env:CommonProgramFiles(x86)} } else { $CommonProgramFiles64 }
    $UserStartMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu'
    $CommonStartMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu'
    $Cases = [ordered]@{
      '{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}' = $env:LOCALAPPDATA
      '{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}' = $env:APPDATA
      '{A520A1A4-1780-4FF6-BD18-167343C5AF16}' = Join-Path $env:USERPROFILE 'AppData\LocalLow'
      '{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}' = $env:ProgramData
      '{5E6C858F-0E22-4760-9AFE-EA3317B67173}' = $env:USERPROFILE
      '{F38BF404-1D43-42F2-9305-67DE0B28FC23}' = $WindowsDirectory
      '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}' = $SystemDirectory
      '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}' = $SystemX86Directory
      '{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}' = Join-Path $WindowsDirectory 'Fonts'
      '{905E63B6-C1BF-494E-B29C-65B732D3D21A}' = $ProgramFiles64
      '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}' = $ProgramFilesX86
      '{6D809377-6AF0-444B-8957-A3773F02200E}' = $ProgramFiles64
      '{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}' = $CommonProgramFiles64
      '{DE974D24-D9C6-4D3E-BF91-F4455120B917}' = $CommonProgramFilesX86
      '{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}' = $CommonProgramFiles64
      '{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}' = Join-Path $env:LOCALAPPDATA 'Programs'
      '{BCBD3057-CA5C-4622-B42D-BC56DB0AE516}' = Join-Path $env:LOCALAPPDATA 'Programs\Common'
      '{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}' = $UserStartMenu
      '{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}' = Join-Path $UserStartMenu 'Programs'
      '{B97D20BB-F46A-4C97-BA10-5E3608430854}' = Join-Path $UserStartMenu 'Programs\Startup'
      '{724EF170-A42D-4FEF-9F26-B60E846FBA4F}' = Join-Path $UserStartMenu 'Programs\Administrative Tools'
      '{A4115719-D62E-491D-AA7C-E74B8BE3B067}' = $CommonStartMenu
      '{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}' = Join-Path $CommonStartMenu 'Programs'
      '{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}' = Join-Path $CommonStartMenu 'Programs\Startup'
      '{D0384E7D-BAC3-4797-8F14-CBA229B392B5}' = Join-Path $CommonStartMenu 'Programs\Administrative Tools'
    }

    $Result = & $Module {
      param($Cases)
      $Resolved = [ordered]@{}
      foreach ($Case in $Cases.GetEnumerator()) {
        $Resolved[$Case.Key] = Resolve-NSISKnownFolderPath -FolderId $Case.Key.ToLowerInvariant().Trim('{', '}')
      }
      $Resolved['Unknown'] = Resolve-NSISKnownFolderPath -FolderId '{00000000-0000-0000-0000-000000000000}'
      $Resolved['Invalid'] = Resolve-NSISKnownFolderPath -FolderId 'not-a-guid'
      $Resolved
    } $Cases

    foreach ($Case in $Cases.GetEnumerator()) {
      $Result[$Case.Key] | Should -Be $Case.Value
    }
    $Result.Unknown | Should -BeNullOrEmpty
    $Result.Invalid | Should -BeNullOrEmpty
  }

  It 'Should normalize known-folder profile paths without retaining the host user name' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      [pscustomobject]@{
        Profile  = ConvertTo-NSISManifestPath -Path (Resolve-NSISKnownFolderPath '{5E6C858F-0E22-4760-9AFE-EA3317B67173}')
        LocalLow = ConvertTo-NSISManifestPath -Path (Resolve-NSISKnownFolderPath '{A520A1A4-1780-4FF6-BD18-167343C5AF16}')
      }
    }

    $Result.Profile | Should -Be '%UserProfile%'
    $Result.LocalLow | Should -Be '%UserProfile%\AppData\LocalLow'
  }

  It 'Should preserve temporary NSIS registers through source-backed System Store calls' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $State = [pscustomobject]@{
        Variables           = @{ 0 = 'original'; 11 = 'original-r1' }
        Stack               = [System.Collections.Generic.List[string]]::new()
        SystemVariableStack = [System.Collections.Generic.List[object]]::new()
      }

      $State.Stack.Add('S')
      $null = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Store'
      $State.Variables[0] = 'temporary'
      $State.Variables[11] = 'temporary-r1'
      $State.Stack.Add('L')
      $null = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Store'

      $State.Variables[2] = 'general-2'
      $State.Variables[12] = 'high-general-2'
      $State.Stack.Add('p2P2r3R3')
      $null = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Store'

      [pscustomobject]@{
        Register0        = $State.Variables[0]
        RegisterR1       = $State.Variables[11]
        GeneralRegister3 = $State.Variables[3]
        HighRegister3    = $State.Variables[13]
        PrivateStackSize = $State.SystemVariableStack.Count
        PublicStackSize  = $State.Stack.Count
      }
    }

    $Result.Register0 | Should -Be 'original'
    $Result.RegisterR1 | Should -Be 'original-r1'
    $Result.GeneralRegister3 | Should -Be 'high-general-2'
    $Result.HighRegister3 | Should -Be 'general-2'
    $Result.PrivateStackSize | Should -Be 0
    $Result.PublicStackSize | Should -Be 0
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
    $Info.IsPortable | Should -BeFalse
    $Info.PortableEvidence | Should -BeNullOrEmpty
    @($Info.AppsAndFeaturesEntries).Count | Should -Be 1
    $Info.HasLocalizedAppsAndFeaturesEntries | Should -BeFalse
    $Info.Notices | Should -BeNullOrEmpty
  }

  It 'Should resolve architecture-specific ARP identities from the BitComet installer' {
    $Fixture = Get-InstallerFixture -Name 'BitComet_2.21_setup.exe' -Url 'https://download.bitcomet.com/achive/BitComet_2.21_setup.exe' -Sha256 '2BB0AC769FE8B75B1B1B8CA42FA55D29D94AAF68480611538DBB4395D05082D2'

    $X86Info = Get-NSISInfo -Path $Fixture -Architecture x86
    $X64Info = Get-NSISInfo -Path $Fixture -Architecture x64

    $X86Info.ProductCode | Should -Be 'BitComet'
    $X86Info.DefaultInstallLocation | Should -Be '%ProgramFiles(x86)%\BitComet'
    $X86Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $X86Info.AppsAndFeaturesEntries.ProductCode | Should -Contain 'BitComet'

    $X64Info.ProductCode | Should -Be 'BitComet_x64'
    $X64Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\BitComet'
    $X64Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $X64Info.AppsAndFeaturesEntries.ProductCode | Should -Contain 'BitComet_x64'
  }

  It 'Should retain Yuanfudao ARP writes when resolving its x64 runtime branch' {
    $Fixture = Get-InstallerFixture -Name 'yuanfudao-student-7.27.0.22424-installer-x64.exe' `
      -Url 'https://apphub.fbcontent.cn/ape-gallery/app/yuanfudao-student-7.27.0.22424-installer-x64.exe' `
      -Sha256 '4ECC35BB89473DA3C4C227BF6B6480493A73CFC293ABF05BB4CE483EDC279B66'

    $Info = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope machine

    $Info.ProductCode | Should -Be 'tutor-electron-student'
    $Info.DisplayName | Should -Be '猿辅导'
    $Info.DisplayVersion | Should -Be '7.27.0.22424'
    $Info.Publisher | Should -Be '北京贞观雨科技有限公司'
    $Info.Scope | Should -Be 'machine'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.AppsAndFeaturesEntries.ProductCode | Should -Contain 'tutor-electron-student'
    @($Info.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be @('HKLM')
    $Info.Warnings | Should -BeNullOrEmpty
  }

  It 'Should select BeeDrive machine ARP writes when dormant user writes are also compiled' {
    $Fixture = Get-InstallerFixture -Name 'BeeDrive-2.0.3-20301-x64.exe' `
      -Url 'https://global.synologydownload.com/download/Utility/BeeDrive/2.0.3-20301/Windows/x86_64/BeeDrive-2.0.3-20301-x64.exe' `
      -Sha256 '253353785A303A704CDA2F4C906AFF1F0986BD5E6A84BCD788826477A41C7A0D'

    $Info = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope machine

    $Info.ProductCode | Should -Be '986aaad0-133f-5ad2-87e6-59ea820cbbad'
    $Info.DisplayName | Should -Be 'BeeDrive 2.0.3-20301'
    $Info.DisplayVersion | Should -Be '2.0.3-20301'
    $Info.Publisher | Should -Be 'Synology'
    $Info.Scope | Should -Be 'machine'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.AppsAndFeaturesEntries.ProductCode | Should -Contain '986aaad0-133f-5ad2-87e6-59ea820cbbad'
    @($Info.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be @('HKLM')
    $Info.Warnings | Should -BeNullOrEmpty
  }

  It 'Should resolve scope-specific ARP identities from the DBeaver installer' {
    $Fixture = Get-InstallerFixture -Name 'dbeaver-ce-26.1.3-windows-x86_64.exe' -Url 'https://github.com/dbeaver/dbeaver/releases/download/26.1.3/dbeaver-ce-26.1.3-windows-x86_64.exe' -Sha256 'DF3E522E3DBD4E6A7F91DCD8E422A0BE13220D2E895A681B5B6732ADB518297D'

    $UserInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope user
    $MachineInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope machine

    $UserInfo.HasScopeRuntimeCheck | Should -BeTrue
    $UserInfo.SupportedScopes | Should -Contain 'user'
    $UserInfo.SupportedScopes | Should -Contain 'machine'
    $UserInfo.ProductCode | Should -Be 'DBeaver (current user)'
    $UserInfo.DisplayName | Should -Be 'DBeaver 26.1.3 (current user)'
    $UserInfo.Scope | Should -Be 'user'
    $UserInfo.DefaultInstallLocation | Should -Be '%LocalAppData%\DBeaver'
    $UserInfo.AppsAndFeaturesEntries.ProductCode | Should -Contain 'DBeaver (current user)'

    $MachineInfo.ProductCode | Should -Be 'DBeaver'
    $MachineInfo.DisplayName | Should -Be 'DBeaver 26.1.3'
    $MachineInfo.Scope | Should -Be 'machine'
    $MachineInfo.DefaultInstallLocation | Should -Be '%ProgramFiles%\DBeaver'
    $MachineInfo.AppsAndFeaturesEntries.ProductCode | Should -Contain 'DBeaver'
    $MachineInfo.Warnings | Should -BeNullOrEmpty
  }

  It 'Should resolve both current electron-builder scopes from the WorkBuddy installer' {
    $Fixture = Get-InstallerFixture -Name 'WorkBuddy-win32-x64-user-5.3.5.34189228-8044e898.exe' -Url 'https://download.codebuddy.cn/workbuddy/saas/win32-x64-user/WorkBuddy-win32-x64-user-5.3.5.34189228-8044e898.exe' -Sha256 '3064D6E873BD74169E62EA2E480382C120125E6B8F99155649EC2389C3CBFAFF'

    $UserInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope user
    $MachineInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope machine

    $UserInfo.SupportedScopes | Should -Contain 'user'
    $UserInfo.SupportedScopes | Should -Contain 'machine'
    $UserInfo.ProductCode | Should -Be 'BFD312E9-1019-4F57-9F44-F86246833B50'
    $UserInfo.Scope | Should -Be 'user'
    $UserInfo.DefaultInstallLocation | Should -Be '%LocalAppData%\Programs\WorkBuddy'
    $UserInfo.UninstallString | Should -Be ('"{0}\Programs\WorkBuddy\Uninstall WorkBuddy.exe" /currentuser' -f $env:LOCALAPPDATA)
    @($UserInfo.RegistryWrites | Where-Object IsUninstallKey).Root | Should -Contain 'HKCU'
    $UserInfo.Warnings | Should -BeNullOrEmpty

    $MachineInfo.ProductCode | Should -Be 'BFD312E9-1019-4F57-9F44-F86246833B50'
    $MachineInfo.Scope | Should -Be 'machine'
    $MachineInfo.DefaultInstallLocation | Should -Be '%ProgramFiles%\WorkBuddy'
    $MachineInfo.UninstallString | Should -Be ('"{0}\WorkBuddy\Uninstall WorkBuddy.exe" /allusers' -f $env:ProgramFiles)
    @($MachineInfo.RegistryWrites | Where-Object IsUninstallKey).Root | Should -Contain 'HKLM'
    $MachineInfo.Warnings | Should -BeNullOrEmpty
  }

  It 'Should recover one explicit scoped ARP identity after custom AionUi hooks stop section simulation' {
    $Fixture = Get-InstallerFixture -Name 'AionUi-2.1.42-win-x64.exe' -Url 'https://github.com/iOfficeAI/AionUi/releases/download/v2.1.42/AionUi-2.1.42-win-x64.exe'

    $UserInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope user
    $MachineInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope machine

    foreach ($Info in @($UserInfo, $MachineInfo)) {
      $Info.ProductCode | Should -Be 'f3bfde38-8429-545c-a4e9-a078d87dee6c'
      $Info.DisplayName | Should -Be 'AionUi'
      $Info.DisplayVersion | Should -Be '2.1.42'
      $Info.Publisher | Should -Be 'AionUi'
      $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
      $Info.AppsAndFeaturesEntries.ProductCode | Should -Contain 'f3bfde38-8429-545c-a4e9-a078d87dee6c'
      $Info.UninstallString | Should -BeNullOrEmpty
      $Info.QuietUninstallString | Should -BeNullOrEmpty
      $Info.UnresolvedFields | Should -Contain 'UninstallString'
      $Info.UnresolvedFields | Should -Contain 'QuietUninstallString'
      $Info.Warnings | Should -BeNullOrEmpty
    }

    $UserInfo.Scope | Should -Be 'user'
    $UserInfo.DefaultInstallLocation | Should -Be '%LocalAppData%\Programs\AionUi'
    @($UserInfo.RegistryWrites | Where-Object IsUninstallKey).Count | Should -BeGreaterThan 0
    @($UserInfo.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be @('HKCU')

    $MachineInfo.Scope | Should -Be 'machine'
    $MachineInfo.DefaultInstallLocation | Should -Be '%ProgramFiles%\AionUi'
    @($MachineInfo.RegistryWrites | Where-Object IsUninstallKey).Count | Should -BeGreaterThan 0
    @($MachineInfo.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be @('HKLM')
  }

  It 'Should retain the selected RivonClaw scope after later sections change ambient shell context' {
    $Fixture = Get-InstallerFixture -Name 'TK-Copilot.Setup.1.8.82.exe' -Url 'https://github.com/gaoyangz77/rivonclaw/releases/download/v1.8.82/TK-Copilot.Setup.1.8.82.exe' -Sha256 '02AD6F71BCE64307EB3EBAE25041503D690E0C64FFAD4D209BF791B91A684824'

    $UserInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope user
    $MachineInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope machine

    foreach ($Info in @($UserInfo, $MachineInfo)) {
      $Info.ProductCode | Should -Be '51492edb-6d67-582c-a781-6b48bbf5f3bf'
      $Info.DisplayName | Should -Be 'TK Copilot'
      $Info.DisplayVersion | Should -Be '1.8.82'
      $Info.SupportedScopes | Should -Contain 'user'
      $Info.SupportedScopes | Should -Contain 'machine'
      $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
      $Info.Warnings | Should -BeNullOrEmpty
    }

    $UserInfo.Scope | Should -Be 'user'
    $UserInfo.DefaultInstallLocation | Should -Be '%LocalAppData%\Programs\TK Copilot'
    @($UserInfo.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be @('HKCU')

    $MachineInfo.Scope | Should -Be 'machine'
    $MachineInfo.DefaultInstallLocation | Should -Be '%ProgramFiles%\TK Copilot'
    @($MachineInfo.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be @('HKLM')
  }

  It 'Should identify the three standard Tauri NSIS install modes from compiled evidence' {
    $Readest = Get-InstallerFixture -Name 'Readest_0.11.20_x64-setup.exe' -Url 'https://github.com/readest/readest/releases/download/v0.11.20/Readest_0.11.20_x64-setup.exe' -Sha256 'DF8C9E2763CC9EC3E453CCE6320DF442798D115F9127C0C6BA831B800CBDB7DD'
    $Yaak = Get-InstallerFixture -Name 'Yaak_2026.4.0_x64-setup.exe' -Url 'https://github.com/mountain-loop/yaak/releases/download/v2026.4.0/Yaak_2026.4.0_x64-setup.exe' -Sha256 '026DC0753F4880313B93BBFF848A9CD09A114F87111AAAEF5E4E698C52C8B561'
    $ClashVerge = Get-InstallerFixture -Name 'Clash.Verge_2.5.2_x64-setup.exe' -Url 'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v2.5.2/Clash.Verge_2.5.2_x64-setup.exe' -Sha256 'BA42F00B1082E352352080170FE86AE411BCC854CB13F1B8BEBC9025E8A7CBF4'

    $BothInfo = Get-NSISInfo -Path $Readest -Scope user
    $UserInfo = Get-NSISInfo -Path $Yaak
    $MachineInfo = Get-NSISInfo -Path $ClashVerge

    $BothInfo.IsTauri | Should -BeTrue
    $BothInfo.TauriInstallerMode | Should -Be 'both'
    $BothInfo.RequestedExecutionLevel | Should -Be 'highestAvailable'
    $BothInfo.SupportedScopes | Should -Be @('user', 'machine')
    $BothInfo.Scope | Should -Be 'user'
    $BothInfo.DefaultInstallLocation | Should -Be '%LocalAppData%\Programs\Readest'

    $UserInfo.IsTauri | Should -BeTrue
    $UserInfo.TauriInstallerMode | Should -Be 'currentUser'
    $UserInfo.RequestedExecutionLevel | Should -Be 'asInvoker'
    $UserInfo.SupportedScopes | Should -Be @('user')
    $UserInfo.DefaultInstallLocation | Should -Be '%LocalAppData%\Yaak'

    $MachineInfo.IsTauri | Should -BeTrue
    $MachineInfo.TauriInstallerMode | Should -Be 'perMachine'
    $MachineInfo.RequestedExecutionLevel | Should -Be 'requireAdministrator'
    $MachineInfo.SupportedScopes | Should -Be @('machine')
    $MachineInfo.DefaultInstallLocation | Should -Be '%ProgramFiles%\Clash Verge'
  }

  It 'Should classify standard Tauri command-line switches by purpose' {
    $Fixture = Get-InstallerFixture -Name 'Yaak_2026.4.0_x64-setup.exe' -Url 'https://github.com/mountain-loop/yaak/releases/download/v2026.4.0/Yaak_2026.4.0_x64-setup.exe' -Sha256 '026DC0753F4880313B93BBFF848A9CD09A114F87111AAAEF5E4E698C52C8B561'
    $Info = Get-NSISInstallerSwitchInfo -Path $Fixture

    $Info.IsTauri | Should -BeTrue
    $Info.TauriInstallerMode | Should -Be 'currentUser'
    $Info.TauriSwitches.Switch | Should -Contain '/P'
    $Info.TauriSwitches.Switch | Should -Contain '/NS'
    $Info.TauriSwitches.Switch | Should -Contain '/UPDATE'
    $Info.TauriSwitches.Switch | Should -Contain '/R'
    $Info.TauriSwitches.Switch | Should -Contain '/ARGS'
    ($Info.TauriSwitches | Where-Object Switch -EQ '/P').Purpose | Should -Be 'Passive installation with progress'
    ($Info.TauriSwitches | Where-Object Switch -EQ '/R').Purpose | Should -Be 'Run the application after silent or passive installation'
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

  It 'Should detect the electron-builder Bitwarden portable launcher' {
    $Fixture = Get-InstallerFixture `
      -Name 'Bitwarden-Portable-2026.6.1.exe' `
      -Url 'https://github.com/bitwarden/clients/releases/download/desktop-v2026.6.1/Bitwarden-Portable-2026.6.1.exe' `
      -Sha256 'ECE0E69AE6907564364A8E4B99FB8CB95BE23DC418201871CFA69B11967DAC53'
    $Info = Get-NSISInfo -Path $Fixture
    $ElectronBuilderInfo = Get-ElectronBuilderNSISInfo -Path $Fixture

    $Info.IsPortable | Should -BeTrue
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
    $Info.DefaultInstallLocation | Should -BeNullOrEmpty
    $Info.PortableEvidence | Should -Contain 'EnvironmentVariable:PORTABLE_EXECUTABLE_DIR'
    $Info.PortableEvidence | Should -Contain 'EnvironmentVariable:PORTABLE_EXECUTABLE_FILE'
    $Info.PortableEvidence | Should -Contain 'EnvironmentVariable:PORTABLE_EXECUTABLE_APP_FILENAME'
    $Info.PortableEvidence | Should -Contain 'NoAppsAndFeaturesEntry'
    $Info.Warnings | Should -HaveCount 1
    $Info.Warnings[0] | Should -Match 'portable launcher'
    $ElectronBuilderInfo.IsElectronBuilder | Should -BeTrue
    $ElectronBuilderInfo.IsPortable | Should -BeTrue
    $ElectronBuilderInfo.Evidence.PortableEvidence | Should -Contain 'NoAppsAndFeaturesEntry'
  }

  It 'Should repair Tencent Meeting paths after its custom directory page' {
    $Fixture = Get-InstallerFixture `
      -Name 'TencentMeeting_0300000000_3.44.10.457_x86_64.publish.exe' `
      -Url 'https://updatecdn.meeting.qq.com/cos/a2bf9c01f76b1df44383ab2f529bec13/TencentMeeting_0300000000_3.44.10.457_x86_64.publish.exe' `
      -Sha256 '91C02F0877B83052B4D2C0C20736ED1CA6DBC64F5FB09DA3911A5DE91A51BD93'
    $Info = Get-NSISInfo -Path $Fixture -Architecture x64
    $InstallRoot = Join-Path $env:ProgramFiles 'Tencent\WeMeet'

    $Info.ProductCode | Should -Be 'WeMeet'
    $Info.DisplayName | Should -Be 'Tencent Meeting'
    $Info.DisplayVersion | Should -Be '3.44.10.457'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\Tencent\WeMeet\3.44.10.457'
    $Info.UninstallString | Should -Be "`"$InstallRoot\3.44.10.457\WeMeetUninstall.exe`""
    $Info.DisplayIcon | Should -Be "`"$InstallRoot\WeMeetApp.exe`""
    $Info.Scope | Should -Be 'machine'
    $Info.Warnings | Should -BeNullOrEmpty
  }

  It 'Should resolve GoTo electron-builder uninstall commands from StrCpy assignments' {
    $Fixture = Get-InstallerFixture `
      -Name 'GoToSetup-4.19.1.exe' `
      -Url 'https://goto-desktop.goto.com/GoToSetup-4.19.1.exe' `
      -Sha256 '6EF77AB5904A7FEDDA696F54AA346BDE535537D85D9F09DC8A6C321CEE1BDF41'
    $Info = Get-NSISInfo -Path $Fixture
    $InstallRoot = Join-Path $env:LOCALAPPDATA 'Programs\goto'

    $Info.ProductCode | Should -Be 'b5746384-3503-4fbf-824a-0a42d1bd0639'
    $Info.DisplayName | Should -Be 'GoTo 4.19.1'
    $Info.DisplayVersion | Should -Be '4.19.1'
    $Info.DefaultInstallLocation | Should -Be '%LocalAppData%\Programs\goto'
    $Info.UninstallString | Should -Be "`"$InstallRoot\Uninstall GoTo.exe`" /currentuser"
    $Info.QuietUninstallString | Should -Be "`"$InstallRoot\Uninstall GoTo.exe`" /currentuser /S"
    $Info.DisplayIcon | Should -Be "$InstallRoot\GoTo.exe,0"
    $Info.Scope | Should -Be 'user'
    $Info.Warnings | Should -BeNullOrEmpty
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

