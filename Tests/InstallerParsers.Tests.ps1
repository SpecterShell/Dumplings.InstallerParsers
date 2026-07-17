BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Compression.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'PE.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'RegistryAssociations.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'NSIS.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Inno.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'QtInstallerFramework.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'InstallerParsers\Main'

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url,

      [switch]$UseSourceForgeMetaRefresh
    )

    Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name $Name -Uri $Url -UseSourceForgeMetaRefresh:$UseSourceForgeMetaRefresh
  }

  function Add-TestUInt16BE {
    param([System.Collections.Generic.List[byte]]$Bytes, [uint16]$Value)

    $Bytes.Add([byte](($Value -shr 8) -band 0xff))
    $Bytes.Add([byte]($Value -band 0xff))
  }

  function Add-TestUInt32BE {
    param([System.Collections.Generic.List[byte]]$Bytes, [uint32]$Value)

    $Bytes.Add([byte](($Value -shr 24) -band 0xff))
    $Bytes.Add([byte](($Value -shr 16) -band 0xff))
    $Bytes.Add([byte](($Value -shr 8) -band 0xff))
    $Bytes.Add([byte]($Value -band 0xff))
  }

  function Add-TestInt64LE {
    param([System.Collections.Generic.List[byte]]$Bytes, [int64]$Value)

    $Bytes.AddRange([System.BitConverter]::GetBytes($Value))
  }

  function Add-TestQtRccName {
    param(
      [System.Collections.Generic.List[byte]]$Bytes,
      [string]$Name
    )

    $Offset = $Bytes.Count
    Add-TestUInt16BE -Bytes $Bytes -Value ([uint16]$Name.Length)
    Add-TestUInt32BE -Bytes $Bytes -Value 0
    $Bytes.AddRange([System.Text.Encoding]::BigEndianUnicode.GetBytes($Name))
    return $Offset
  }

  function New-TestQtRccResource {
    param([string]$InstallerXml)

    $Payload = [System.Text.Encoding]::UTF8.GetBytes($InstallerXml)
    $DataBlob = [System.Collections.Generic.List[byte]]::new()
    Add-TestUInt32BE -Bytes $DataBlob -Value ([uint32]$Payload.Length)
    $DataBlob.AddRange($Payload)

    $NameTable = [System.Collections.Generic.List[byte]]::new()
    $InstallerConfigNameOffset = Add-TestQtRccName -Bytes $NameTable -Name 'installer-config'
    $ConfigNameOffset = Add-TestQtRccName -Bytes $NameTable -Name 'config.xml'

    $DataOffset = 20
    $NamesOffset = $DataOffset + $DataBlob.Count
    $TreeOffset = $NamesOffset + $NameTable.Count
    $Rcc = [System.Collections.Generic.List[byte]]::new()
    $Rcc.AddRange([System.Text.Encoding]::ASCII.GetBytes('qres'))
    Add-TestUInt32BE -Bytes $Rcc -Value 1
    Add-TestUInt32BE -Bytes $Rcc -Value ([uint32]$TreeOffset)
    Add-TestUInt32BE -Bytes $Rcc -Value ([uint32]$DataOffset)
    Add-TestUInt32BE -Bytes $Rcc -Value ([uint32]$NamesOffset)
    $Rcc.AddRange($DataBlob.ToArray())
    $Rcc.AddRange($NameTable.ToArray())

    Add-TestUInt32BE -Bytes $Rcc -Value 0
    Add-TestUInt16BE -Bytes $Rcc -Value 2
    Add-TestUInt32BE -Bytes $Rcc -Value 1
    Add-TestUInt32BE -Bytes $Rcc -Value 1

    Add-TestUInt32BE -Bytes $Rcc -Value ([uint32]$InstallerConfigNameOffset)
    Add-TestUInt16BE -Bytes $Rcc -Value 2
    Add-TestUInt32BE -Bytes $Rcc -Value 1
    Add-TestUInt32BE -Bytes $Rcc -Value 2

    Add-TestUInt32BE -Bytes $Rcc -Value ([uint32]$ConfigNameOffset)
    Add-TestUInt16BE -Bytes $Rcc -Value 0
    Add-TestUInt16BE -Bytes $Rcc -Value 0
    Add-TestUInt16BE -Bytes $Rcc -Value 1
    Add-TestUInt32BE -Bytes $Rcc -Value 0

    return , $Rcc.ToArray()
  }

  function New-TestQtInstallerFrameworkFixture {
    param(
      [string]$Name,
      [string]$InstallerXml,
      [switch]$GuiOnly
    )

    $FixturePath = Join-Path $Script:FixtureDirectory $Name
    $Bytes = [System.Collections.Generic.List[byte]]::new()
    $Bytes.AddRange([byte[]](0x4d, 0x5a))
    if (-not $GuiOnly) {
      $Bytes.AddRange([System.Text.Encoding]::ASCII.GetBytes("accept-licenses`0default-answer`0confirm-command`0check-updates`0create-offline`0clear-cache`0"))
    }
    while ($Bytes.Count -lt 512) { $Bytes.Add(0) }

    $EndOfExecutable = $Bytes.Count
    $MetaStart = $Bytes.Count
    $MetaBytes = [byte[]](New-TestQtRccResource -InstallerXml $InstallerXml)
    $Bytes.AddRange([byte[]]$MetaBytes)

    $OperationsStart = $Bytes.Count
    Add-TestInt64LE -Bytes $Bytes -Value 0
    Add-TestInt64LE -Bytes $Bytes -Value 0
    $OperationsLength = $Bytes.Count - $OperationsStart

    Add-TestInt64LE -Bytes $Bytes -Value 0
    $CollectionIndexStart = $Bytes.Count
    Add-TestInt64LE -Bytes $Bytes -Value 0
    Add-TestInt64LE -Bytes $Bytes -Value 0
    $CollectionIndexLength = $Bytes.Count - $CollectionIndexStart

    Add-TestInt64LE -Bytes $Bytes -Value ($CollectionIndexStart - $EndOfExecutable)
    Add-TestInt64LE -Bytes $Bytes -Value $CollectionIndexLength
    Add-TestInt64LE -Bytes $Bytes -Value ($MetaStart - $EndOfExecutable)
    Add-TestInt64LE -Bytes $Bytes -Value $MetaBytes.Length
    Add-TestInt64LE -Bytes $Bytes -Value ($OperationsStart - $EndOfExecutable)
    Add-TestInt64LE -Bytes $Bytes -Value $OperationsLength
    Add-TestInt64LE -Bytes $Bytes -Value 1

    $BinaryContentSize = ($Bytes.Count + 24) - $EndOfExecutable
    Add-TestInt64LE -Bytes $Bytes -Value $BinaryContentSize
    Add-TestInt64LE -Bytes $Bytes -Value 0x12023233
    $Bytes.AddRange([byte[]](0xf8, 0x68, 0xd6, 0x99, 0x1c, 0x0a, 0x63, 0xc2))

    [System.IO.File]::WriteAllBytes($FixturePath, $Bytes.ToArray())
    return $FixturePath
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
          DisplayVersion         = $null
          DisplayName            = $null
          Publisher              = $null
          ProductCode            = $null
          DefaultInstallLocation = $null
          UninstallString        = $null
          QuietUninstallString   = $null
          DisplayIcon            = $null
          SystemComponent        = $null
          Scope                  = $null
          WritesAppsAndFeaturesEntry = $false
          RegistryValues         = @{}
          RegistryWrites         = @()
          ExtractedFiles         = @()
          ExecutedPayloads       = @()
          Warnings               = @()
          ParserVersionInfo      = $null
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
        Entries = @([pscustomobject]@{
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
          DisplayVersion         = $null
          DisplayName            = $null
          Publisher              = $null
          ProductCode            = $null
          DefaultInstallLocation = $null
          UninstallString        = $null
          QuietUninstallString   = $null
          DisplayIcon            = $null
          SystemComponent        = $null
          Scope                  = $null
          WritesAppsAndFeaturesEntry = $false
          RegistryValues         = @{}
          RegistryWrites         = @()
          ExtractedFiles         = @()
          ExecutedPayloads       = @()
          Warnings               = @()
          ParserVersionInfo      = $null
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
          DisplayVersion         = $null
          DisplayName            = $null
          Publisher              = $null
          ProductCode            = $null
          DefaultInstallLocation = $null
          UninstallString        = $null
          QuietUninstallString   = $null
          DisplayIcon            = $null
          SystemComponent        = $null
          Scope                  = $null
          WritesAppsAndFeaturesEntry = $false
          RegistryValues         = @{}
          RegistryWrites         = @()
          ExtractedFiles         = @()
          ExecutedPayloads       = @()
          Warnings               = @()
          ParserVersionInfo      = $null
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
        LogOpcode       = Get-NSISNormalizedOpcode -Opcode $Script:NSIS_OPCODE_SECTION_SET -Type 'NSIS3' -Unicode $true -LogCmdIsEnabled $true
        ShiftedSection  = Get-NSISNormalizedOpcode -Opcode ($Script:NSIS_OPCODE_SECTION_SET + 1) -Type 'NSIS3' -Unicode $true -LogCmdIsEnabled $true
        ParkFileWrite   = Get-NSISNormalizedOpcode -Opcode $Script:NSIS_OPCODE_FILE_SEEK -Type 'Park1' -Unicode $true -LogCmdIsEnabled $false
        RegEnum         = Get-NSISNormalizedOpcode -Opcode 53 -Type 'NSIS3' -Unicode $true -LogCmdIsEnabled $false
        NsisBiWriteReg  = ConvertFrom-NSISBiOpcode -Opcode 53
      }
    }

    $Result.LogOpcode | Should -Be 70
    $Result.ShiftedSection | Should -Be 63
    $Result.ParkFileWrite | Should -Be 68
    $Result.RegEnum | Should -Be 53
    $Result.NsisBiWriteReg | Should -Be 51
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
}

Describe 'Qt Installer Framework parser' {
  It 'Should read static metadata from IFW binary-content resources' {
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw.exe' -InstallerXml @'
<Installer>
  <Name>Example.QtIFW</Name>
  <Version>1.2.3</Version>
  <Title>Example Qt IFW</Title>
  <Publisher>Example Publisher</Publisher>
  <ProductUrl>https://example.invalid</ProductUrl>
  <TargetDir>@ApplicationsDir@/Example</TargetDir>
  <StartMenuDir>Example</StartMenuDir>
  <MaintenanceToolName>example-maintenance</MaintenanceToolName>
  <ProductUUID>{11111111-2222-3333-4444-555555555555}</ProductUUID>
</Installer>
'@

    $Info = Get-QtInstallerFrameworkInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Qt Installer Framework'
    $Info.BinaryMarker | Should -Be 'Installer'
    $Info.PackageName | Should -Be 'Example.QtIFW'
    $Info.DisplayVersion | Should -Be '1.2.3'
    $Info.Publisher | Should -Be 'Example Publisher'
    $Info.ProductCode | Should -Be '{11111111-2222-3333-4444-555555555555}'
    $Info.MaintenanceToolName | Should -Be 'example-maintenance'
    $Info.InstallerConfigSource | Should -Be ':/installer-config/config.xml'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.InterfaceVariant | Should -Be 'CLI'
    $Info.CommandLineInterface | Should -Be 'Enabled'
    $Info.SupportsSilentInstallation | Should -BeTrue
    $Info.RequiresExplicitInstallLocation | Should -BeFalse
    $Info.InstallLocationSwitch | Should -Be '--root "<INSTALLPATH>"'
    $Info.SupportsExistingInstallationOverride | Should -BeFalse
    $Info.ExistingInstallationMarker | Should -Be '@ApplicationsDir@/Example\example-maintenance.exe'
    $Info.RecommendedUpgradeBehavior | Should -Be 'uninstallPrevious'
    $Info.Scope | Should -Be 'user'
    $Info.DefaultScope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.UserScopeSwitch | Should -Be 'AllUsers=false'
    $Info.MachineScopeSwitch | Should -Be 'AllUsers=true'
    Read-ScopeFromQtInstallerFramework -Path $Fixture | Should -Be 'user'
    Read-SupportedScopesFromQtInstallerFramework -Path $Fixture | Should -Be @('user', 'machine')
    Test-QtInstallerFrameworkDualScope -Path $Fixture | Should -BeTrue
    Test-QtInstallerFrameworkCLI -Path $Fixture | Should -BeTrue
    Test-QtInstallerFrameworkSilentInstallation -Path $Fixture | Should -BeTrue
    Test-QtInstallerFrameworkRequiresInstallLocation -Path $Fixture | Should -BeFalse
    Test-QtInstallerFrameworkSupportsExistingInstallationOverride -Path $Fixture | Should -BeFalse
    Read-UpgradeBehaviorFromQtInstallerFramework -Path $Fixture | Should -Be 'uninstallPrevious'
  }

  It 'Should warn when IFW ProductUUID is generated at install time' {
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-random-productuuid.exe' -InstallerXml @'
<Installer>
  <Name>Example.RandomCode</Name>
  <Version>4.5.6</Version>
  <Publisher>Example Publisher</Publisher>
</Installer>
'@

    $Info = Get-QtInstallerFrameworkInfo -Path $Fixture

    $Info.PackageName | Should -Be 'Example.RandomCode'
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.RequiresExplicitInstallLocation | Should -BeTrue
    $Info.Warnings | Should -Contain 'No embedded ProductUUID was found. Qt IFW generates the Windows uninstall key at install time unless a script/config sets ProductUUID.'
    $Info.Warnings | Should -Contain 'The embedded TargetDir is empty, so command-line installation requires --root with an absolute installation path.'
    { Read-ProductCodeFromQtInstallerFramework -Path $Fixture } | Should -Throw
  }

  It 'Should not recommend command-line scope overrides when IFW disables CLI support' {
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-disable-cli.exe' -InstallerXml @'
<Installer>
  <Name>Example.NoCli</Name>
  <Version>1.0.0</Version>
  <Publisher>Example Publisher</Publisher>
  <DisableCommandLineInterface>true</DisableCommandLineInterface>
</Installer>
'@

    $Info = Get-QtInstallerFrameworkInfo -Path $Fixture

    $Info.Scope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user')
    $Info.SupportsDualScope | Should -BeFalse
    $Info.SupportsCommandLineScopeOverride | Should -BeFalse
    $Info.InterfaceVariant | Should -Be 'CLI'
    $Info.CommandLineInterface | Should -Be 'Disabled'
    $Info.SupportsSilentInstallation | Should -BeFalse
    $Info.UserScopeSwitch | Should -BeNullOrEmpty
    $Info.MachineScopeSwitch | Should -BeNullOrEmpty
    $Info.Warnings | Should -Contain 'The embedded IFW config disables the command-line interface, so silent installation and AllUsers scope overrides are unavailable.'
  }

  It 'Should identify the Qt Linguist installer as GUI-only' {
    $Fixture = Get-InstallerFixture -Name 'qtlinguistinstaller-5.12.2.exe' -Url 'https://download.qt.io/linguist_releases/qtlinguistinstaller-5.12.2.exe'
    $Info = Get-QtInstallerFrameworkInfo -Path $Fixture

    $Info.PackageName | Should -Be 'Qt Linguist'
    $Info.InterfaceVariant | Should -Be 'GUI'
    $Info.PESubsystem.Name | Should -Be 'WindowsGui'
    $Info.CommandLineInterface | Should -Be 'Unavailable'
    $Info.SupportsSilentInstallation | Should -BeFalse
    $Info.RequiresExplicitInstallLocation | Should -BeNullOrEmpty
    $Info.SupportedScopes | Should -Be @('user')
    $Info.SupportsDualScope | Should -BeFalse
    $Info.UserScopeSwitch | Should -BeNullOrEmpty
    $Info.MachineScopeSwitch | Should -BeNullOrEmpty
    $Info.Warnings | Should -Contain 'The Qt IFW launcher does not contain the modern command-line interface; GUI-only installers do not support WinGet-compatible silent installation.'
    Test-QtInstallerFrameworkCLI -Path $Fixture | Should -BeFalse
    Test-QtInstallerFrameworkSilentInstallation -Path $Fixture | Should -BeFalse
  }

  It 'Should identify the current MSYS2 installer as CLI-capable' {
    $Fixture = Get-InstallerFixture -Name 'msys2-x86_64-latest.exe' -Url 'https://github.com/msys2/msys2-installer/releases/download/nightly-x86_64/msys2-x86_64-latest.exe'
    $Info = Get-QtInstallerFrameworkInfo -Path $Fixture

    $Info.PackageName | Should -Be 'MSYS2'
    $Info.InterfaceVariant | Should -Be 'CLI'
    $Info.PESubsystem.Name | Should -Be 'WindowsCui'
    $Info.CommandLineInterface | Should -Be 'Enabled'
    $Info.SupportsSilentInstallation | Should -BeTrue
    $Info.RequiresExplicitInstallLocation | Should -BeTrue
    $Info.SupportsExistingInstallationOverride | Should -BeFalse
    $Info.RecommendedUpgradeBehavior | Should -Be 'uninstallPrevious'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.CommandLineInterfaceEvidence.FoundMarkers | Should -Contain 'accept-licenses'
    $Info.CommandLineInterfaceEvidence.FoundMarkers | Should -Contain 'check-updates'
    Test-QtInstallerFrameworkRequiresInstallLocation -Path $Fixture | Should -BeTrue
    Test-QtInstallerFrameworkSupportsExistingInstallationOverride -Path $Fixture | Should -BeFalse
  }

  It 'Should use the embedded target directory of a CLI-capable reMarkable installer' {
    $Fixture = Get-InstallerFixture -Name 'reMarkable-3.8.0.810-win64-LDv4m9Vntg.exe' -Url 'https://downloads.remarkable.com/desktop/production/win/reMarkable-3.8.0.810-win64-LDv4m9Vntg.exe'
    $Info = Get-QtInstallerFrameworkInfo -Path $Fixture

    $Info.PackageName | Should -Be 'reMarkable'
    $Info.PESubsystem.Name | Should -Be 'WindowsCui'
    $Info.InterfaceVariant | Should -Be 'CLI'
    $Info.SupportsSilentInstallation | Should -BeTrue
    $Info.TargetDir | Should -Be '@ApplicationsDirX64@/reMarkable'
    $Info.HasDefaultTargetDir | Should -BeTrue
    $Info.RequiresExplicitInstallLocation | Should -BeFalse
    Test-QtInstallerFrameworkRequiresInstallLocation -Path $Fixture | Should -BeFalse
  }

  It 'Should expand files from embedded IFW metadata resources' {
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-expand.exe' -InstallerXml @'
<Installer>
  <Name>Example.Expand</Name>
  <Version>1.0.0</Version>
  <Publisher>Example Publisher</Publisher>
</Installer>
'@
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'synthetic-ifw-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Result = Expand-QtInstallerFramework -Path $Fixture -DestinationPath $ExpandedPath -Name 'config.xml'
      $ConfigPath = Join-Path $Result 'installer-config\config.xml'

      $ConfigPath | Should -Exist
      (Get-Content -LiteralPath $ConfigPath -Raw) | Should -BeLike '*<Name>Example.Expand</Name>*'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should reject an IFW resource path that escapes the destination' {
    $Module = Get-Module QtInstallerFramework | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    {
      & $Module {
        Resolve-QtInstallerFrameworkExtractionPath -DestinationPath $env:TEMP -RelativePath '..\escape.exe'
      }
    } | Should -Throw '*escapes the destination*'
  }

  It 'Should selectively expand a file from a real IFW package archive' {
    $Fixture = Get-InstallerFixture -Name 'msys2-x86_64-latest.exe' -Url 'https://github.com/msys2/msys2-installer/releases/download/nightly-x86_64/msys2-x86_64-latest.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'msys2-ifw-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Result = Expand-QtInstallerFramework -Path $Fixture -DestinationPath $ExpandedPath -Name 'msys-2.0.dll'
      $ExtractedFiles = @(Get-ChildItem -Path $Result -Recurse -File)

      $ExtractedFiles | Should -HaveCount 1
      $ExtractedFiles[0].Name | Should -Be 'msys-2.0.dll'
      $ExtractedFiles[0].Length | Should -BeGreaterThan 0
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should reject an IFW package resource above the configured output limit' {
    $Fixture = Get-InstallerFixture -Name 'msys2-x86_64-latest.exe' -Url 'https://github.com/msys2/msys2-installer/releases/download/nightly-x86_64/msys2-x86_64-latest.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'msys2-ifw-limited'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      { Expand-QtInstallerFramework -Path $Fixture -DestinationPath $ExpandedPath -Name 'msys-2.0.dll' -MaximumExpandedBytes 1048576 } | Should -Throw '*exceeds the 1048576-byte limit*'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}

Describe 'Inno parser' {
  It 'Should read static metadata from the WinSCP installer' {
    $Fixture = Get-InstallerFixture -Name 'winscp-6.5.6-setup.exe' -Url 'https://sourceforge.net/projects/winscp/files/WinSCP/6.5.6/WinSCP-6.5.6-Setup.exe/download' -UseSourceForgeMetaRefresh
    $Info = Get-InnoInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Inno'
    $Info.DisplayName | Should -Be 'WinSCP 6.5.6'
    $Info.DisplayVersion | Should -Be '6.5.6'
    $Info.ProductCode | Should -Be 'winscp3'
    $Info.PrivilegesRequired | Should -Be 'admin'
    $Info.PrivilegesRequiredOverridesAllowed | Should -Be @('commandline', 'dialog')
    $Info.DefaultScope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.EffectiveArchitecturesAllowed | Should -Be 'x86compatible'
    $Info.UnsupportedArchitectures | Should -BeNullOrEmpty
    Test-InnoAppsAndFeaturesEntry -Path $Fixture | Should -BeTrue
  }

  It 'Should detect a default-user dual-scope Inno installer' {
    $Fixture = Get-InstallerFixture -Name 'loot_0.26.0-win64.exe' -Url 'https://github.com/loot/loot/releases/download/0.26.0/loot_0.26.0-win64.exe'
    $Info = Get-InnoInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Inno'
    $Info.DisplayName | Should -Be 'LOOT'
    $Info.DisplayVersion | Should -Be '0.26.0'
    $Info.ProductCode | Should -Be '{{BF634210-A0D4-443F-A657-0DCE38040374}'
    $Info.PrivilegesRequired | Should -Be 'lowest'
    $Info.PrivilegesRequiredOverridesAllowed | Should -Be @('commandline', 'dialog')
    $Info.DefaultScope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.ArchitecturesAllowed | Should -Be 'x64compatible'
    $Info.UnsupportedArchitectures | Should -Be @('x86')
    Test-InnoUnsupportedArchitecture -Path $Fixture -Architecture x86 | Should -BeTrue
    Test-InnoAppsAndFeaturesEntry -Path $Fixture | Should -BeTrue
  }

  It 'Should not treat a legacy Inno installer without command-line privilege overrides as dual-scope' {
    $Fixture = Get-InstallerFixture -Name 'BankLinkBooks.exe' -Url 'https://download.myob.com/BankLinkBooks.exe'
    $Info = Get-InnoInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Inno'
    $Info.SupportedScopes | Should -BeNullOrEmpty
    $Info.SupportsDualScope | Should -BeFalse
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.UnsupportedArchitectures | Should -BeNullOrEmpty
  }

  It 'Should detect Inno setups that suppress their own Apps & Features entry' {
    $Module = Get-Module Inno | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $HeaderValues = [string[]]::new(26)
      for ($Index = 0; $Index -lt $HeaderValues.Count; $Index++) { $HeaderValues[$Index] = '' }
      $HeaderValues[24] = 'no'
      $HeaderValues[25] = 'yes'
      $NoRegistryKey = Get-InnoAppsAndFeaturesEntryInfo -HeaderValues $HeaderValues -VersionNumber 6500

      $HeaderValues[24] = 'yes'
      $HeaderValues[25] = 'no'
      $NoUninstaller = Get-InnoAppsAndFeaturesEntryInfo -HeaderValues $HeaderValues -VersionNumber 6500

      $HeaderValues[24] = ''
      $HeaderValues[25] = ''
      $Default = Get-InnoAppsAndFeaturesEntryInfo -HeaderValues $HeaderValues -VersionNumber 6500

      [pscustomobject]@{
        NoRegistryKey = $NoRegistryKey.WritesAppsAndFeaturesEntry
        NoUninstaller = $NoUninstaller.WritesAppsAndFeaturesEntry
        Default = $Default.WritesAppsAndFeaturesEntry
      }
    }

    $Result.NoRegistryKey | Should -BeFalse
    $Result.NoUninstaller | Should -BeFalse
    $Result.Default | Should -BeTrue
  }

  It 'Should detect Argente Inno wrappers that do not write their own Apps & Features entry' {
    $FixtureName = 'Argente.DataShredder.x64.exe'
    $FixtureUrl = 'https://argenteutilities.com/en/download/datashredderx64'
    $Fixture = Get-InstallerFixture -Name $FixtureName -Url $FixtureUrl

    try {
      $Info = Get-InnoInfo -Path $Fixture
    } catch {
      Remove-Item -Path $Fixture -Force -ErrorAction SilentlyContinue
      $Fixture = Get-InstallerFixture -Name $FixtureName -Url $FixtureUrl
      $Info = Get-InnoInfo -Path $Fixture
    }

    $Info.InstallerType | Should -Be 'Inno'
    $Info.DisplayName | Should -Be 'Argente'
    $Info.ProductCode | Should -Be 'Argente'
    $Info.CreateUninstallRegKey | Should -Be 'yes'
    $Info.Uninstallable | Should -Be 'no'
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
    Test-InnoAppsAndFeaturesEntry -Path $Fixture | Should -BeFalse
  }

  It 'Should extract BK5WIN.EXE statically from the BankLink Books installer' {
    $Fixture = Get-InstallerFixture -Name 'BankLinkBooks.exe' -Url 'https://download.myob.com/BankLinkBooks.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'myob-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = Expand-InnoInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'BK5WIN.EXE'
      $Extracted | Should -HaveCount 1
      (Get-Item $Extracted[0].FullName).VersionInfo.FileVersion | Should -Be '5.55.3.7499'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract the English VUSC launch file statically from the VUSC installer' {
    $Fixture = Get-InstallerFixture -Name 'VUSC_setup_709.zip' -Url 'https://www.ok2kkw.com/vusc/vusc4win/VUSC_setup_709.zip'
    $ArchivePath = Join-Path $Script:FixtureDirectory 'vusc-archive'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'vusc-expanded'
    Remove-Item -Path $ArchivePath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      Expand-Archive -Path $Fixture -DestinationPath $ArchivePath -Force
      $NestedInstaller = Get-ChildItem -Path $ArchivePath -Filter '*.exe' -Recurse | Select-Object -First 1
      $Extracted = Expand-InnoInstaller -Path $NestedInstaller.FullName -DestinationPath $ExpandedPath -Name 'VUSC.exe' -Language 'en'

      $Extracted | Should -HaveCount 1
      (Get-FileHash -Path $Extracted[0].FullName -Algorithm SHA256).Hash | Should -Be '021A05A497BBCE1EE604CC223E7BB813171F198B3B27AE3C90A50EBD0F6DFEAE'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
      Remove-Item -Path $ArchivePath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}
