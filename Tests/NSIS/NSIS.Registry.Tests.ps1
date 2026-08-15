. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\NSISTestSetup.ps1')

Describe 'NSIS registry and scope projection' -Tag Unit {
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
}
