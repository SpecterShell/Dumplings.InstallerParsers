. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

# SPDX-License-Identifier: GPL-3.0-or-later

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Binary.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Archive.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\PE.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\InstallerDiagnostics.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\InstallerEvidence.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\SetupFactory.psm1') -Force
  function New-TestSetupFactoryProjectData {
    param (
      [bool]$EnableSilentMode,
      [bool]$StartInSilentMode = $false
    )

    $Bytes = [Collections.Generic.List[byte]]::new()
    $AddUInt32 = { param([uint32]$Value) $Bytes.AddRange([BitConverter]::GetBytes($Value)) }
    $AddString = {
      param([string]$Value)
      $Encoded = [Text.Encoding]::UTF8.GetBytes($Value)
      $Bytes.Add([byte]$Encoded.Length)
      $Bytes.AddRange($Encoded)
    }

    & $AddUInt32 1
    $Bytes.Add(1)
    & $AddString '%WindowsFolder%\%ProductName% Setup Log.txt'
    $Bytes.Add(0)
    $Bytes.Add(1)
    $Bytes.Add([byte]$EnableSilentMode)
    $Bytes.Add([byte]$StartInSilentMode)
    $Bytes.Add(0)
    $Bytes.Add(0)
    & $AddUInt32 1
    $Bytes.Add(1)
    & $AddUInt32 0
    & $AddUInt32 0
    foreach ($Color in 0x000000, 0xFFFFFF, 0x808080) { & $AddUInt32 $Color }
    & $AddString ''
    $Bytes.Add(0)
    & $AddString ''
    $Bytes.Add(0)
    $Bytes.Add(0)
    & $AddString 'Setup'
    & $AddUInt32 1
    return , $Bytes.ToArray()
  }

  function Expand-TestSetupFactory31Media {
    param([Parameter(Mandatory)][string]$DestinationPath)

    $ArchivePath = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SetupFactory-3.1-builder.zip')
    if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) { return $null }
    $null = New-Item -ItemType Directory -Path $DestinationPath -Force
    [IO.Compression.ZipFile]::ExtractToDirectory($ArchivePath, $DestinationPath, $true)
    return Join-Path $DestinationPath 'SETUP.EXE'
  }
}

Describe 'Setup Factory static parser' {
  It 'parses Setup Factory 3.1 multi-file media and its two Crusher profiles' {
    $Path = Expand-TestSetupFactory31Media -DestinationPath (Join-Path $TestDrive 'setup-factory-31-parse')
    if (-not $Path) { Set-ItResult -Skipped -Because 'The historical Setup Factory 3.1 fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    Test-SetupFactory -Path $Path | Should -BeTrue
    Test-SetupFactory -Path (Join-Path (Split-Path $Path) 'IRDATA.IRD') | Should -BeTrue
    $Info.ParserVersionInfo.ProfileId | Should -BeExactly 'setup-factory-3.1-multifile'
    $Info.ParserVersionInfo.BuilderVersion | Should -BeExactly '3.1.0'
    $Info.DisplayName | Should -BeExactly 'Setup Factory 3.1 Demo'
    $Info.DefaultInstallLocation | Should -BeExactly 'C:\SUF310EV'
    $Info.ContainerEntries.Name | Should -Be @('IRDATA.DAT', 'IRSETUP.EXE', 'IRUNIN31.EXE', 'OWNER.ARQ')
    $Info.PayloadCatalog | Should -HaveCount 15
    $Info.PayloadCatalog.Compression | Should -Contain 'CrusherLh5Extended'
    $Info.CanExpand | Should -BeTrue
    $Info.SupportsSilentInstallation | Should -BeFalse
    $Info.InstallModes | Should -Be @('interactive')
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
    $Info.Diagnostics.Id | Should -Contain 'SetupFactory.Installability.SilentUnsupportedByGeneration'
    $Info.Diagnostics.Id | Should -Contain 'SetupFactory.Metadata.NoWindowsArpByGeneration'
  }

  It 'extracts every installed and raw Setup Factory 3.1 record with CRC validation' {
    $Path = Expand-TestSetupFactory31Media -DestinationPath (Join-Path $TestDrive 'setup-factory-31-extract')
    if (-not $Path) { Set-ItResult -Skipped -Because 'The historical Setup Factory 3.1 fixture is not available'; return }

    $InstalledFiles = @(Expand-SetupFactoryInstaller -Path $Path -DestinationPath (Join-Path $TestDrive 'setup-factory-31-installed') -CollisionAction Error)
    $RawFiles = @(Expand-SetupFactoryInstaller -Path $Path -DestinationPath (Join-Path $TestDrive 'setup-factory-31-raw') -RawEntries -CollisionAction Error)
    $Installed = $InstalledFiles | Where-Object Name -EQ 'DEFAULT.SFP'
    $Metadata = $RawFiles | Where-Object Name -EQ 'IRDATA.DAT'
    $Owner = $RawFiles | Where-Object Name -EQ 'OWNER.ARQ'

    $InstalledFiles | Should -HaveCount 15
    ($InstalledFiles | Measure-Object Length -Sum).Sum | Should -Be 1787357
    $Installed.Length | Should -Be 813
    (Get-FileHash -LiteralPath $Installed.FullName -Algorithm SHA256).Hash | Should -BeExactly 'D2F7AA74806DB772C01164BC32ED95553EB53CA65C02AF50B7E896014A0DC45D'
    $RawFiles | Should -HaveCount 4
    $Metadata.Length | Should -Be 3465
    (Get-FileHash -LiteralPath $Metadata.FullName -Algorithm SHA256).Hash | Should -BeExactly '9AF9289AB0E9EF4348C2D5381397FF70D64D18CC3A386D7444440F67425A2A4B'
    $Owner.Length | Should -Be 205
    (Get-FileHash -LiteralPath $Owner.FullName -Algorithm SHA256).Hash | Should -BeExactly 'A3AF6E2130D29F80A30A5D50341997D0E0D2A8ECDD44B56F4A29D0423ECDB5F4'
  }

  It 'reports a missing Setup Factory 3.1 companion without hiding extractable entries' {
    $Path = Expand-TestSetupFactory31Media -DestinationPath (Join-Path $TestDrive 'setup-factory-31-missing')
    if (-not $Path) { Set-ItResult -Skipped -Because 'The historical Setup Factory 3.1 fixture is not available'; return }
    Remove-Item -LiteralPath (Join-Path (Split-Path $Path) 'DEFAULT.SF_') -Force

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.CanExpand | Should -BeFalse
    $Info.CanExpandPartial | Should -BeTrue
    $Info.Diagnostics.Id | Should -Contain 'SetupFactory.Payload.MultiFileCompanionMissing'
    { Expand-SetupFactoryInstaller -Path $Path -DestinationPath (Join-Path $TestDrive 'setup-factory-31-missing-output') -Name 'DEFAULT.SFP' -CollisionAction Error } | Should -Throw '*missing or has an invalid companion*'
    $Other = Expand-SetupFactoryInstaller -Path $Path -DestinationPath (Join-Path $TestDrive 'setup-factory-31-partial') -Name 'README.TXT' -CollisionAction Error
    $Other.Length | Should -Be 5613
  }

  It 'rejects a corrupt Setup Factory 3.1 ARQ member before decoding it' {
    $Path = Expand-TestSetupFactory31Media -DestinationPath (Join-Path $TestDrive 'setup-factory-31-corrupt')
    if (-not $Path) { Set-ItResult -Skipped -Because 'The historical Setup Factory 3.1 fixture is not available'; return }
    $ArchivePath = Join-Path (Split-Path $Path) 'IRDATA.IRD'
    $Stream = [IO.File]::Open($ArchivePath, 'Open', 'ReadWrite', 'None')
    try {
      $Stream.Position = 51
      $Value = $Stream.ReadByte()
      $Stream.Position = 51
      $Stream.WriteByte([byte]($Value -bxor 0x80))
    } finally {
      $Stream.Dispose()
    }

    { Get-SetupFactoryInfo -Path $Path } | Should -Throw '*failed its packed CRC32 check*'
  }

  It 'resolves the compiled modern silent-mode flag from a validated project record' -ForEach @(
    @{ Enabled = $false; StartsSilent = $false }
    @{ Enabled = $true; StartsSilent = $true }
  ) {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Bytes = New-TestSetupFactoryProjectData -EnableSilentMode $Enabled -StartInSilentMode $StartsSilent

    $Result = & $Module { param([byte[]]$Data) Get-SetupFactorySilentInstallationInfo -Bytes $Data -MetadataRoute 'irdat-v7' } $Bytes

    $Result.IsResolved | Should -BeTrue
    $Result.SupportsSilentInstallation | Should -Be $Enabled
    $Result.StartsInSilentMode | Should -Be $StartsSilent
    $Result.CandidateCount | Should -Be 1
    $Result.Evidence.SilentFlagOffset | Should -BeGreaterThan $Result.Evidence.Offset
  }

  It 'resolves historical silent-mode capabilities and leaves malformed modern project data unresolved' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Bytes = New-TestSetupFactoryProjectData -EnableSilentMode $true
    $Malformed = $Bytes[0..($Bytes.Length - 6)]

    $Version4 = & $Module { param([byte[]]$Data) Get-SetupFactorySilentInstallationInfo -Bytes $Data -MetadataRoute 'irdat-v4' } $Bytes
    $Version5 = & $Module { param([byte[]]$Data) Get-SetupFactorySilentInstallationInfo -Bytes $Data -MetadataRoute 'irdat-v5' } $Bytes
    $Version6 = & $Module { param([byte[]]$Data) Get-SetupFactorySilentInstallationInfo -Bytes $Data -MetadataRoute 'irdat-v6' } $Bytes
    $Truncated = & $Module { param([byte[]]$Data) Get-SetupFactorySilentInstallationInfo -Bytes $Data -MetadataRoute 'irdat-v7' } $Malformed

    $Version4.IsResolved | Should -BeTrue
    $Version4.SupportsSilentInstallation | Should -BeFalse
    $Version4.Evidence.Reason | Should -Be 'GenerationPredatesSilentMode'
    $Version5.IsResolved | Should -BeTrue
    $Version5.SupportsSilentInstallation | Should -BeFalse
    $Version5.Evidence.Reason | Should -Be 'GenerationPredatesSilentMode'
    $Version6.IsResolved | Should -BeTrue
    $Version6.SupportsSilentInstallation | Should -BeTrue
    $Version6.StartsInSilentMode | Should -BeNullOrEmpty
    $Version6.Evidence.Reason | Should -Be 'GenerationImplementsSilentMode'
    $Truncated.IsResolved | Should -BeFalse
    $Truncated.Evidence.Reason | Should -Be 'ProjectDataNotFound'
  }

  It 'resolves duplicate modern project records only when their silent-mode flags agree' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Enabled = New-TestSetupFactoryProjectData -EnableSilentMode $true
    $Disabled = New-TestSetupFactoryProjectData -EnableSilentMode $false
    $ConsensusBytes = [byte[]]($Enabled + $Enabled)
    $ConflictBytes = [byte[]]($Enabled + $Disabled)

    $Consensus = & $Module { param([byte[]]$Data) Get-SetupFactorySilentInstallationInfo -Bytes $Data -MetadataRoute 'irdat-v8-plus' } $ConsensusBytes
    $Conflict = & $Module { param([byte[]]$Data) Get-SetupFactorySilentInstallationInfo -Bytes $Data -MetadataRoute 'irdat-v8-plus' } $ConflictBytes

    $Consensus.IsResolved | Should -BeTrue
    $Consensus.SupportsSilentInstallation | Should -BeTrue
    $Consensus.CandidateCount | Should -Be 2
    $Consensus.Evidence.Reason | Should -Be 'ProjectDataConsensus'
    $Conflict.IsResolved | Should -BeFalse
    $Conflict.CandidateCount | Should -Be 2
    $Conflict.Evidence.Reason | Should -Be 'ProjectDataConflict'
  }

  It 'distinguishes default and behavior-affecting classic file conditions' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Summary = & $Module {
      $Default4 = ConvertTo-SetupFactoryFilePolicy -Values @{ LegacyPolicySchema = 2; LegacyOperatingSystemMask = 0x1F; LegacyOperatingSystemPolicy = Get-SetupFactoryLegacyOperatingSystemPolicy -Generation Classic4 -Mask 0x1F; UseTrueVersion = $true; FileVersionMS = 0x00010002; FileVersionLS = 0x00030004 }
      $Conditional4 = ConvertTo-SetupFactoryFilePolicy -Values @{ LegacyPolicySchema = 2; LegacyOperatingSystemMask = 0x0F; LegacyOperatingSystemPolicy = Get-SetupFactoryLegacyOperatingSystemPolicy -Generation Classic4 -Mask 0x0F }
      $Default5 = ConvertTo-SetupFactoryFilePolicy -Values @{ LegacyOperatingSystemMask = [uint32]::MaxValue; LegacyOperatingSystemPolicy = Get-SetupFactoryLegacyOperatingSystemPolicy -Generation Legacy5 -Mask ([uint32]::MaxValue); LegacyLanguageCondition = 0; LegacyAdvancedConditions = @() }
      $Conditional5 = ConvertTo-SetupFactoryFilePolicy -Values @{ LegacyOperatingSystemMask = 4; LegacyOperatingSystemPolicy = Get-SetupFactoryLegacyOperatingSystemPolicy -Generation Legacy5 -Mask 4; LegacyLanguageCondition = 2; LegacyAdvancedConditions = @([pscustomobject]@{ LeftOperand = '%WindowsVersion%'; Operator = [uint32]0; OperatorName = 'Equals'; RightOperand = 'Windows 2000'; IsSupported = $true }) }
      Get-SetupFactoryFilePolicySummary -Entry @(
        [pscustomobject]@{ Name = 'default4.exe'; Policy = $Default4; Packages = @() }
        [pscustomobject]@{ Name = 'conditional4.exe'; Policy = $Conditional4; Packages = @() }
        [pscustomobject]@{ Name = 'default5.exe'; Policy = $Default5; Packages = @() }
        [pscustomobject]@{ Name = 'conditional5.exe'; Policy = $Conditional5; Packages = @() }
      )
    }

    $Summary.ConditionalEntries | Should -Be @('conditional4.exe', 'conditional5.exe')
  }

  It 'treats the Setup Factory 4 Any OS bit as an unrestricted runtime policy' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Policies = & $Module {
      [pscustomobject]@{
        AnyOs            = Get-SetupFactoryLegacyOperatingSystemPolicy -Generation Classic4 -Mask 0x10
        SelectedVersions = Get-SetupFactoryLegacyOperatingSystemPolicy -Generation Classic4 -Mask 0x0F
      }
    }

    $Policies.AnyOs.Targets | Should -Be @('Any OS')
    $Policies.AnyOs.AcceptsEveryKnownOperatingSystem | Should -BeTrue
    $Policies.AnyOs.IsRestricted | Should -BeFalse
    $Policies.SelectedVersions.AcceptsEveryKnownOperatingSystem | Should -BeFalse
    $Policies.SelectedVersions.IsRestricted | Should -BeTrue
  }

  It 'normalizes Setup Factory 6 textual Boolean operators and variable tokens' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      [pscustomobject]@{
        Constant = Resolve-SetupFactoryActionCondition6 -Expression 'FALSE AND !TRUE' -IdentifierState @{}
        Variable = Resolve-SetupFactoryActionCondition6 -Expression '%FeatureEnabled% OR FALSE' -IdentifierState @{ '%FeatureEnabled%' = 'True' }
        Dynamic  = Resolve-SetupFactoryActionCondition6 -Expression '%Counter% < 2' -IdentifierState @{}
      }
    }

    $Result.Constant.State | Should -BeExactly 'False'
    $Result.Constant.NormalizedExpression | Should -BeExactly 'FALSE && !TRUE'
    $Result.Variable.State | Should -BeExactly 'True'
    $Result.Variable.NormalizedExpression | Should -BeExactly 'SF_FeatureEnabled || FALSE'
    $Result.Dynamic.State | Should -BeExactly 'Unknown'
  }

  It 'decodes variable-length Setup Factory 5 advanced condition records' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Condition = & $Module {
      $Data = [Collections.Generic.List[byte]]::new()
      foreach ($Value in '%ProductVer%', '5.0') {
        $Encoded = [Text.Encoding]::UTF8.GetBytes($Value)
        $Data.Add([byte]$Encoded.Length)
        $Data.AddRange($Encoded)
      }
      $Data.AddRange([BitConverter]::GetBytes([uint32]3))
      $Data.AddRange([BitConverter]::GetBytes([uint32]0x11223344))
      $Data.AddRange([BitConverter]::GetBytes([uint32]0x55667788))
      foreach ($Value in 'Builder note', 'UI label') {
        $Encoded = [Text.Encoding]::UTF8.GetBytes($Value)
        $Data.Add([byte]$Encoded.Length)
        $Data.AddRange($Encoded)
      }
      $Offset = [long]0
      $Result = Read-SetupFactoryConditionRecord5 -Bytes $Data.ToArray() -Offset ([ref]$Offset) -Width Small -Type 0x8001 -ClassName CConditionData
      [pscustomobject]@{ Result = $Result; EndOffset = $Offset; Length = $Data.Count }
    }

    $Condition.EndOffset | Should -Be $Condition.Length
    $Condition.Result.LeftOperand | Should -BeExactly '%ProductVer%'
    $Condition.Result.Operator | Should -Be 3
    $Condition.Result.OperatorName | Should -BeExactly 'GreaterThanOrEqual'
    $Condition.Result.RightOperand | Should -BeExactly '5.0'
    $Condition.Result.IsSupported | Should -BeTrue
    $Condition.Result.Comparison | Should -BeExactly 'CaseInsensitiveLexical'
    $Condition.Result.ReservedValues | Should -Be @([uint32]0x11223344, [uint32]0x55667788)
    $Condition.Result.ReservedStrings | Should -Be @('Builder note', 'UI label')
    $Condition.Result.RecordLength | Should -Be $Condition.Length
  }

  It 'accepts an existing MFC CConditionData class reference at the start of a nested list' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Condition = & $Module {
      $Stream = [IO.MemoryStream]::new()
      $Writer = [IO.BinaryWriter]::new($Stream, [Text.Encoding]::ASCII, $true)
      $WriteString = {
        param ([string]$Value)
        $Encoded = [Text.Encoding]::ASCII.GetBytes($Value)
        $Writer.Write([byte]$Encoded.Length)
        $Writer.Write($Encoded)
      }
      try {
        $Writer.Write([uint16]0x8097)
        & $WriteString '%StartApp%'
        & $WriteString 'Checked'
        $Writer.Write([uint32]0)
        $Writer.Write([uint32]0)
        $Writer.Write([uint32]0)
        & $WriteString ''
        & $WriteString ''
        $Writer.Flush()
        $Bytes = $Stream.ToArray()
        $Offset = [long]0
        $Records = @(Read-SetupFactoryConditionList5 -Bytes $Bytes -Offset ([ref]$Offset) -Count 1)
        [pscustomobject]@{ Records = $Records; EndOffset = $Offset; Length = $Bytes.Length }
      } finally {
        $Writer.Dispose()
        $Stream.Dispose()
      }
    }

    $Condition.EndOffset | Should -Be $Condition.Length
    $Condition.Records | Should -HaveCount 1
    $Condition.Records[0].Type | Should -Be 0x8097
    $Condition.Records[0].ClassName | Should -BeExactly 'CConditionData'
    $Condition.Records[0].LeftOperand | Should -BeExactly '%StartApp%'
    $Condition.Records[0].OperatorName | Should -BeExactly 'Equals'
    $Condition.Records[0].RightOperand | Should -BeExactly 'Checked'
  }

  It 'decodes the complete Setup Factory 5 INI action layout' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $Stream = [IO.MemoryStream]::new()
      $Writer = [IO.BinaryWriter]::new($Stream, [Text.Encoding]::ASCII, $true)
      $WriteString = {
        param ([string]$Value)
        $Encoded = [Text.Encoding]::ASCII.GetBytes($Value)
        $Writer.Write([byte]$Encoded.Length)
        $Writer.Write($Encoded)
      }
      try {
        $Writer.Write([byte]0)
        & $WriteString '%AppDir%\settings.ini'
        & $WriteString 'Options'
        & $WriteString 'SearchPath'
        & $WriteString '%AppDir%\bin'
        $Writer.Write([byte]4)
        & $WriteString ';'
        $Writer.Write([byte]1)
        $Writer.Write([uint32]::MaxValue)
        $Writer.Write([uint32]0)
        & $WriteString 'None'
        $Writer.Write([uint16]0)
        foreach ($Value in 0..3) { $Writer.Write([uint32]0) }
        foreach ($Value in 0..3) { & $WriteString '' }
        $Writer.Flush()
        $Bytes = $Stream.ToArray()
        $Offset = [long]0
        $Record = Read-SetupFactoryIniRecord5 -Bytes $Bytes -Offset ([ref]$Offset)
        [pscustomobject]@{ Record = $Record; EndOffset = $Offset; Length = $Bytes.Length }
      } finally {
        $Writer.Dispose()
        $Stream.Dispose()
      }
    }

    $Result.EndOffset | Should -Be $Result.Length
    $Result.Record.ActionName | Should -BeExactly 'SetValue'
    $Result.Record.FileName | Should -BeExactly '%AppDir%\settings.ini'
    $Result.Record.Section | Should -BeExactly 'Options'
    $Result.Record.Key | Should -BeExactly 'SearchPath'
    $Result.Record.Value | Should -BeExactly '%AppDir%\bin'
    $Result.Record.ExistingValueActionName | Should -BeExactly 'Append'
    $Result.Record.Separator | Should -BeExactly ';'
    $Result.Record.ConditionState | Should -BeExactly 'True'
  }

  It 'preserves literal registry values for protocol and file association analysis' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Writes = & $Module {
      $Text = @'
Registry.SetValue("HKCU", "Software\Classes\example", "URL Protocol", "")
Registry.SetValue("HKCU", "Software\Classes\example\shell\open\command", "", "\"%AppFolder%\Example.exe\" \"%1\"")
Registry.SetValue("HKCU", "Software\Classes\.example", "", "Example.Document")
'@
      @(Get-SetupFactoryLiteralRegistryWrite -Bytes ([Text.Encoding]::UTF8.GetBytes($Text)))
    }

    $Info = Get-InstallerRegistryAssociationInfo -RegistryWrite $Writes

    $Writes[0].Value | Should -Be ''
    $Writes[0].Key | Should -Be 'Software\Classes\example'
    $Writes[1].Value | Should -Be '"%AppFolder%\Example.exe" "%1"'
    $Info.Protocols | Should -Be @('example')
    $Info.FileExtensions | Should -Be @('example')
  }

  It 'counts computed registry actions without treating them as literal evidence' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $Text = @'
Registry.SetValue("HKCR", "demo", "URL Protocol", "")
Registry.SetValue(rootName, "Software\Classes\computed", "", "value")
'@
      $Unresolved = 0
      $Writes = @(Get-SetupFactoryLiteralRegistryWrite -Bytes ([Text.Encoding]::UTF8.GetBytes($Text)) -UnresolvedCount ([ref]$Unresolved))
      [pscustomobject]@{ Writes = $Writes; Unresolved = $Unresolved }
    }

    $Result.Writes | Should -HaveCount 1
    $Result.Writes[0].Root | Should -Be 'HKCR'
    $Result.Unresolved | Should -Be 1
  }

  It 'does not treat unrelated registry writes as Apps and Features evidence' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Entries = & $Module {
      $Writes = @(
        [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Classes\Example.Document'; Name = ''; Value = 'Example'; Type = 'REG_SZ' }
        [pscustomobject]@{ Root = 'HKCR'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Not.Arp'; Name = 'DisplayName'; Value = 'Not ARP'; Type = 'REG_SZ' }
      )
      @(Get-SetupFactoryArpEntry -RegistryWrite $Writes -Variables @{})
    }

    $Entries | Should -BeNullOrEmpty
  }

  It 'keeps visible and hidden custom uninstall entries separate' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Entries = & $Module {
      $Writes = @(
        [pscustomobject]@{ Root = 'HKCU'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Visible.Product'; Name = 'DisplayName'; Value = 'Visible Product'; Type = 'REG_SZ' }
        [pscustomobject]@{ Root = 'HKCU'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Visible.Product'; Name = 'Publisher'; Value = 'Example Publisher'; Type = 'REG_SZ' }
        [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden.Product'; Name = 'DisplayName'; Value = 'Hidden Product'; Type = 'REG_SZ' }
        [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden.Product'; Name = 'SystemComponent'; Value = '1'; Type = 'REG_DWORD' }
      )
      @(Get-SetupFactoryArpEntry -RegistryWrite $Writes -Variables @{})
    }

    $Entries.Count | Should -Be 2
    ($Entries | Where-Object ProductCode -CEQ 'Visible.Product').Scope | Should -Be 'user'
    ($Entries | Where-Object ProductCode -CEQ 'Visible.Product').IsVisible | Should -BeTrue
    ($Entries | Where-Object ProductCode -CEQ 'Hidden.Product').Scope | Should -Be 'machine'
    ($Entries | Where-Object ProductCode -CEQ 'Hidden.Product').IsVisible | Should -BeFalse
  }

  It 'decodes the official zlib blast PKWARE test vector with an output limit' {
    if (-not ([System.Management.Automation.PSTypeName]'Dumplings.InstallerParsers.PkwareBlast').Type) {
      Add-Type -Path (Join-Path $Script:DumplingsModuleRoot 'Assets\Source\SetupFactory\PkwareBlast.cs')
    }
    $Compressed = [byte[]](0x00, 0x04, 0x82, 0x24, 0x25, 0x8F, 0x80, 0x7F)
    $Decoded = [Dumplings.InstallerParsers.PkwareBlast]::Decode($Compressed, 13)
    [Text.Encoding]::ASCII.GetString($Decoded) | Should -Be 'AIAIAIAIAIAIA'
    { [Dumplings.InstallerParsers.PkwareBlast]::Decode($Compressed, 12) } | Should -Throw '*configured limit*'
  }

  It 'rejects a truncated PKWARE stream without hanging' {
    if (-not ([System.Management.Automation.PSTypeName]'Dumplings.InstallerParsers.PkwareBlast').Type) {
      Add-Type -Path (Join-Path $Script:DumplingsModuleRoot 'Assets\Source\SetupFactory\PkwareBlast.cs')
    }
    { [Dumplings.InstallerParsers.PkwareBlast]::Decode([byte[]](0, 4, 0), 1024) } | Should -Throw '*end marker*'
  }

  It 'parses the real Bicom Systems OutCALL installer when available' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'OutCALL-2.0.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared real-installer fixture is not available'; return }
    $Info = Get-SetupFactoryInfo -Path $Path
    $Info.DisplayName | Should -Be 'OutCALL'
    $Info.DisplayVersion | Should -Be '2.0'
    $Info.Publisher | Should -Be 'Bicom Systems'
    $Info.ProductCode | Should -Be 'OutCALL2.0'
    $Info.Scope | Should -Be 'machine'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.SupportsSilentInstallation | Should -BeTrue
    $Info.InstallModes | Should -Be @('interactive', 'silent')
    $Info.InstallerSwitches.Silent | Should -Be '/S'
  }

  It 'selectively expands the runtime and metadata records from OutCALL when available' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'OutCALL-2.0.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared real-installer fixture is not available'; return }
    $Destination = Join-Path $TestDrive 'outcall'

    $Files = @(Expand-SetupFactoryInstaller -Path $Path -DestinationPath $Destination -Name 'irsetup.*' -RawEntries -CollisionAction Error)

    $Files.Name | Sort-Object | Should -Be @('irsetup.dat', 'irsetup.exe')
    $Runtime = [IO.File]::OpenRead((Join-Path $Destination 'irsetup.exe'))
    try {
      $Runtime.ReadByte() | Should -Be 0x4D
      $Runtime.ReadByte() | Should -Be 0x5A
    } finally {
      $Runtime.Dispose()
    }
    (Get-Item -LiteralPath (Join-Path $Destination 'irsetup.dat')).Length | Should -BeGreaterThan 0
  }

  It 'selectively expands and verifies one installed application file' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'OutCALL-2.0.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared real-installer fixture is not available'; return }
    $Destination = Join-Path $TestDrive 'outcall-installed'

    $File = Expand-SetupFactoryInstaller -Path $Path -DestinationPath $Destination -Name 'icudt53.dll' -CollisionAction Error

    $File.Name | Should -Be 'icudt53.dll'
    $File.Length | Should -Be 21529088
  }

  It 'restores caller-owned stream positions during layout and catalog reads' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'OutCALL-2.0.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared real-installer fixture is not available'; return }
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Stream = [IO.File]::OpenRead($Path)
    try {
      $Stream.Position = 17
      $Overlay = & $Module { param($InstallerPath, $InstallerStream) Get-SetupFactoryOverlayInfo -Path $InstallerPath -Stream $InstallerStream } $Path $Stream
      $Stream.Position | Should -Be 17
      $Catalog = & $Module { param($InstallerPath, $InstallerStream) Get-SetupFactoryArchiveCatalog -Path $InstallerPath -Stream $InstallerStream } $Path $Stream
      $Stream.Position | Should -Be 17
      $Overlay.ProfileId | Should -Be 'setup-factory-8-plus'
      $Catalog.Entries.Name | Should -Contain 'irsetup.dat'
    } finally {
      $Stream.Dispose()
    }
  }

  It 'parses the real Bicom Systems Communicator installer when available' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'Communicator-7.6.0.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared real-installer fixture is not available'; return }
    (Get-DumplingsTestFixtureHash -Path $Path) | Should -Be 'C2B8713B80533ACCA04B850B79C686D3DFDED2EDEE91168361128591FDEE7D6B'
    $Info = Get-SetupFactoryInfo -Path $Path
    $Info.DisplayName | Should -Be 'Communicator'
    $Info.ProductCode | Should -Be 'Communicator4'
    $Info.Scope | Should -Be 'machine'
    $Info.DependencyPayloads.FileName | Should -Be 'vc_redist.x64.exe'
    $Info.InstalledFileCatalog.ExtractableEntryCount | Should -Be 750
    $Info.InstalledFileCatalog.UnavailableEntryCount | Should -Be 0
    $Info.CanExpand | Should -BeTrue
    $Info.CanExpandPartial | Should -BeFalse
    $Info.Diagnostics.Id | Should -Not -Contain 'SetupFactory.Payload.Truncated'
    $RegistryDiagnostic = $Info.Diagnostics | Where-Object Id -EQ 'SetupFactory.Metadata.RegistryActionsUnresolved'
    $RegistryDiagnostic.AffectedFields | Should -Be @('AppsAndFeaturesEntries', 'FileExtensions', 'Protocols')
    $Info.UnresolvedFields | Should -Not -Contain 'ProductCode'
    $Info.UnresolvedFields | Should -Not -Contain 'Scope'
  }

  It 'extracts application files and separately framed prerequisites from current media' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'Communicator-7.6.0.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The current Setup Factory fixture is not available'; return }
    $AvailableDestination = Join-Path $TestDrive 'communicator-available'
    $DependencyDestination = Join-Path $TestDrive 'communicator-dependency'

    $Available = Expand-SetupFactoryInstaller -Path $Path -DestinationPath $AvailableDestination -Name 'sounds\fax.wav' -CollisionAction Error
    $Dependency = Expand-SetupFactoryInstaller -Path $Path -DestinationPath $DependencyDestination -Name '_dependencies\vc_redist.x64.exe' -RawEntries -CollisionAction Error

    $Available.Length | Should -Be 273140
    $Dependency.Length | Should -Be 14876264
    $DependencyStream = [IO.File]::OpenRead($Dependency.FullName)
    try {
      $DependencyMagic = [byte[]]::new(2)
      $DependencyStream.ReadExactly($DependencyMagic)
      $DependencyMagic | Should -Be ([byte[]](0x4D, 0x5A))
    } finally {
      $DependencyStream.Dispose()
    }
  }

  It 'parses the real Bicom Systems gloCOM installer when available' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'gloCOM-7.6.0.4.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared real-installer fixture is not available'; return }
    (Get-DumplingsTestFixtureHash -Path $Path) | Should -Be '40E8CB1A1D79B592278E5925CA9EEE9438DF7F9B4F4F321E59F9EF684CC5F5A5'
    $Info = Get-SetupFactoryInfo -Path $Path
    $Info.DisplayName | Should -Be 'gloCOM'
    $Info.ProductCode | Should -Be 'gloCOM4'
    $Info.Scope | Should -Be 'machine'
    $Info.DependencyPayloads.FileName | Should -Be 'vc_redist.x64.exe'
    $Info.InstalledFileCatalog.ExtractableEntryCount | Should -Be 766
    $Info.InstalledFileCatalog.UnavailableEntryCount | Should -Be 0
    $Info.CanExpand | Should -BeTrue
    $Info.CanExpandPartial | Should -BeFalse
  }

  It 'extracts the final installed-file record from complete Bicom media' -ForEach @(
    @{ Fixture = 'Communicator-7.6.0.exe'; EntryCount = 750 }
    @{ Fixture = 'gloCOM-7.6.0.4.exe'; EntryCount = 766 }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Fixture)
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The complete Bicom Setup Factory fixture is not available'; return }
    $Info = Get-SetupFactoryInfo -Path $Path
    $LastEntry = $Info.PayloadCatalog[-1]
    $Destination = Join-Path $TestDrive ([IO.Path]::GetFileNameWithoutExtension($Fixture) + '-tail')

    $Extracted = Expand-SetupFactoryInstaller -Path $Path -DestinationPath $Destination -Name $LastEntry.Name -CollisionAction Error

    $Info.PayloadCatalog | Should -HaveCount $EntryCount
    $LastEntry.Name | Should -Be 'opus.dll'
    $Extracted.Length | Should -Be 374784
    $Extracted.Length | Should -Be $LastEntry.ExpandedSize
  }

  It 'parses the real Locklizard installer without inventing a ProductCode' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SafeguardPDFViewer_v3.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared real-installer fixture is not available'; return }
    $Info = Get-SetupFactoryInfo -Path $Path
    $Info.DisplayName | Should -Be 'Locklizard Safeguard - PDF Viewer'
    $Info.DisplayVersion | Should -Be '3.0.2.231'
    $Info.Publisher | Should -Be 'Locklizard Ltd.'
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
  }

  It 'selects both observed Setup Factory 7 runtime-prefix routes' -ForEach @(
    @{ Fixture = 'SetupFactory-7.0.1-ReNamer.exe'; Prefix = 8; Name = 'ReNamer'; Version = '1.80'; PayloadCount = 1 }
    @{ Fixture = 'SetupFactory-7.0.3-setup365dni.exe'; Prefix = 8; Name = '365dní'; Version = '6.0.7'; PayloadCount = 107 }
    @{ Fixture = 'SetupFactory-7.0.6-FLVPlayerSetup.exe'; Prefix = 9; Name = 'FLV Player'; Version = '2.0 '; PayloadCount = 1 }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Fixture)
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared historical Setup Factory fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.ParserVersionInfo.ProfileId | Should -Be 'setup-factory-7'
    $Info.ParserVersionInfo.HeaderPrefixLength | Should -Be $Prefix
    $Info.DisplayVersion | Should -Be $Version
    $Info.PayloadCatalog.Count | Should -Be $PayloadCount
    $Info.CanExpand | Should -BeTrue
    if ($Name) { $Info.DisplayName | Should -Be $Name }
    if ($Fixture -eq 'SetupFactory-7.0.1-ReNamer.exe') {
      $Info.SupportsSilentInstallation | Should -BeFalse
      $Info.InstallModes | Should -Be @('interactive')
      $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'Silent'
      $Info.Diagnostics.Id | Should -Contain 'SetupFactory.Installability.SilentDisabled'
      $Info.PayloadCatalog[0].Policy.OverwritePolicy | Should -BeExactly 'Older'
      $Info.PayloadCatalog[0].Policy.ShortcutLocations | Should -Be @('ApplicationShortcutFolder', 'Desktop')
      $Info.PayloadCatalog[0].Policy.BuildConfigurations | Should -Be @('All')
      $Info.PayloadCatalog[0].Policy.PackageSelector | Should -BeExactly 'None'
      $Info.PayloadCatalog[0].Policy.InstallOrder | Should -Be 1000
    }
  }

  It 'keeps modern archive revisions separate from the Setup Factory release identity' -ForEach @(
    @{ Fixture = 'SetupFactory-8.1.1008.0-builder.exe'; Builder = '8.1.1008.0'; Major = 8; Product = 'Setup Factory 8.0 Trial'; PayloadCount = 1083; DestinationPolicyLength = 10; HasAppUserModelID = $false; Silent = $false }
    @{ Fixture = 'SetupFactory-9.0.3-trial.exe'; Builder = '9.0.3.0'; Major = 9; Product = 'Setup Factory 9 Trial'; PayloadCount = 1169; DestinationPolicyLength = 10; HasAppUserModelID = $false; Silent = $true }
    @{ Fixture = 'SetupFactory-9.0.4-trial.exe'; Builder = '9.0.4.0'; Major = 9; Product = 'Setup Factory 9 Trial'; PayloadCount = 1169; DestinationPolicyLength = 10; HasAppUserModelID = $false; Silent = $true }
    @{ Fixture = 'SetupFactory-9.1.1-trial.exe'; Builder = '9.1.1.0'; Major = 9; Product = 'Setup Factory 9 Trial'; PayloadCount = 1169; DestinationPolicyLength = 11; HasAppUserModelID = $false; Silent = $true }
    @{ Fixture = 'SetupFactory-9.2.0-trial.exe'; Builder = '9.2.0.0'; Major = 9; Product = 'Setup Factory 9 Trial'; PayloadCount = 1169; DestinationPolicyLength = 11; HasAppUserModelID = $false; Silent = $true }
    @{ Fixture = 'SetupFactory-9.5.1-trial.exe'; Builder = '9.5.1.0'; Major = 9; Product = 'Setup Factory 9 Trial'; PayloadCount = 1169; DestinationPolicyLength = 11; HasAppUserModelID = $false; Silent = $true }
    @{ Fixture = 'SetupFactory-10.2.0-trial.exe'; Builder = '10.2.0.0'; Major = 10; Product = 'Setup Factory 10 Trial'; PayloadCount = 1258; DestinationPolicyLength = 11; HasAppUserModelID = $true; Silent = $true }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Fixture)
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared Setup Factory builder fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.ParserVersionInfo.ProfileId | Should -Be 'setup-factory-8-plus'
    $Info.ParserVersionInfo.FormatGeneration | Should -Be 'Modern8Plus'
    $Info.ParserVersionInfo.BuilderVersion | Should -Be $Builder
    $Info.ParserVersionInfo.MajorVersion | Should -Be $Major
    $Info.ParserVersionInfo.EmbeddedRuntimeVersion | Should -Be $Builder
    $Info.EmbeddedRuntimeInfo.IsTrusted | Should -BeTrue
    $Info.EmbeddedRuntimeInfo.IsProfileCompatible | Should -BeTrue
    $Info.DisplayName | Should -Be $Product
    $Info.PayloadCatalog.Count | Should -Be $PayloadCount
    $Info.InstalledFileCatalog.DestinationPolicyLength | Should -Be $DestinationPolicyLength
    $Info.InstalledFileCatalog.HasAppUserModelID | Should -Be $HasAppUserModelID
    $Info.Diagnostics.Id | Should -Not -Contain 'SetupFactory.Release.StructuralProfileMismatch'
    [regex]::Matches($Info.PayloadCatalog[0].SourcePath, ':').Count | Should -Be 1
    $Info.PayloadCatalog[0].LastWriteTime | Should -BeOfType [datetime]
    $Info.PayloadCatalog[0].Policy.OverwritePolicy | Should -BeExactly 'Older'
    $Info.PayloadCatalog[0].Policy.BuildConfigurations | Should -Be @('Trial')
    $Info.PayloadCatalog[0].Policy.PackageSelector | Should -BeExactly 'None'
    $Info.PayloadCatalog[0].Policy.ForcedAttributes | Should -Be 0
    if ($HasAppUserModelID) {
      $Info.PayloadCatalog[0].Policy.AppUserModelID | Should -BeExactly ''
      $Info.PayloadCatalog[0].Policy.StartScreenPinning | Should -BeFalse
    } else {
      $Info.PayloadCatalog[0].Policy.AppUserModelID | Should -BeNullOrEmpty
    }
    $Info.CanExpand | Should -BeTrue
    $Info.SupportsSilentInstallation | Should -Be $Silent
    $Info.InstallModes | Should -Be ($Silent ? @('interactive', 'silent') : @('interactive'))
    if ($Silent) { $Info.InstallerSwitches.Silent | Should -Be '/S' }
    else { $Info.Diagnostics.Id | Should -Contain 'SetupFactory.Installability.SilentDisabled' }
  }

  It 'decodes the full Setup Factory 4 conclusion object without fabricating disabled ARP metadata' {
    $Fixture = 'SetupFactory-4-inst95.exe'
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Fixture)
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared historical Setup Factory fixture is not available'; return }
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1

    $Overlay = & $Module { param($InstallerPath) Get-SetupFactoryOverlayInfo -Path $InstallerPath } $Path

    $Overlay.ProfileId | Should -Be 'setup-factory-4'
    $Overlay.FormatGeneration | Should -Be 'Classic4'
    $Overlay.IsSupported | Should -BeTrue
    $Overlay.SupportsMetadata | Should -BeTrue
    Test-SetupFactory -Path $Path | Should -BeTrue
    $Info = Get-SetupFactoryInfo -Path $Path
    $Info.ContainerEntries.Name | Should -Contain 'irsetup.dat'
    $Info.PayloadCatalog.Count | Should -Be 1
    $Info.CanExpand | Should -BeTrue
    $Info.ParserVersionInfo.MetadataProfile | Should -BeExactly 'Classic4-Object24'
    $Info.UninstallConfiguration.Offset | Should -Be 0x90
    $Info.UninstallConfiguration.IncludeUninstall | Should -BeFalse
    $Info.UninstallConfiguration.ControlPanelDescription | Should -BeExactly 'My Application'
    $Info.UninstallConfiguration.UniqueRegistryKey | Should -BeExactly 'MyApp'
    $Info.Diagnostics.Id | Should -Not -Contain 'SetupFactory.Metadata.LegacyProductBlockIncomplete'
    $Info.Diagnostics.Id | Should -Contain 'SetupFactory.Metadata.Classic4ProductFieldsUnavailable'
    $Info.PayloadCatalog[0].Policy.LegacyPolicySchema | Should -Be 0
    $Info.PayloadCatalog[0].Policy.LegacyVersionWords | Should -HaveCount 4
    $Info.PayloadCatalog[0].Policy.OverwritePolicy | Should -BeExactly 'AskUser'
    $Info.PayloadCatalog[0].Policy.ShortcutHotKey | Should -Be 0x1000
    $Info.PayloadCatalog[0].Policy.RegisterWithDllRegisterServer | Should -BeNullOrEmpty
    $Info.Diagnostics.Id | Should -Contain 'SetupFactory.Installability.FileOverwritePrompt'
    $Info.UnresolvedFields | Should -Not -Contain 'InstallationMetadata.FilePolicy'
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
    $Info.AppsAndFeaturesEntries | Should -BeNullOrEmpty
    $Info.RegistryWrites | Should -BeNullOrEmpty
  }

  It 'decodes Setup Factory 5 and 6 product and built-in uninstall metadata' -ForEach @(
    @{ Fixture = 'SetupFactory-5-ttally11.exe'; ProfileId = 'setup-factory-5'; Generation = 'Legacy5'; MetadataRoute = 'irdat-v5'; PayloadCount = 4; DisplayName = 'Text Tally 1.1'; DisplayVersion = '1.1'; Publisher = 'Harmony Hollow Software'; ProductCode = 'Text Tally 1.1'; DefaultInstallLocation = 'C:\Program Files\TxtTally'; SupportsSilent = $false; OverwritePolicy = 'AskUser'; AskUserCount = 4; ConditionalCount = 0 }
    @{ Fixture = 'SetupFactory-6-suf60ev.exe'; ProfileId = 'setup-factory-6'; Generation = 'Legacy6'; MetadataRoute = 'irdat-v6'; PayloadCount = 791; DisplayName = 'Setup Factory 6.0 Demo'; DisplayVersion = '6.0.1.2'; Publisher = 'Indigo Rose Corporation'; ProductCode = 'Setup Factory 6.0 Demo'; DefaultInstallLocation = '%ProgramFiles%\Setup Factory 6.0 Demo'; SupportsSilent = $true; OverwritePolicy = 'SameOrOlder'; AskUserCount = 0; ConditionalCount = 5 }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Fixture)
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared historical Setup Factory fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.ParserVersionInfo.ProfileId | Should -Be $ProfileId
    $Info.ParserVersionInfo.FormatGeneration | Should -Be $Generation
    $Info.ParserVersionInfo.MetadataRoute | Should -Be $MetadataRoute
    $Info.PayloadCatalog.Count | Should -Be $PayloadCount
    $Info.DisplayName | Should -Be $DisplayName
    $Info.DisplayVersion | Should -Be $DisplayVersion
    $Info.Publisher | Should -Be $Publisher
    $Info.ProductCode | Should -Be $ProductCode
    $Info.Scope | Should -Be 'machine'
    $Info.DefaultInstallLocation | Should -Be $DefaultInstallLocation
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.AppsAndFeaturesEntries | Should -HaveCount 1
    $Info.AppsAndFeaturesEntries[0].ProductCode | Should -Be $ProductCode
    $Info.UninstallConfiguration.IncludeUninstall | Should -BeTrue
    $Info.PayloadCatalog[0].Policy.OverwritePolicy | Should -BeExactly $OverwritePolicy
    if ($ProfileId -eq 'setup-factory-5') {
      $Info.PayloadCatalog[0].Policy.LegacyOperatingSystemMask | Should -Be ([uint32]::MaxValue)
      $Info.PayloadCatalog[0].Policy.LegacyOperatingSystemPolicy.EvaluatedMask | Should -Be 0x7F
      $Info.PayloadCatalog[0].Policy.LegacyOperatingSystemPolicy.IgnoredMask | Should -Be ([uint32]4294967168)
      $Info.PayloadCatalog[0].Policy.LegacyOperatingSystemPolicy.AcceptsEveryKnownOperatingSystem | Should -BeTrue
      $Info.PayloadCatalog[0].Policy.LegacyOperatingSystemPolicy.Targets | Should -HaveCount 7
      $Info.PayloadCatalog[0].Policy.LegacyLanguageCondition | Should -Be 0
      $Info.PayloadCatalog[0].Policy.LegacyAdvancedConditions | Should -BeNullOrEmpty
      $Info.UnresolvedFields | Should -Not -Contain 'InstallationMetadata.FilePolicy'
    }
    $Info.FilePolicySummary.AskUserOverwriteEntries | Should -HaveCount $AskUserCount
    $Info.FilePolicySummary.ConditionalEntries | Should -HaveCount $ConditionalCount
    if ($AskUserCount) { $Info.Diagnostics.Id | Should -Contain 'SetupFactory.Installability.FileOverwritePrompt' }
    if ($ConditionalCount) {
      $Info.Diagnostics.Id | Should -Contain 'SetupFactory.Metadata.ConditionalInstalledFiles'
      $Info.UnresolvedFields | Should -Contain 'InstallationMetadata.Files'
    }
    $Info.UnresolvedFields | Should -Not -Contain 'ProductCode'
    $Info.SupportsSilentInstallation | Should -Be $SupportsSilent
    $Info.InstallModes | Should -Be ($SupportsSilent ? @('interactive', 'silent') : @('interactive'))
    if ($SupportsSilent) {
      $Info.InstallerSwitches.Silent | Should -Be '/S'
      $Info.Diagnostics.Id | Should -Not -Contain 'SetupFactory.Installability.SilentUnsupportedByGeneration'
    } else {
      $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'Silent'
      $Info.Diagnostics.Id | Should -Contain 'SetupFactory.Installability.SilentUnsupportedByGeneration'
    }
    $Info.Diagnostics.Id | Should -Not -Contain 'SetupFactory.Installability.SilentSupportUnresolved'
    $Info.UnresolvedFields | Should -Not -Contain 'InstallerSwitches'
  }

  It 'decodes legacy product settings when optional password data is absent and preserves a disabled uninstaller' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Metadata = & $Module {
      $Bytes = [Collections.Generic.List[byte]]::new()
      $Bytes.AddRange([byte[]]::new(64))
      $Bytes.Add(0)
      foreach ($Value in 'Control Panel Name', 'Product.Key') {
        $Encoded = [Text.Encoding]::UTF8.GetBytes($Value)
        $Bytes.Add([byte]$Encoded.Length)
        $Bytes.AddRange($Encoded)
      }
      $Bytes.Add(0)
      foreach ($Value in 'Uninstall Product', '', '%AppDir%\irunin.ini') {
        $Encoded = [Text.Encoding]::UTF8.GetBytes($Value)
        $Bytes.Add([byte]$Encoded.Length)
        $Bytes.AddRange($Encoded)
        if ($Value -eq 'Uninstall Product') { $Bytes.Add(0) }
      }
      $Bytes.AddRange([byte[]]::new(32))
      foreach ($Value in 'Product', 'Publisher', 'Tagline', '1.2.3', 'Copyright', 'https://example.invalid', '%ProgramFiles%\Product', 'Product') {
        $Encoded = [Text.Encoding]::UTF8.GetBytes($Value)
        $Bytes.Add([byte]$Encoded.Length)
        $Bytes.AddRange($Encoded)
      }
      $Bytes.AddRange([byte[]](0, 3, 1))
      $Log = [Text.Encoding]::UTF8.GetBytes('%AppDir%\setuplog.txt')
      $Bytes.Add([byte]$Log.Length)
      $Bytes.AddRange($Log)
      $Bytes.AddRange([byte[]]::new(32))
      $Bytes.AddRange([Text.Encoding]::ASCII.GetBytes('CImageInfo'))

      Get-SetupFactoryLegacyMetadata -Bytes $Bytes.ToArray()
    }

    $Metadata.Product.ProductName | Should -Be 'Product'
    $Metadata.Product.ProductVersion | Should -Be '1.2.3'
    $Metadata.Uninstall.IncludeUninstall | Should -BeFalse
    $Metadata.Uninstall.UniqueRegistryKey | Should -Be 'Product.Key'
  }

  It 'extracts a compressed-flagged empty file from Setup Factory 5 media' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SetupFactory-5.0.1.6-builder.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The Setup Factory 5 builder fixture is not available'; return }
    $Destination = Join-Path $TestDrive 'setup-factory-5-empty'

    $File = Expand-SetupFactoryInstaller -Path $Path -DestinationPath $Destination -Name 'data.001' -CollisionAction Error

    $File.Name | Should -Be 'data.001'
    $File.Length | Should -Be 0
  }

  It 'extracts and verifies compressed files from the supplied Setup Factory 7 and 8 builders' -ForEach @(
    @{ Fixture = 'SetupFactory-7.0.6.1-builder.exe'; Destination = 'setup-factory-7-compressed' }
    @{ Fixture = 'SetupFactory-8.1.1008.0-builder.exe'; Destination = 'setup-factory-8-compressed' }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Fixture)
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The supplied Setup Factory builder fixture is not available'; return }

    $File = Expand-SetupFactoryInstaller -Path $Path -DestinationPath (Join-Path $TestDrive $Destination) -Name 'Data\Importers\suf60_import.xml' -CollisionAction Error

    $File.Length | Should -Be 146
    (Get-FileHash -LiteralPath $File.FullName).Hash | Should -Be 'F7828D53576E9B447C38ECF69231B0FB41AAF5E8322CFD5C81A39A60B25D2978'
  }

  It 'recognizes official historical builder installers with changing runtime resources' -ForEach @(
    @{ Fixture = 'SetupFactory-4.0-builder.exe'; ProfileId = 'setup-factory-4'; Builder = '4.0.0.0'; Embedded = '4.0.0.8'; RuntimeProduct = 'Indigo Rose Corporation Setup'; RuntimeFile = 'setup.exe'; ContainerCount = 11; PayloadCount = 54; Product = 'Setup Factory 4.0 Evaluation'; ProductCode = 'SetupFactory4Demo' }
    @{ Fixture = 'SetupFactory-5.0.1.6-builder.exe'; ProfileId = 'setup-factory-5'; Builder = '5.0.1.6'; Embedded = '5.0.1.6'; RuntimeProduct = 'Setup Factory 5.0 Runtime Module setup32'; RuntimeFile = 'setup32.exe'; ContainerCount = 5; PayloadCount = 141; Product = 'Setup Factory 5.0'; ProductCode = 'Setup_Factory_5_EV' }
    @{ Fixture = 'SetupFactory-6.0.1.4-builder.exe'; ProfileId = 'setup-factory-6'; Builder = '6.0.1.4'; Embedded = '6.0.1.4'; RuntimeProduct = 'Setup Factory 6.0 Runtime Module'; RuntimeFile = 'SUF60Runtime.exe'; ContainerCount = 5; PayloadCount = 923; Product = 'Setup Factory 6.0 Demo'; ProductCode = 'Setup Factory 6.0 Demo' }
    @{ Fixture = 'SetupFactory-7.0.6.1-builder.exe'; ProfileId = 'setup-factory-7'; Builder = '7.0.6.1'; Embedded = '7.0.6.1'; RuntimeProduct = 'Setup Factory 7.0 Runtime'; RuntimeFile = 'suf70_rt.exe'; ContainerCount = 5; PayloadCount = 933; Product = 'Setup Factory 7.0 Trial'; ProductCode = $null }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Fixture)
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The Internet Archive builder fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.ParserVersionInfo.ProfileId | Should -Be $ProfileId
    $Info.ParserVersionInfo.BuilderVersion | Should -Be $Builder
    $Info.ParserVersionInfo.EmbeddedRuntimeVersion | Should -Be $Embedded
    $Info.EmbeddedRuntimeInfo.ProductName | Should -BeExactly $RuntimeProduct
    $Info.EmbeddedRuntimeInfo.OriginalFilename | Should -BeExactly $RuntimeFile
    $Info.EmbeddedRuntimeInfo.IsTrusted | Should -BeTrue
    $Info.EmbeddedRuntimeInfo.IsProfileCompatible | Should -BeTrue
    $Info.ContainerEntries.Count | Should -Be $ContainerCount
    $Info.ContainerEntries.Name | Should -Contain 'irsetup.dat'
    $Info.PayloadCatalog.Count | Should -Be $PayloadCount
    if ($ProductCode) {
      $Info.DisplayName | Should -Be $Product
      $Info.ProductCode | Should -Be $ProductCode
      $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    } else {
      $Info.DisplayName | Should -Be $Product
      $Info.ProductCode | Should -BeNullOrEmpty
    }
  }

  It 'walks the Setup Factory 4 global objects to the built-in ARP identity' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SetupFactory-4.0-builder.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The Internet Archive Setup Factory 4 fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.ProductMetadata.SetupTitle | Should -BeExactly 'Setup'
    $Info.UninstallConfiguration.Offset | Should -Be 0xED
    $Info.ParserVersionInfo.MetadataProfile | Should -BeExactly 'Classic4-Scalar32'
    $Info.UninstallConfiguration.IncludeUninstall | Should -BeTrue
    $Info.UninstallConfiguration.ControlPanelDescription | Should -BeExactly 'Setup Factory 4.0 Evaluation'
    $Info.UninstallConfiguration.UniqueRegistryKey | Should -BeExactly 'SetupFactory4Demo'
    $Info.DisplayName | Should -BeExactly 'Setup Factory 4.0 Evaluation'
    $Info.ProductCode | Should -BeExactly 'SetupFactory4Demo'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.SupportsSilentInstallation | Should -BeFalse
    $Info.InstallModes | Should -Be @('interactive')
    $Info.InstallerSwitches.PSObject.Properties.Name | Should -Not -Contain 'Silent'
    $Info.Diagnostics.Id | Should -Contain 'SetupFactory.Installability.SilentUnsupportedByGeneration'
    $Info.UnresolvedFields | Should -Not -Contain 'ProductCode'
    $Info.UnresolvedFields | Should -Not -Contain 'InstallerSwitches'
    $Info.Diagnostics.Id | Should -Not -Contain 'SetupFactory.Metadata.LegacyIrsetupDatPartial'
  }

  It 'projects Setup Factory 4 INI actions from the official builder media' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SetupFactory-4.0-builder.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The Internet Archive Setup Factory 4 fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.LegacyActionCatalog.IsComplete | Should -BeTrue
    $Info.IniActions | Should -HaveCount 2
    $Info.ActionEffects.UnknownActions | Should -HaveCount 0
    $Info.IniActions[0].ActionName | Should -BeExactly 'SetValue'
    $Info.IniActions[0].FileName | Should -BeExactly '%AppDir%\irunin.ini'
    $Info.IniActions[0].Section | Should -BeExactly 'Files'
    $Info.IniActions[0].Key | Should -BeExactly 'File1'
    $Info.IniActions[0].Value | Should -BeExactly '%AppDir%\suf40-32.gid'
    $Info.IniActions[0].Phase | Should -BeExactly 'Uninstall'
    $Info.IniActions[0].ConditionState | Should -BeExactly 'True'
    $Info.Diagnostics.Id | Should -Not -Contain 'SetupFactory.Metadata.LegacyActionsPartial'
  }

  It 'decodes the Setup Factory 4 MFC registry list with its generation-specific enums' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Catalog = & $Module {
      $Stream = [IO.MemoryStream]::new()
      $Writer = [IO.BinaryWriter]::new($Stream, [Text.Encoding]::ASCII, $true)
      $WriteString = {
        param ([string]$Value)
        $Encoded = [Text.Encoding]::ASCII.GetBytes($Value)
        $Writer.Write([byte]$Encoded.Length)
        $Writer.Write($Encoded)
      }
      try {
        $Writer.Write([uint16]2)
        $Writer.Write([uint16]0xFFFF)
        $Writer.Write([uint16]1)
        $Writer.Write([uint16]13)
        $Writer.Write([Text.Encoding]::ASCII.GetBytes('CRegistryData'))
        $Writer.Write([byte]2)
        $Writer.Write([byte]2)
        & $WriteString 'Software\Example'
        $Writer.Write([byte]1)
        & $WriteString 'InstallPath'
        & $WriteString '%AppDir%'
        $Writer.Write([uint16]0x8001)
        $Writer.Write([byte]2)
        $Writer.Write([byte]1)
        & $WriteString 'Software\Example'
        $Writer.Write([byte]0)
        & $WriteString 'Enabled'
        & $WriteString '1'
        $Writer.Flush()
        Get-SetupFactoryRegistryCatalog4 -Bytes $Stream.ToArray()
      } finally {
        $Writer.Dispose()
        $Stream.Dispose()
      }
    }

    $Catalog.IsComplete | Should -BeTrue
    $Catalog.DeclaredCount | Should -Be 2
    $Catalog.RegistryWrites | Should -HaveCount 2
    $Catalog.RegistryWrites[0].Root | Should -BeExactly 'HKLM'
    $Catalog.RegistryWrites[0].Type | Should -BeExactly 'REG_SZ'
    $Catalog.RegistryWrites[1].Root | Should -BeExactly 'HKCU'
    $Catalog.RegistryWrites[1].Type | Should -BeExactly 'REG_DWORD'
  }

  It 'decodes the counted Setup Factory 5 CRegistryData table' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SetupFactory-5.0.1.6-builder.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The Internet Archive Setup Factory 5 fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.LegacyActionCatalog.IsComplete | Should -BeTrue
    $Info.LegacyActionCatalog.RegistryCatalog.DeclaredCount | Should -Be 4
    $Info.LegacyActionCatalog.RegistryCatalog.Entries | Should -HaveCount 4
    $Info.RegistryWrites | Should -HaveCount 4
    $Info.RegistryWrites[0].Root | Should -BeExactly 'HKCU'
    $Info.RegistryWrites[0].Key | Should -BeExactly 'Software\Indigo Rose\Setup Factory 5.0'
    $Info.RegistryWrites[0].Name | Should -BeExactly 'InstallPath'
    $Info.RegistryWrites[0].Value | Should -BeExactly '%AppDir%'
    $Info.RegistryWrites[0].Type | Should -BeExactly 'REG_SZ'
    $Info.RegistryWrites[3].Type | Should -BeExactly 'REG_DWORD'
    $Info.Diagnostics.Id | Should -Not -Contain 'SetupFactory.Metadata.LegacyRegistryActionsPartial'
  }

  It 'projects Setup Factory 5 execution, file, and registry-variable records from the official builder media' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SetupFactory-5.0.1.6-builder.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The Internet Archive Setup Factory 5 fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.LegacyActionCatalog.IsComplete | Should -BeTrue
    $Info.LegacyActionCatalog.DeclaredCount | Should -Be 15
    $Info.ExecutionActions | Should -HaveCount 2
    $Info.FileSystemActions | Should -HaveCount 6
    $Info.VariableReads | Should -HaveCount 3
    $Info.ActionEffects.UnknownActions | Should -HaveCount 0

    $Info.ExecutionActions[0].ActionName | Should -BeExactly 'OpenDocument'
    $Info.ExecutionActions[0].Target | Should -BeExactly '%AppDir%\readme.txt'
    $Info.ExecutionActions[0].Phase | Should -BeExactly 'Shutdown'
    $Info.ExecutionActions[0].ConditionState | Should -BeExactly 'Unknown'
    $Info.ExecutionActions[0].Conditions[0].LeftOperand | Should -BeExactly '%ViewReadme%'
    $Info.ExecutionActions[0].Conditions[0].RightOperand | Should -BeExactly 'Checked'
    $Info.ExecutionActions[1].ActionName | Should -BeExactly 'ExecuteProgram'
    $Info.ExecutionActions[1].Target | Should -BeExactly '%AppDir%\builder.exe'
    $Info.ExecutionActions[1].Arguments | Should -BeExactly '%AppDir%'
    $Info.ExecutionActions[1].WorkingDirectory | Should -BeExactly ''
    $Info.ExecutionActions[1].Conditions[0].Type | Should -Be 0x8097

    $Info.FileSystemActions[0].ActionName | Should -BeExactly 'Delete'
    $Info.FileSystemActions[0].Source | Should -BeExactly '%AppDir%\builder.gid'
    $Info.FileSystemActions[0].Phase | Should -BeExactly 'Uninstall'
    $Info.FileSystemActions[0].SuppressErrors | Should -BeTrue
    $Info.FileSystemActions[-1].ActionName | Should -BeExactly 'RemoveDirectory'
    $Info.FileSystemActions[-1].Source | Should -BeExactly '%AppDir%\Update'

    $Info.VariableReads[0].VariableName | Should -BeExactly '%RegInstallPath%'
    $Info.VariableReads[0].Root | Should -BeExactly 'HKCU'
    $Info.VariableReads[0].Key | Should -BeExactly 'Software\Indigo Rose\Setup Factory 5.0'
    $Info.VariableReads[0].ValueName | Should -BeExactly 'InstallPath'
    $Info.VariableReads[0].DefaultValue | Should -BeExactly '%ProgramFiles%\%ProductName% Demo'
    $Info.Diagnostics.Id | Should -Not -Contain 'SetupFactory.Metadata.LegacyActionsPartial'
  }

  It 'continues past Setup Factory 5 registry records with advanced conditions' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Catalog = & $Module {
      $Stream = [IO.MemoryStream]::new()
      $Writer = [IO.BinaryWriter]::new($Stream, [Text.Encoding]::ASCII, $true)
      $WriteVariableString = {
        param ([string]$Value)
        $Encoded = [Text.Encoding]::ASCII.GetBytes($Value)
        $Writer.Write([byte]$Encoded.Length)
        $Writer.Write($Encoded)
      }
      $WriteRegistryRecord = {
        param ([string]$Name, [int]$ConditionCount)
        $Writer.Write([byte]2)
        $Writer.Write([byte]3)
        & $WriteVariableString 'Software\Example'
        & $WriteVariableString $Name
        $Writer.Write([byte]1)
        & $WriteVariableString 'Value'
        $Writer.Write([byte]0)
        & $WriteVariableString ''
        $Writer.Write([byte]0)
        $Writer.Write([uint32]::MaxValue)
        $Writer.Write([uint32]0)
        & $WriteVariableString 'None'
        $Writer.Write([uint16]$ConditionCount)
        if ($ConditionCount) {
          $Writer.Write([uint16]0xFFFF)
          $Writer.Write([uint16]1)
          $ConditionClass = [Text.Encoding]::ASCII.GetBytes('CConditionData')
          $Writer.Write([uint16]$ConditionClass.Length)
          $Writer.Write($ConditionClass)
          & $WriteVariableString '%ProductVer%'
          & $WriteVariableString '1.0'
          $Writer.Write([uint32]0)
          $Writer.Write([uint32]0)
          $Writer.Write([uint32]0)
          & $WriteVariableString ''
          & $WriteVariableString ''
        }
        foreach ($Value in 0..3) { $Writer.Write([uint32]0) }
        foreach ($Value in 0..3) { & $WriteVariableString '' }
      }
      try {
        $Writer.Write([uint16]2)
        $Writer.Write([uint16]0xFFFF)
        $Writer.Write([uint16]1)
        $RegistryClass = [Text.Encoding]::ASCII.GetBytes('CRegistryData')
        $Writer.Write([uint16]$RegistryClass.Length)
        $Writer.Write($RegistryClass)
        & $WriteRegistryRecord 'Conditional' 1
        $Writer.Write([uint16]0x8001)
        & $WriteRegistryRecord 'Unconditional' 0
        $Writer.Flush()
        Get-SetupFactoryRegistryCatalog5 -Bytes $Stream.ToArray() -UninstallOffset ([long]::MaxValue)
      } finally {
        $Writer.Dispose()
        $Stream.Dispose()
      }
    }

    $Catalog.IsComplete | Should -BeTrue
    $Catalog.Entries | Should -HaveCount 2
    $Catalog.Entries[0].Conditions | Should -HaveCount 1
    $Catalog.Entries[0].Conditions[0].OperatorName | Should -BeExactly 'Equals'
    $Catalog.Entries[0].ConditionState | Should -BeExactly 'Unknown'
    $Catalog.RegistryWrites | Should -HaveCount 1
    $Catalog.RegistryWrites[0].Name | Should -BeExactly 'Unconditional'
    $Catalog.UnresolvedCount | Should -Be 1
  }

  It 'decodes Setup Factory 6 action lists and excludes false and uninstall registry branches' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SetupFactory-6.0.1.4-builder.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The Internet Archive Setup Factory 6 fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.LegacyActionCatalog.IsComplete | Should -BeTrue
    $Info.LegacyActionCatalog.Groups.Phase | Should -Be @('Startup', 'BeforeInstalling', 'AfterInstalling', 'Shutdown', 'Uninstall')
    $Info.LegacyActionCatalog.Entries | Should -HaveCount 136
    $Info.RegistryWrites | Should -HaveCount 2
    $Info.RegistryWrites.Name | Should -Be @('InstallDir', 'SCFolder')
    $Info.RegistryWrites.Key | Should -Not -Contain 'Software\Indigo Rose\Setup Factory 6.0\Registration'
    $Info.RegistryWrites.Name | Should -Not -Contain 'My Value'
    $Info.RegistryWrites.ConditionState | Should -Be @('True', 'True')
    $Info.Diagnostics.Id | Should -Not -Contain 'SetupFactory.Metadata.RegistryActionsUnresolved'
    @($Info.LegacyActionCatalog.Entries | Where-Object { -not $_.ActionName }) | Should -HaveCount 0
    $Info.LegacyActionCatalog.UnresolvedControlFlowCount | Should -Be 1
    $Info.VariableAssignments | Should -HaveCount 19
    $Info.ExecutionActions | Should -HaveCount 4
    $Info.UserInteractionActions | Should -HaveCount 1
    $Info.InstallabilityActions | Should -HaveCount 1
    $Info.ActionEffects.UnknownActions | Should -HaveCount 0

    $ExecuteAction = $Info.ExecutionActions | Where-Object ActionName -CEQ Execute | Select-Object -First 1
    $ExecuteAction.Details.FilePath | Should -BeExactly '%AppDir%\SUF60Design.exe'
    $ExecuteAction.Details.WorkingDirectory | Should -BeExactly '%AppDir%'
    $ExecuteAction.Details.WaitForReturn | Should -BeFalse
    $ExecuteAction.ConditionState | Should -BeExactly 'Unknown'

    $FirstAssignment = $Info.VariableAssignments | Select-Object -First 1
    $FirstAssignment.ActionName | Should -BeExactly 'Assign Value'
    $FirstAssignment.Details.VariableName | Should -BeExactly '%SUF30Found%'
    $FirstAssignment.Details.Value | Should -BeExactly 'FALSE'
    $FirstAssignment.ConditionState | Should -BeExactly 'False'
    $Info.Diagnostics.Id | Should -Contain 'SetupFactory.Installability.ExecutionActions'
    $Info.Diagnostics.Id | Should -Contain 'SetupFactory.Installability.RuntimeActions'
    $Info.Diagnostics.Id | Should -Contain 'SetupFactory.Metadata.ActionControlFlowUnresolved'
  }

  It 'routes a legacy catalog when the application replaces the runtime product version' {
    $Source = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SetupFactory-5.0.1.6-builder.exe')
    if (-not (Test-Path -LiteralPath $Source)) { Set-ItResult -Skipped -Because 'The Internet Archive Setup Factory 5 fixture is not available'; return }
    $Path = Join-Path $TestDrive 'custom-version.exe'
    $Bytes = [IO.File]::ReadAllBytes($Source)
    foreach ($Encoding in [Text.Encoding]::ASCII, [Text.Encoding]::Unicode) {
      $Pattern = $Encoding.GetBytes('5.0.1.6')
      $Replacement = $Encoding.GetBytes('custom!!')
      foreach ($Offset in @(Find-BinaryPattern -Bytes $Bytes -Pattern $Pattern)) {
        [Array]::Copy($Replacement, 0, $Bytes, $Offset, $Replacement.Length)
      }
    }
    [IO.File]::WriteAllBytes($Path, $Bytes)

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.ParserVersionInfo.ProfileId | Should -Be 'setup-factory-5'
    $Info.ParserVersionInfo.OuterRuntimeVersion | Should -BeNullOrEmpty
    $Info.ParserVersionInfo.BuilderVersion | Should -Be '5.0.1.6'
    $Info.ParserVersionInfo.BuilderVersionSource | Should -Be 'EmbeddedRuntimeVersionResource'
    $Info.ParserVersionInfo.EmbeddedRuntimeVersion | Should -Be '5.0.1.6'
    $Info.ContainerEntries.Name | Should -Contain 'irsetup.dat'
  }

  It 'rejects a valid PE truncated after a Setup Factory signature' {
    $Source = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SetupFactory-10.2.0-trial.exe')
    if (-not (Test-Path -LiteralPath $Source)) { Set-ItResult -Skipped -Because 'The Setup Factory 10 fixture is not available'; return }
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Overlay = & $Module { param($InstallerPath) Get-SetupFactoryOverlayInfo -Path $InstallerPath } $Source
    $Path = Join-Path $TestDrive 'marker-only.exe'
    $InputStream = [IO.File]::OpenRead($Source)
    $OutputStream = [IO.File]::Create($Path)
    try {
      $null = Copy-BoundedStream -Source $InputStream -Destination $OutputStream -MaximumBytes ($Overlay.Offset + 16) -ExpectedBytes ($Overlay.Offset + 16)
    } finally {
      $OutputStream.Dispose()
      $InputStream.Dispose()
    }

    Test-SetupFactory -Path $Path | Should -BeFalse
    { Get-SetupFactoryInfo -Path $Path } | Should -Throw
  }

  It 'rejects a malformed Setup Factory-like input without hanging' {
    $Path = Join-Path $TestDrive 'malformed.exe'
    [IO.File]::WriteAllBytes($Path, [byte[]](0x4D, 0x5A, 0, 0))
    { Get-SetupFactoryInfo -Path $Path } | Should -Throw
  }
}
