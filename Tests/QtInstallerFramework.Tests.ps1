BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Compression.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'PE.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'RegistryAssociations.psm1') -Force
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
