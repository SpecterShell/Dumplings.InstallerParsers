BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  $LibraryPath = Join-Path $PSScriptRoot '..\Libraries'
  foreach ($ModuleName in @('Runtime', 'Binary', 'Compression', 'Archive', 'PE', 'RegistryAssociations', 'Inno')) {
    Import-Module (Join-Path $LibraryPath "$ModuleName.psm1") -Force
  }

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
}

Describe 'Inno parser' {
  It 'Reads chunked metadata into one non-enumerated byte array' {
    InModuleScope Inno {
      $Payload = [byte[]]::new(5000)
      for ($Index = 0; $Index -lt $Payload.Length; $Index++) { $Payload[$Index] = [byte]($Index % 251) }
      $EncodedStream = [System.IO.MemoryStream]::new()
      $EncodedWriter = [System.IO.BinaryWriter]::new($EncodedStream)
      try {
        $EncodedWriter.Write([uint32](Get-BinaryCrc32 -Bytes $Payload -Offset 0 -Count 4096))
        $EncodedWriter.Write($Payload, 0, 4096)
        $EncodedWriter.Write([uint32](Get-BinaryCrc32 -Bytes $Payload -Offset 4096 -Count 904))
        $EncodedWriter.Write($Payload, 4096, 904)
        $StoredBytes = $EncodedStream.ToArray()
      } finally {
        $EncodedWriter.Dispose()
        $EncodedStream.Dispose()
      }
      $Stream = [System.IO.MemoryStream]::new($StoredBytes, $false)
      $Reader = [System.IO.BinaryReader]::new($Stream)
      try {
        $Result = Read-InnoCompressedBlock -Reader $Reader -BlockHeader ([pscustomobject]@{
            HeaderOffset = -9
            HeaderLength = 5
            StoredSize   = $StoredBytes.Length
            Compressed   = $false
          })
        $Result.Bytes.GetType() | Should -Be ([byte[]])
        $Result.Bytes | Should -HaveCount $Payload.Length
        (Test-BinarySequence -Left $Result.Bytes -Right $Payload) | Should -BeTrue
      } finally {
        $Reader.Dispose()
        $Stream.Dispose()
      }
    }
  }

  It 'Should use source-backed header layouts at every supported format transition' {
    InModuleScope Inno {
      $Cases = @(
        @{ Version = 5310; Strings = 26; Privilege = 138; Override = $null; Architecture = 142; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; LocationSize = 74; Digest = 'SHA1'; StartSize = 4 }
        @{ Version = 5500; Strings = 27; Privilege = 138; Override = $null; Architecture = 142; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; LocationSize = 74; Digest = 'SHA1'; StartSize = 4 }
        @{ Version = 5506; Strings = 28; Privilege = 138; Override = $null; Architecture = 142; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; LocationSize = 74; Digest = 'SHA1'; StartSize = 4 }
        @{ Version = 5507; Strings = 28; Privilege = 135; Override = $null; Architecture = 139; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; LocationSize = 74; Digest = 'SHA1'; StartSize = 4 }
        @{ Version = 6000; Strings = 30; Privilege = 144; Override = 145; Architecture = 149; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; LocationSize = 74; Digest = 'SHA1'; StartSize = 4 }
        @{ Version = 6300; Strings = 32; Privilege = 144; Override = 145; Architecture = $null; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; LocationSize = 75; Digest = 'SHA1'; StartSize = 4 }
        @{ Version = 6402; Strings = 33; Privilege = 156; Override = 157; Architecture = $null; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; LocationSize = 87; Digest = 'SHA256'; StartSize = 4 }
        @{ Version = 6403; Strings = 33; Privilege = 156; Override = 157; Architecture = $null; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; LocationSize = 85; Digest = 'SHA256'; StartSize = 4 }
        @{ Version = 6500; Strings = 34; Privilege = 112; Override = 113; Architecture = $null; Int64 = $false; FileStrings = 15; FileAnsiStrings = 1; LocationSize = 85; Digest = 'SHA256'; StartSize = 4 }
        @{ Version = 6502; Strings = 34; Privilege = 120; Override = 121; Architecture = $null; Int64 = $false; FileStrings = 15; FileAnsiStrings = 1; LocationSize = 89; Digest = 'SHA256'; StartSize = 8 }
        @{ Version = 6600; Strings = 34; Privilege = 128; Override = 129; Architecture = $null; Int64 = $false; FileStrings = 15; FileAnsiStrings = 1; LocationSize = 89; Digest = 'SHA256'; StartSize = 8 }
        @{ Version = 6601; Strings = 34; Privilege = 129; Override = 130; Architecture = $null; Int64 = $false; FileStrings = 15; FileAnsiStrings = 1; LocationSize = 89; Digest = 'SHA256'; StartSize = 8 }
        @{ Version = 6700; Strings = 39; Privilege = 139; Override = 140; Architecture = $null; Int64 = $true; FileStrings = 15; FileAnsiStrings = 1; LocationSize = 89; Digest = 'SHA256'; StartSize = 8 }
        @{ Version = 7000; Strings = 39; Privilege = 143; Override = 144; Architecture = $null; Int64 = $true; FileStrings = 15; FileAnsiStrings = 1; LocationSize = 89; Digest = 'SHA256'; StartSize = 8 }
      )

      foreach ($Case in $Cases) {
        $Layout = Get-InnoLayout -VersionNumber $Case.Version -UnicodeVariant $true
        $Layout.HeaderStringCount | Should -Be $Case.Strings
        $Layout.PrivilegesRequiredOffset | Should -Be $Case.Privilege
        $Layout.PrivilegesRequiredOverridesAllowedOffset | Should -Be $Case.Override
        $Layout.ArchitecturesAllowedOffset | Should -Be $Case.Architecture
        $Layout.UsesInt64BlockHeader | Should -Be $Case.Int64
        $Layout.FileEntryStringCount | Should -Be $Case.FileStrings
        $Layout.FileEntryAnsiStringCount | Should -Be $Case.FileAnsiStrings
        $Layout.FileLocationEntrySize | Should -Be $Case.LocationSize
        $Layout.FileLocationDigestAlgorithm | Should -Be $Case.Digest
        $Layout.FileLocationStartOffsetSize | Should -Be $Case.StartSize
      }

      $AnsiLayout = Get-InnoLayout -VersionNumber 5500 -UnicodeVariant $false
      $AnsiLayout.PrivilegesRequiredOffset | Should -Be 170
      $AnsiLayout.ArchitecturesAllowedOffset | Should -Be 174
    }
  }

  It 'Should read source-backed legacy scope and packed architecture fields' {
    InModuleScope Inno {
      function New-TestInnoHeader {
        param(
          [pscustomobject]$Layout,
          [byte]$Privilege,
          [byte]$Override,
          [byte]$Allowed,
          [byte]$Install64
        )

        $StringBytes = [byte[]]::new(($Layout.HeaderStringCount + $Layout.HeaderAnsiStringCount) * 4)
        $Offsets = @(
          $Layout.PrivilegesRequiredOffset
          $Layout.PrivilegesRequiredOverridesAllowedOffset
          $Layout.ArchitecturesAllowedOffset
          $Layout.ArchitecturesInstallIn64BitModeOffset
          $Layout.CompressMethodOffset
        ) | Where-Object { $null -ne $_ }
        $Tail = [byte[]]::new((($Offsets | Measure-Object -Maximum).Maximum) + 1)
        $Tail[$Layout.PrivilegesRequiredOffset] = $Privilege
        if ($null -ne $Layout.PrivilegesRequiredOverridesAllowedOffset) { $Tail[$Layout.PrivilegesRequiredOverridesAllowedOffset] = $Override }
        if ($null -ne $Layout.ArchitecturesAllowedOffset) { $Tail[$Layout.ArchitecturesAllowedOffset] = $Allowed }
        if ($null -ne $Layout.ArchitecturesInstallIn64BitModeOffset) { $Tail[$Layout.ArchitecturesInstallIn64BitModeOffset] = $Install64 }
        $Tail[$Layout.CompressMethodOffset] = 4
        return [byte[]]($StringBytes + $Tail)
      }

      $LegacyLayout = Get-InnoLayout -VersionNumber 5310 -UnicodeVariant $true
      $LegacyFixed = Read-InnoHeaderFixedData -Bytes (New-TestInnoHeader -Layout $LegacyLayout -Privilege 2 -Override 0 -Allowed 4 -Install64 4) -Layout $LegacyLayout
      $LegacyHeaderValues = [string[]]::new(26)
      for ($Index = 0; $Index -lt $LegacyHeaderValues.Count; $Index++) { $LegacyHeaderValues[$Index] = '' }
      $LegacyArchitecture = Get-InnoHeaderArchitectureData -HeaderValues $LegacyHeaderValues -PEInfo ([pscustomobject]@{ Architecture = 'x86' }) -HeaderFixedData $LegacyFixed -Layout $LegacyLayout

      $LegacyFixed.PrivilegesRequired | Should -Be 'admin'
      $LegacyFixed.PrivilegesRequiredOverridesAllowed | Should -BeNullOrEmpty
      $LegacyFixed.CompressMethod | Should -Be 'Lzma2'
      $LegacyArchitecture.SupportedArchitectures | Should -Be @('x64')
      $LegacyArchitecture.UnsupportedArchitectures | Should -Be @('x86', 'arm64')
      $LegacyArchitecture.InstallIn64BitMode | Should -BeTrue

      $Version6Layout = Get-InnoLayout -VersionNumber 6000 -UnicodeVariant $true
      $Version6Fixed = Read-InnoHeaderFixedData -Bytes (New-TestInnoHeader -Layout $Version6Layout -Privilege 3 -Override 1 -Allowed 16 -Install64 16) -Layout $Version6Layout
      $Version6HeaderValues = [string[]]::new(30)
      for ($Index = 0; $Index -lt $Version6HeaderValues.Count; $Index++) { $Version6HeaderValues[$Index] = '' }
      $Version6Architecture = Get-InnoHeaderArchitectureData -HeaderValues $Version6HeaderValues -PEInfo ([pscustomobject]@{ Architecture = 'x86' }) -HeaderFixedData $Version6Fixed -Layout $Version6Layout

      $Version6Fixed.PrivilegesRequired | Should -Be 'lowest'
      $Version6Fixed.PrivilegesRequiredOverridesAllowed | Should -Be @('commandline')
      $Version6Fixed.CompressMethod | Should -Be 'Lzma2'
      $Version6Architecture.SupportedArchitectures | Should -Be @('arm64')
      $Version6Architecture.InstallIn64BitMode | Should -BeTrue
    }
  }

  It 'Should read only the requested file-location record as a scalar object' {
    InModuleScope Inno {
      $Layout = Get-InnoLayout -VersionNumber 7000 -UnicodeVariant $true
      $Bytes = [byte[]]::new($Layout.FileLocationEntrySize * 2)
      $Stream = [System.IO.MemoryStream]::new($Bytes, $true)
      $Writer = [System.IO.BinaryWriter]::new($Stream)
      try {
        $Writer.BaseStream.Position = $Layout.FileLocationEntrySize
        $Writer.Write([int]0)
        $Writer.Write([int]0)
        $Writer.Write([long]123)
        $Writer.Write([long]456)
        $Writer.Write([long]789)
        $Writer.Write([long]1000)
        $Writer.Write([byte[]]::new(32))
        $Writer.Write([byte[]]::new(8))
        $Writer.Write([uint32]0)
        $Writer.Write([uint32]0)
        $Writer.Write([byte]0x14)
      } finally {
        $Writer.Dispose()
        $Stream.Dispose()
      }

      $Location = Read-InnoFileLocation -Bytes $Bytes -Count 2 -Index 1 -Layout $Layout
      $Location -is [System.Array] | Should -BeFalse
      $Location.Index | Should -Be 1
      $Location.StartOffset | Should -Be 123
      $Location.ChunkSuboffset | Should -Be 456
      $Location.OriginalSize | Should -Be 789
      $Location.Flags.CallInstructionOptimized | Should -BeTrue
      $Location.Flags.ChunkCompressed | Should -BeTrue
    }
  }

  It 'Should reverse the Inno CALL transform without PowerShell byte-loop output' {
    InModuleScope Inno {
      $Bytes = [byte[]](0xE8, 0x05, 0x00, 0x00, 0x00, 0x90)
      $Output = @(Convert-InnoCallInstructions5309 -Bytes $Bytes)

      $Output | Should -BeNullOrEmpty
      $Bytes | Should -Be ([byte[]](0xE8, 0x00, 0x00, 0x00, 0x00, 0x90))
    }
  }

  It 'Should parse architecture expressions with the same token rules as Inno Setup' {
    InModuleScope Inno {
      Test-InnoArchitectureExpression -Expression 'x86 x64' -Architecture x64 | Should -BeTrue
      Test-InnoArchitectureExpression -Expression 'not not x64compatible' -Architecture x64 | Should -BeTrue
      Test-InnoArchitectureExpression -Expression 'x64compatible and not arm64' -Architecture arm64 | Should -BeFalse
      { Test-InnoArchitectureExpression -Expression 'x64 (x86)' -Architecture x64 } | Should -Throw
      { Test-InnoArchitectureExpression -Expression 'x64; x86' -Architecture x64 } | Should -Throw
      { Test-InnoArchitectureExpression -Expression '(x64' -Architecture x64 } | Should -Throw
      { Test-InnoArchitectureExpression -Expression 'futurearchitecture' -Architecture x64 } | Should -Throw '*Unknown Inno Setup architecture identifier*'
    }
  }

  It 'Should validate the exact Inno Setup 6.5 encryption header' {
    InModuleScope Inno {
      $Header = [byte[]]::new(49)
      $Header[0] = 1
      [System.BitConverter]::GetBytes([int]120000) | ForEach-Object -Begin { $Index = 17 } -Process { $Header[$Index++] = $_ }
      $Record = [System.BitConverter]::GetBytes((Get-InstallerCrc32 -Bytes $Header)) + $Header
      $Stream = [System.IO.MemoryStream]::new([byte[]]$Record, $false)
      $Reader = [System.IO.BinaryReader]::new($Stream)
      try {
        $Info = Read-InnoSetupEncryptionHeader -Reader $Reader -Offset 0 -FileLength $Stream.Length
        $Info.EncryptionUse | Should -Be 'Files'
        $Info.KDFIterations | Should -Be 120000
        $Info.NextOffset | Should -Be 53
      } finally {
        $Reader.Dispose()
        $Stream.Dispose()
      }

      $Header[0] = 2
      $FullRecord = [System.BitConverter]::GetBytes((Get-InstallerCrc32 -Bytes $Header)) + $Header
      $FullStream = [System.IO.MemoryStream]::new([byte[]]$FullRecord, $false)
      $FullReader = [System.IO.BinaryReader]::new($FullStream)
      try {
        (Read-InnoSetupEncryptionHeader -Reader $FullReader -Offset 0 -FileLength $FullStream.Length).EncryptionUse | Should -Be 'Full'
      } finally {
        $FullReader.Dispose()
        $FullStream.Dispose()
      }

      $FullRecord[4] = 1
      $BadStream = [System.IO.MemoryStream]::new([byte[]]$FullRecord, $false)
      $BadReader = [System.IO.BinaryReader]::new($BadStream)
      try {
        { Read-InnoSetupEncryptionHeader -Reader $BadReader -Offset 0 -FileLength $BadStream.Length } | Should -Throw '*CRC is invalid*'
      } finally {
        $BadReader.Dispose()
        $BadStream.Dispose()
      }
    }
  }

  It 'Should reject malformed and oversized compressed block headers before allocation' {
    InModuleScope Inno {
      foreach ($StoredSize in @([long]4, [long]($Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE + 1))) {
        $Header = [System.BitConverter]::GetBytes($StoredSize) + [byte]0
        $Record = [System.BitConverter]::GetBytes((Get-InstallerCrc32 -Bytes $Header)) + $Header
        $Stream = [System.IO.MemoryStream]::new([byte[]]$Record, $false)
        $Reader = [System.IO.BinaryReader]::new($Stream)
        try {
          Test-InnoCompressedBlockHeader -Reader $Reader -Offset 0 -UsesInt64BlockHeader $true -FileLength ([long]$Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE + 1024) |
            Should -BeNullOrEmpty
        } finally {
          $Reader.Dispose()
          $Stream.Dispose()
        }
      }
    }
  }

  It 'Should decode escaped literal braces and resolve the user Program Files constant' {
    InModuleScope Inno {
      ConvertFrom-InnoEscapedString -Value '{{A2CA08B5-C756-463E-B13D-F051F4F11F0B}' |
        Should -Be '{A2CA08B5-C756-463E-B13D-F051F4F11F0B}'
      Resolve-InnoDefaultDirectory -Value '{userpf}\Kiro' |
        Should -Be '%LocalAppData%\Programs\Kiro'
      Resolve-InnoDefaultDirectory -Value '{{userpf}\Literal' |
        Should -Be '{userpf}\Literal'
      Resolve-InnoDefaultDirectory -Value '{localappdata}\Product' |
        Should -Be '%LocalAppData%\Product'
      Resolve-InnoDefaultDirectory -Value '{usercf}\Product' |
        Should -Be '%LocalAppData%\Programs\Common\Product'
      Resolve-InnoDefaultDirectory -Value '{commonpf}\Product' -DefaultScope machine -InstallIn64BitMode $true |
        Should -Be '%ProgramFiles%\Product'
      Resolve-InnoDefaultDirectory -Value '{commonpf}\Product' -DefaultScope machine -InstallIn64BitMode $false |
        Should -Be '%ProgramFiles(x86)%\Product'
      Resolve-InnoDefaultDirectory -Value '{autopf}\Product' -DefaultScope user |
        Should -Be '%LocalAppData%\Programs\Product'
      Resolve-InnoDefaultDirectory -Value '{code:GetInstallPath}' |
        Should -BeNullOrEmpty
      ConvertFrom-InnoEscapedString -Value '{code:GetPath|{{literal}' |
        Should -Be '{code:GetPath|{{literal}'
      Get-InnoProductCode -AppId '{A2CA08B5-C756-463E-B13D-F051F4F11F0B}' |
        Should -Be '{A2CA08B5-C756-463E-B13D-F051F4F11F0B}_is1'
      Get-InnoProductCode -AppId 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' |
        Should -Be 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv~1fc2e6d2_is1'
    }
  }

  It 'Should read static metadata from the WinSCP installer' {
    $Fixture = Get-InstallerFixture -Name 'winscp-6.5.6-setup.exe' -Url 'https://sourceforge.net/projects/winscp/files/WinSCP/6.5.6/WinSCP-6.5.6-Setup.exe/download' -UseSourceForgeMetaRefresh
    $Info = Get-InnoInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Inno'
    $Info.DisplayName | Should -Be 'WinSCP 6.5.6'
    $Info.DisplayVersion | Should -Be '6.5.6'
    $Info.ProductCode | Should -Be 'winscp3_is1'
    $Info.PrivilegesRequired | Should -Be 'admin'
    $Info.PrivilegesRequiredOverridesAllowed | Should -Be @('commandline', 'dialog')
    $Info.DefaultScope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.EffectiveArchitecturesAllowed | Should -Be 'x86compatible'
    $Info.UnsupportedArchitectures | Should -BeNullOrEmpty
    $Info.CompressMethod | Should -Be 'Lzma2'
    $Info.ParserVersionInfo.FileLocationDigestAlgorithm | Should -Be 'SHA256'
    $Info.ParserVersionInfo.FileLocationStartOffsetSize | Should -Be 4
    Test-InnoAppsAndFeaturesEntry -Path $Fixture | Should -BeTrue
  }

  It 'Should parse the official Inno Setup 7 layout without inventing dynamic ARP metadata' {
    $Fixture = Get-InstallerFixture -Name 'innosetup-7.0.2-x64.exe' -Url 'https://github.com/jrsoftware/issrc/releases/download/is-7_0_2/innosetup-7.0.2-x64.exe'
    $Info = Get-InnoInfo -Path $Fixture

    $Info.Signature | Should -Be 'Inno Setup Setup Data (7.0.0.3)'
    $Info.DisplayVersion | Should -Be '7.0.2'
    $Info.PrivilegesRequired | Should -Be 'admin'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportedArchitectures | Should -Be @('x64', 'arm64')
    $Info.UnsupportedArchitectures | Should -Be @('x86')
    $Info.EncryptionUse | Should -Be 'None'
    $Info.CompressMethod | Should -Be 'Lzma2'
    $Info.WritesAppsAndFeaturesEntry | Should -BeNullOrEmpty
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.UnresolvedFields | Should -Contain 'ProductCode'
    $Info.ParserVersionInfo.HeaderStringCount | Should -Be 39
    $Info.ParserVersionInfo.FileEntryStringCount | Should -Be 15
    $Info.ParserVersionInfo.FileEntryAnsiStringCount | Should -Be 1
    $Info.ParserVersionInfo.FileLocationEntrySize | Should -Be 89
    $Info.ParserVersionInfo.FileLocationDigestAlgorithm | Should -Be 'SHA256'
    $Info.ParserVersionInfo.FileLocationStartOffsetSize | Should -Be 8
    $Info.ParserVersionInfo.UsesInt64BlockHeader | Should -BeTrue
    $Info.ParserVersionInfo.OffsetTableVersion | Should -Be 2
    $Info.Warnings | Should -Contain 'CreateUninstallRegKey or Uninstallable is a dynamic expression, so Apps & Features registration cannot be determined statically.'
  }

  It 'Should detect a default-user dual-scope Inno installer' {
    $Fixture = Get-InstallerFixture -Name 'loot_0.26.0-win64.exe' -Url 'https://github.com/loot/loot/releases/download/0.26.0/loot_0.26.0-win64.exe'
    $Info = Get-InnoInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Inno'
    $Info.DisplayName | Should -Be 'LOOT'
    $Info.DisplayVersion | Should -Be '0.26.0'
    $Info.ProductCode | Should -Be '{BF634210-A0D4-443F-A657-0DCE38040374}_is1'
    $Info.RawAppId | Should -Be '{{BF634210-A0D4-443F-A657-0DCE38040374}'
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

  It 'Should normalize the Kiro AppId and user Program Files location' {
    $Fixture = Get-InstallerFixture -Name 'kiro-ide-1.0.138-stable-win32-x64.exe' -Url 'https://prod.download.desktop.kiro.dev/releases/stable/win32-x64/signed/1.0.138/kiro-ide-1.0.138-stable-win32-x64.exe'
    $Info = Get-InnoInfo -Path $Fixture

    $Info.ProductCode | Should -Be '{A2CA08B5-C756-463E-B13D-F051F4F11F0B}_is1'
    $Info.AppId | Should -Be '{A2CA08B5-C756-463E-B13D-F051F4F11F0B}'
    $Info.RawAppId | Should -Be '{{A2CA08B5-C756-463E-B13D-F051F4F11F0B}'
    $Info.DefaultInstallLocation | Should -Be '%LocalAppData%\Programs\Kiro'
    $Info.RawDefaultDirName | Should -Be '{userpf}\Kiro'
    $Info.Scope | Should -Be 'user'
  }

  It 'Should normalize the Qoder AppId' {
    $Fixture = Get-InstallerFixture -Name 'QoderUserSetup-1.14.1-x64.exe' -Url 'https://qoder-ide.oss-accelerate.aliyuncs.com/release/1.14.1/QoderUserSetup-x64.exe'
    $Info = Get-InnoInfo -Path $Fixture

    $Info.ProductCode | Should -Be '{943D6004-554E-4B49-A1D5-52F999A1B3C9}_is1'
    $Info.RawAppId | Should -Be '{{943D6004-554E-4B49-A1D5-52F999A1B3C9}'
  }

  It 'Should not treat a legacy Inno installer without command-line privilege overrides as dual-scope' {
    $Fixture = Get-InstallerFixture -Name 'BankLinkBooks.exe' -Url 'https://download.myob.com/BankLinkBooks.exe'
    $Info = Get-InnoInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Inno'
    $Info.PrivilegesRequired | Should -Be 'admin'
    $Info.DefaultScope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be @('machine')
    $Info.SupportsDualScope | Should -BeFalse
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.PackedArchitecturesAllowed | Should -Be 0
    $Info.SupportedArchitectures | Should -Be @('x86', 'x64', 'arm64')
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

      $HeaderValues[24] = '{code:ShouldCreateUninstallKey}'
      $HeaderValues[25] = 'yes'
      $Dynamic = Get-InnoAppsAndFeaturesEntryInfo -HeaderValues $HeaderValues -VersionNumber 6500

      [pscustomobject]@{
        NoRegistryKey   = $NoRegistryKey.WritesAppsAndFeaturesEntry
        NoUninstaller   = $NoUninstaller.WritesAppsAndFeaturesEntry
        Default         = $Default.WritesAppsAndFeaturesEntry
        Dynamic         = $Dynamic.WritesAppsAndFeaturesEntry
        DynamicResolved = $Dynamic.IsResolved
      }
    }

    $Result.NoRegistryKey | Should -BeFalse
    $Result.NoUninstaller | Should -BeFalse
    $Result.Default | Should -BeTrue
    $Result.Dynamic | Should -BeNullOrEmpty
    $Result.DynamicResolved | Should -BeFalse
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
    $Info.AppId | Should -Be 'Argente'
    $Info.ProductCode | Should -BeNullOrEmpty
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

  It 'Should extract and verify a Unicode Inno 6.5 payload' {
    $Fixture = Get-InstallerFixture -Name 'winscp-6.5.6-setup.exe' -Url 'https://sourceforge.net/projects/winscp/files/WinSCP/6.5.6/WinSCP-6.5.6-Setup.exe/download' -UseSourceForgeMetaRefresh
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'winscp-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = Expand-InnoInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'WinSCP.exe'
      $Extracted | Should -HaveCount 1
      (Get-FileHash -Path $Extracted[0].FullName -Algorithm SHA256).Hash |
        Should -Be '7493AFBA8559470CF39FEAC96B9A05D70530AA14F1A0172E44E878AF61BC7BFD'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract and verify an official Inno 7 payload' {
    $Fixture = Get-InstallerFixture -Name 'innosetup-7.0.2-x64.exe' -Url 'https://github.com/jrsoftware/issrc/releases/download/is-7_0_2/innosetup-7.0.2-x64.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'inno7-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = Expand-InnoInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'ISCC.exe'
      $Extracted | Should -HaveCount 1
      (Get-FileHash -Path $Extracted[0].FullName -Algorithm SHA256).Hash |
        Should -Be 'C925160C8686390A4420FF9C35DED0654E2B7D4B432B0BF18290B843FC2E5B12'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract and verify a large solid Inno payload at a nonzero chunk suboffset' {
    $Fixture = Get-InstallerFixture -Name 'kiro-ide-1.0.138-stable-win32-x64.exe' -Url 'https://prod.download.desktop.kiro.dev/releases/stable/win32-x64/signed/1.0.138/kiro-ide-1.0.138-stable-win32-x64.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'kiro-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = Expand-InnoInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'Kiro.exe'
      $Extracted | Should -HaveCount 1
      (Get-FileHash -Path $Extracted[0].FullName -Algorithm SHA256).Hash |
        Should -Be '488A91B53D17CA8B52E25F143197875AEF7DD50E1BD51BAD749F559C17F52AEC'
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
      $Info = Get-InnoInfo -Path $NestedInstaller.FullName
      $Info.Signature | Should -Be 'Inno Setup Setup Data (5.5.7)'
      $Info.PrivilegesRequired | Should -Be 'admin'
      $Info.CompressMethod | Should -Be 'Lzma2'
      $Extracted = Expand-InnoInstaller -Path $NestedInstaller.FullName -DestinationPath $ExpandedPath -Name 'VUSC.exe' -Language 'en'

      $Extracted | Should -HaveCount 1
      (Get-FileHash -Path $Extracted[0].FullName -Algorithm SHA256).Hash | Should -Be '021A05A497BBCE1EE604CC223E7BB813171F198B3B27AE3C90A50EBD0F6DFEAE'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
      Remove-Item -Path $ArchivePath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}
