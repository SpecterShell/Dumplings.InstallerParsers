. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InnoTestSetup.ps1')

Describe 'Inno structures and version handling' -Tag Unit {
  It 'Resolves every catalog row to a complete route descriptor' {
    InModuleScope Inno {
      $Script:InnoFormatCatalog.Formats.Count | Should -Be 104
      @($Script:InnoFormatCatalog.Formats.Id | Select-Object -Unique).Count | Should -Be 104
      $Script:InnoResolvedFormats.Count | Should -Be 104
      foreach ($Format in $Script:InnoFormatCatalog.Formats) {
        $Layout = $Script:InnoResolvedFormats[$Format.Id]
        $Layout.HeaderCountNames.Count | Should -BeGreaterThan 0
        $Layout.HeaderFields | Should -Not -BeNullOrEmpty
        $Layout.FileEntryFields.Count | Should -Be $Layout.FileEntryStringCount
        @($Layout.RecordFamilies.PSObject.Properties).Count | Should -Be 13
        foreach ($Family in $Layout.RecordFamilies.PSObject.Properties.Value) {
          $Family.Id | Should -Not -BeNullOrEmpty
          $Family.FixedSize | Should -BeGreaterOrEqual 0
          $Family.Fields.GetType().IsArray | Should -BeTrue
          $Family.AnsiFields.GetType().IsArray | Should -BeTrue
        }
        $Layout.FileEntryOptionsSize | Should -BeGreaterOrEqual 2
        $Layout.FileLocationEntrySize | Should -BeGreaterThan 0
        $Layout.FileLocationFlagNames.Count | Should -BeGreaterThan 0
        $Layout.LoaderRoute | Should -Not -BeNullOrEmpty
        $Layout.MetadataRoute | Should -Not -BeNullOrEmpty
        $Layout.RecordSchemaRoute | Should -Not -BeNullOrEmpty
        $Layout.PayloadRoute | Should -Not -BeNullOrEmpty
        if ($Layout.EditionId -eq 'official' -and $Layout.InternalStructureVersion -lt 4000) {
          $Layout.CompiledCodeStringIndex | Should -BeNullOrEmpty
        } elseif ($Layout.EditionId -in @('official', 'myinno', 'restools')) {
          $Layout.CompiledCodeStringIndex | Should -BeGreaterOrEqual 0
        }
        if ([int]$Layout.InternalStructureVersion -lt 4000) {
          $Layout.SupportsExternalDiskSlices | Should -BeFalse
          $Layout.SlicesPerDiskOffset | Should -BeNullOrEmpty
          $Layout.SlicesPerDiskDefault | Should -Be 1
        } else {
          $Layout.SupportsExternalDiskSlices | Should -BeTrue
          $Layout.SlicesPerDiskOffset | Should -BeGreaterOrEqual 0
          $Layout.SlicesPerDiskDefault | Should -BeNullOrEmpty
        }
      }
    }
  }

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

  It 'Projects literal file-extension and protocol associations from catalogued registry records' {
    InModuleScope Inno {
      $RegistryEntries = @(
        [pscustomobject]@{ RootKey = 'HKA'; Subkey = 'Software\Classes\.sample'; ValueName = ''; ValueData = 'Dumplings.Sample'; Conditional = $false }
        [pscustomobject]@{ RootKey = 'HKLM'; Subkey = 'Software\Classes\dumplings\shell\open\command'; ValueName = ''; ValueData = '"{app}\sample.exe" "%1"'; Conditional = $false }
        [pscustomobject]@{ RootKey = 'HKLM'; Subkey = 'Software\Classes\dumplings'; ValueName = 'URL Protocol'; ValueData = ''; Conditional = $false }
        [pscustomobject]@{ RootKey = 'HKCU'; Subkey = 'Software\Vendor\.ignored'; ValueName = ''; ValueData = 'Ignored'; Conditional = $false }
      )

      $Associations = Get-InnoRegistryAssociationInfo -RegistryEntries $RegistryEntries

      $Associations.FileExtensions | Should -Be @('sample')
      $Associations.Protocols | Should -Be @('dumplings')
    }
  }

  It 'Should use source-backed header layouts at every supported format transition' {
    InModuleScope Inno {
      $Cases = @(
        @{ Version = 5303; Strings = 24; Privilege = 134; Override = $null; Architecture = 138; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; FileVersionData = 20; FileTrailing = 0; FileOptions = 4; FileBitness = $false; LocationSize = 70; Digest = 'MD5'; StartSize = 4 }
        @{ Version = 5310; Strings = 26; Privilege = 138; Override = $null; Architecture = 142; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; FileVersionData = 20; FileTrailing = 0; FileOptions = 4; FileBitness = $false; LocationSize = 74; Digest = 'SHA1'; StartSize = 4 }
        @{ Version = 5500; Strings = 27; Privilege = 138; Override = $null; Architecture = 142; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; FileVersionData = 20; FileTrailing = 0; FileOptions = 4; FileBitness = $false; LocationSize = 74; Digest = 'SHA1'; StartSize = 4 }
        @{ Version = 5506; Strings = 28; Privilege = 138; Override = $null; Architecture = 142; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; FileVersionData = 20; FileTrailing = 0; FileOptions = 4; FileBitness = $false; LocationSize = 74; Digest = 'SHA1'; StartSize = 4 }
        @{ Version = 5507; Strings = 28; Privilege = 135; Override = $null; Architecture = 139; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; FileVersionData = 20; FileTrailing = 0; FileOptions = 4; FileBitness = $false; LocationSize = 74; Digest = 'SHA1'; StartSize = 4 }
        @{ Version = 6000; Strings = 30; Privilege = 144; Override = 145; Architecture = 149; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; FileVersionData = 20; FileTrailing = 0; FileOptions = 4; FileBitness = $false; LocationSize = 74; Digest = 'SHA1'; StartSize = 4 }
        @{ Version = 6300; Strings = 32; Privilege = 144; Override = 145; Architecture = $null; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; FileVersionData = 20; FileTrailing = 0; FileOptions = 4; FileBitness = $false; LocationSize = 75; Digest = 'SHA1'; StartSize = 4 }
        @{ Version = 6402; Strings = 33; Privilege = 156; Override = 157; Architecture = $null; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; FileVersionData = 20; FileTrailing = 0; FileOptions = 4; FileBitness = $false; LocationSize = 87; Digest = 'SHA256'; StartSize = 4 }
        @{ Version = 6403; Strings = 33; Privilege = 156; Override = 157; Architecture = $null; Int64 = $false; FileStrings = 10; FileAnsiStrings = 0; FileVersionData = 20; FileTrailing = 0; FileOptions = 4; FileBitness = $false; LocationSize = 85; Digest = 'SHA256'; StartSize = 4 }
        @{ Version = 6500; Strings = 34; Privilege = 112; Override = 113; Architecture = $null; Int64 = $false; FileStrings = 15; FileAnsiStrings = 1; FileVersionData = 20; FileTrailing = 0; FileOptions = 5; FileBitness = $false; LocationSize = 85; Digest = 'SHA256'; StartSize = 4 }
        @{ Version = 6502; Strings = 34; Privilege = 120; Override = 121; Architecture = $null; Int64 = $false; FileStrings = 15; FileAnsiStrings = 1; FileVersionData = 20; FileTrailing = 0; FileOptions = 5; FileBitness = $false; LocationSize = 89; Digest = 'SHA256'; StartSize = 8 }
        @{ Version = 6600; Strings = 34; Privilege = 128; Override = 129; Architecture = $null; Int64 = $false; FileStrings = 15; FileAnsiStrings = 1; FileVersionData = 20; FileTrailing = 0; FileOptions = 5; FileBitness = $false; LocationSize = 89; Digest = 'SHA256'; StartSize = 8 }
        @{ Version = 6601; Strings = 34; Privilege = 129; Override = 130; Architecture = $null; Int64 = $false; FileStrings = 15; FileAnsiStrings = 1; FileVersionData = 20; FileTrailing = 0; FileOptions = 5; FileBitness = $false; LocationSize = 89; Digest = 'SHA256'; StartSize = 8 }
        @{ Version = 6700; Strings = 39; Privilege = 139; Override = 140; Architecture = $null; Int64 = $true; FileStrings = 15; FileAnsiStrings = 1; FileVersionData = 20; FileTrailing = 0; FileOptions = 8; FileBitness = $false; LocationSize = 89; Digest = 'SHA256'; StartSize = 8 }
        @{ Version = 7000; Strings = 39; Privilege = 143; Override = 144; Architecture = $null; Int64 = $true; FileStrings = 15; FileAnsiStrings = 1; FileVersionData = 20; FileTrailing = 0; FileOptions = 8; FileBitness = $true; LocationSize = 89; Digest = 'SHA256'; StartSize = 8 }
      )

      foreach ($Case in $Cases) {
        $Layout = Get-TestInnoCatalogLayout -VersionNumber $Case.Version -UnicodeVariant $true
        $Layout.HeaderStringCount | Should -Be $Case.Strings
        $Layout.PrivilegesRequiredOffset | Should -Be $Case.Privilege
        $Layout.PrivilegesRequiredOverridesAllowedOffset | Should -Be $Case.Override
        $Layout.ArchitecturesAllowedOffset | Should -Be $Case.Architecture
        $Layout.UsesInt64BlockHeader | Should -Be $Case.Int64
        $Layout.FileEntryStringCount | Should -Be $Case.FileStrings
        $Layout.FileEntryAnsiStringCount | Should -Be $Case.FileAnsiStrings
        $Layout.FileEntryVersionDataSize | Should -Be $Case.FileVersionData
        $Layout.FileEntryTrailingSize | Should -Be $Case.FileTrailing
        $Layout.FileEntryOptionsSize | Should -Be $Case.FileOptions
        $Layout.FileEntryHasBitness | Should -Be $Case.FileBitness
        $Layout.FileLocationEntrySize | Should -Be $Case.LocationSize
        $Layout.FileLocationDigestAlgorithm | Should -Be $Case.Digest
        $Layout.FileLocationStartOffsetSize | Should -Be $Case.StartSize
      }

      $AnsiLayout = Get-TestInnoCatalogLayout -VersionNumber 5500 -UnicodeVariant $false
      $AnsiLayout.PrivilegesRequiredOffset | Should -Be 170
      $AnsiLayout.ArchitecturesAllowedOffset | Should -Be 174

      $Layout5303 = Get-TestInnoCatalogLayout -VersionNumber 5303 -UnicodeVariant $true
      $Layout5303.HeaderAnsiStringCount | Should -Be 5
      $Layout5303.LegacyHeaderOptionsOffset | Should -Be 150
      $Layout5303.LegacyCreateUninstallRegKeyOptionBit | Should -Be 15
      $Layout5303.LegacyUninstallableOptionBit | Should -Be 1
      $Layout5303.UsesLegacyCallInstructionTransform | Should -BeTrue

      $Layout5308 = Get-TestInnoCatalogLayout -VersionNumber 5308 -UnicodeVariant $true
      $Layout5308.HeaderStringCount | Should -Be 25
      $Layout5308.LegacyCreateUninstallRegKeyOptionBit | Should -BeNullOrEmpty
      $Layout5308.LegacyUninstallableOptionBit | Should -Be 1

      $Layout5309 = Get-TestInnoCatalogLayout -VersionNumber 5309 -UnicodeVariant $true
      $Layout5309.FileLocationDigestAlgorithm | Should -Be 'SHA1'
      $Layout5309.UsesLegacyCallInstructionTransform | Should -BeFalse
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
          [byte]$Install64,
          [byte]$Compression = 4,
          [byte[]]$HeaderOptions = @()
        )

        $StringBytes = [byte[]]::new(($Layout.HeaderStringCount + $Layout.HeaderAnsiStringCount) * 4)
        $Offsets = @(
          if ($null -ne $Layout.SlicesPerDiskOffset) {
            $Layout.SlicesPerDiskOffset + 3
          }
          $Layout.PrivilegesRequiredOffset
          $Layout.PrivilegesRequiredOverridesAllowedOffset
          $Layout.ArchitecturesAllowedOffset
          $Layout.ArchitecturesInstallIn64BitModeOffset
          $Layout.CompressMethodOffset
          if ($null -ne $Layout.LegacyHeaderOptionsOffset) {
            $Layout.LegacyHeaderOptionsOffset + $Layout.LegacyHeaderOptionsSize - 1
          }
        ) | Where-Object { $null -ne $_ }
        $Tail = [byte[]]::new((($Offsets | Measure-Object -Maximum).Maximum) + 1)
        if ($null -ne $Layout.SlicesPerDiskOffset) {
          [BitConverter]::GetBytes([int]1).CopyTo($Tail, $Layout.SlicesPerDiskOffset)
        }
        $Tail[$Layout.PrivilegesRequiredOffset] = $Privilege
        if ($null -ne $Layout.PrivilegesRequiredOverridesAllowedOffset) { $Tail[$Layout.PrivilegesRequiredOverridesAllowedOffset] = $Override }
        if ($null -ne $Layout.ArchitecturesAllowedOffset) { $Tail[$Layout.ArchitecturesAllowedOffset] = $Allowed }
        if ($null -ne $Layout.ArchitecturesInstallIn64BitModeOffset) { $Tail[$Layout.ArchitecturesInstallIn64BitModeOffset] = $Install64 }
        $Tail[$Layout.CompressMethodOffset] = $Compression
        if ($null -ne $Layout.LegacyHeaderOptionsOffset -and $HeaderOptions.Count -gt 0) {
          $HeaderOptions.CopyTo($Tail, $Layout.LegacyHeaderOptionsOffset)
        }
        return [byte[]]($StringBytes + $Tail)
      }

      $LegacyLayout = Get-TestInnoCatalogLayout -VersionNumber 5310 -UnicodeVariant $true
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

      $Version6Layout = Get-TestInnoCatalogLayout -VersionNumber 6000 -UnicodeVariant $true
      $Version6Fixed = Read-InnoHeaderFixedData -Bytes (New-TestInnoHeader -Layout $Version6Layout -Privilege 3 -Override 1 -Allowed 16 -Install64 16) -Layout $Version6Layout
      $Version6HeaderValues = [string[]]::new(30)
      for ($Index = 0; $Index -lt $Version6HeaderValues.Count; $Index++) { $Version6HeaderValues[$Index] = '' }
      $Version6Architecture = Get-InnoHeaderArchitectureData -HeaderValues $Version6HeaderValues -PEInfo ([pscustomobject]@{ Architecture = 'x86' }) -HeaderFixedData $Version6Fixed -Layout $Version6Layout

      $Version6Fixed.PrivilegesRequired | Should -Be 'lowest'
      $Version6Fixed.PrivilegesRequiredOverridesAllowed | Should -Be @('commandline')
      $Version6Fixed.CompressMethod | Should -Be 'Lzma2'
      $Version6Architecture.SupportedArchitectures | Should -Be @('arm64')
      $Version6Architecture.InstallIn64BitMode | Should -BeTrue

      $Version5303Layout = Get-TestInnoCatalogLayout -VersionNumber 5303 -UnicodeVariant $true
      $Version5303Bytes = New-TestInnoHeader -Layout $Version5303Layout -Privilege 2 -Override 0 -Allowed 0 -Install64 0 `
        -Compression 3 -HeaderOptions ([byte[]](0x02, 0x80, 0, 0, 0, 0))
      $Version5303Fixed = Read-InnoHeaderFixedData -Bytes $Version5303Bytes -Layout $Version5303Layout
      $Version5303Values = [string[]]::new(29)
      for ($Index = 0; $Index -lt $Version5303Values.Count; $Index++) { $Version5303Values[$Index] = '' }
      $Version5303Arp = Get-InnoAppsAndFeaturesEntryInfo -HeaderValues $Version5303Values -Layout $Version5303Layout -HeaderFixedData $Version5303Fixed

      $Version5303Fixed.PrivilegesRequired | Should -Be 'admin'
      $Version5303Fixed.CompressMethod | Should -Be 'Lzma'
      $Version5303Fixed.LegacyCreateUninstallRegKey | Should -BeTrue
      $Version5303Fixed.LegacyUninstallable | Should -BeTrue
      $Version5303Arp.WritesAppsAndFeaturesEntry | Should -BeTrue
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
}
