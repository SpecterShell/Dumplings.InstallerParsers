. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\NSISTestSetup.ps1')

Describe 'NSIS structure and command layouts' -Tag Unit {
  It 'Should render extraction strings with stable symbolic NSIS variables and shell folders' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      function ConvertTo-TestPackedNumber([int]$Value) {
        return [uint16](0x8080 -bor ($Value -band 0x7F) -bor (($Value -shr 7) -shl 8))
      }

      $Strings = [System.Collections.Generic.List[uint16]]::new()
      function Add-TestString([uint16[]]$Characters) {
        $Offset = $Strings.Count
        foreach ($Character in $Characters) { $Strings.Add($Character) }
        $Strings.Add(0)
        return $Offset
      }

      $PluginOffset = Add-TestString @(
        3, (ConvertTo-TestPackedNumber 26), [char]'\', [char]'p', [char]'l', [char]'u', [char]'g', [char]'i', [char]'n', [char]'.', [char]'d', [char]'l', [char]'l'
      )
      $RegisterOffset = Add-TestString @(
        3, (ConvertTo-TestPackedNumber 11), [char]'\', [char]'f', [char]'i', [char]'l', [char]'e'
      )
      $PrivateOffset = Add-TestString @(
        3, (ConvertTo-TestPackedNumber 49), [char]'\', [char]'f', [char]'i', [char]'l', [char]'e'
      )
      $ShellOffset = Add-TestString @(
        2, [uint16](37 -bor (37 -shl 8)), [char]'\', [char]'t', [char]'o', [char]'o', [char]'l', [char]'.', [char]'d', [char]'l', [char]'l'
      )
      $LanguageOffset = Add-TestString @(1, (ConvertTo-TestPackedNumber 62))
      $StringBytes = [byte[]]::new($Strings.Count * 2)
      [Buffer]::BlockCopy($Strings.ToArray(), 0, $StringBytes, 0, $StringBytes.Length)
      $State = [pscustomobject]@{
        StringsBlock = $StringBytes
        VersionInfo  = [pscustomobject]@{ Unicode = $true; IsV3 = $true; Type = 'NSIS3' }
      }

      [pscustomobject]@{
        Plugin   = Get-NSISSymbolicString -State $State -RelativeOffset $PluginOffset
        Register = Get-NSISSymbolicString -State $State -RelativeOffset $RegisterOffset
        Private  = Get-NSISSymbolicString -State $State -RelativeOffset $PrivateOffset
        Shell    = Get-NSISSymbolicString -State $State -RelativeOffset $ShellOffset
        Language = Get-NSISSymbolicString -State $State -RelativeOffset $LanguageOffset
      }
    }

    $Result.Plugin | Should -Be '$PLUGINSDIR\plugin.dll'
    $Result.Register | Should -Be '$R1\file'
    $Result.Private | Should -Be '$_17_\file'
    $Result.Shell | Should -Be '$SYSDIR\tool.dll'
    $Result.Language | Should -Be '$(LSTR_62)'
  }

  It 'Should reconstruct and safely project 7-Zip-style SetOutPath prefixes' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      [pscustomobject]@{
        InstallRoot = Get-NSISReducedArchivePath -SourcePath 'app.exe' -OutputPrefix '$INSTDIR'
        Nested      = Get-NSISReducedArchivePath -SourcePath 'tool.exe' -OutputPrefix '$INSTDIR\bin'
        Plugin      = Get-NSISReducedArchivePath -SourcePath '$PLUGINSDIR\System.dll' -OutputPrefix '$INSTDIR\bin'
        OutDir      = Resolve-NSISArchiveOutputPrefix -Path '$OUTDIR\child' -CurrentPrefix '$INSTDIR\bin' -SavedPrefix '$INSTDIR'
        SavedOutDir = Resolve-NSISArchiveOutputPrefix -Path '$_OUTDIR\restored' -CurrentPrefix '$TEMP' -SavedPrefix '$INSTDIR\saved'
        Drive       = ConvertTo-NSISExtractionRelativePath -Path 'C:\unsafe\payload.exe' -DataOffset 1
        Traversal   = ConvertTo-NSISExtractionRelativePath -Path '..\payload.exe' -DataOffset 2
      }
    }

    $Result.InstallRoot | Should -Be 'app.exe'
    $Result.Nested | Should -Be 'bin\tool.exe'
    $Result.Plugin | Should -Be '$PLUGINSDIR\System.dll'
    $Result.OutDir | Should -Be '$INSTDIR\bin\child'
    $Result.SavedOutDir | Should -Be '$INSTDIR\saved\restored'
    $Result.Drive | Should -Be 'payload.exe'
    $Result.Traversal | Should -Be '_\payload.exe'
  }

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

  It 'Should route compact NSISBI 3.12 external and split-file header fields' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $Compact = Get-NSISFirstHeaderFlagInfo -Flags ([uint32]0x70) -DataBlockLow 3 -DataBlockHigh 64
      $Legacy = Get-NSISFirstHeaderFlagInfo -Flags ([uint32]0x1F0) -DataBlockLow 0 -DataBlockHigh 0
      $Pre304 = Get-NSISFirstHeaderFlagInfo -Flags ([uint32]0) -DataBlockLow 31 -DataBlockHigh ([uint32]2147483648) -Pre304
      [pscustomobject]@{
        CompactRoute = $Compact.FlagRoute
        CompactCount = $Compact.ExternalFileCount
        CompactSize  = $Compact.ExternalSegmentSize
        CompactStub  = $Compact.IsStubInstaller
        LegacyRoute  = $Legacy.FlagRoute
        LegacyStub   = $Legacy.IsStubInstaller
        Pre304Route  = $Pre304.FlagRoute
        Pre304Length = $Pre304.DataBlockLength
        Pre304File   = $Pre304.HasExternalFile
      }
    }

    $Result.CompactRoute | Should -Be 'nsisbi-compact-3.12'
    $Result.CompactCount | Should -Be 3
    $Result.CompactSize | Should -Be 64MB
    $Result.CompactStub | Should -BeTrue
    $Result.LegacyRoute | Should -Be 'nsisbi-legacy'
    $Result.LegacyStub | Should -BeTrue
    $Result.Pre304Route | Should -Be 'nsisbi-pre-3.04.1'
    $Result.Pre304Length | Should -Be 31
    $Result.Pre304File | Should -BeTrue
  }

  It 'Should normalize NSISBI external payload opcodes without losing their source' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      [pscustomobject]@{
        File     = ConvertFrom-NSISBiOpcode -Opcode 20
        StubFile = ConvertFrom-NSISBiOpcode -Opcode 21
        Verify   = ConvertFrom-NSISBiOpcode -Opcode 22
        Delete   = ConvertFrom-NSISBiOpcode -Opcode 23
      }
    }

    $Result.File | Should -Be 20
    $Result.StubFile | Should -Be 1000
    $Result.Verify | Should -Be 1001
    $Result.Delete | Should -Be 21
  }

  It 'Should normalize source-backed NSIS command layouts' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      [pscustomobject]@{
        LogOpcode        = Get-NSISNormalizedOpcode -Opcode $Script:NSIS_OPCODE_SECTION_SET -Type 'NSIS3' -Unicode $true -LogCmdIsEnabled $true
        ShiftedSection   = Get-NSISNormalizedOpcode -Opcode ($Script:NSIS_OPCODE_SECTION_SET + 1) -Type 'NSIS3' -Unicode $true -LogCmdIsEnabled $true
        ParkFileWrite    = Get-NSISNormalizedOpcode -Opcode $Script:NSIS_OPCODE_FILE_SEEK -Type 'Park1' -Unicode $true -LogCmdIsEnabled $false
        Park2FontVersion = Get-NSISNormalizedOpcode -Opcode $Script:NSIS_OPCODE_REGISTER_DLL -Type 'Park2' -Unicode $true -LogCmdIsEnabled $false
        Park3FontName    = Get-NSISNormalizedOpcode -Opcode ($Script:NSIS_OPCODE_REGISTER_DLL + 1) -Type 'Park3' -Unicode $true -LogCmdIsEnabled $false
        RegEnum          = Get-NSISNormalizedOpcode -Opcode 53 -Type 'NSIS3' -Unicode $true -LogCmdIsEnabled $false
        NsisBiWriteReg   = ConvertFrom-NSISBiOpcode -Opcode 53
      }
    }

    $Result.LogOpcode | Should -Be 70
    $Result.ShiftedSection | Should -Be 63
    $Result.ParkFileWrite | Should -Be 68
    $Result.Park2FontVersion | Should -Be 72
    $Result.Park3FontName | Should -Be 73
    $Result.RegEnum | Should -Be 53
    $Result.NsisBiWriteReg | Should -Be 51
  }

  It 'Should reject tied command layouts only when their used opcode meanings differ' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      function New-TestCommandEntry([uint32]$Opcode) {
        [pscustomobject]@{
          LayoutOpcode = $Opcode
          RawOpcode    = $Opcode
          Raw          = [uint32[]]@($Opcode, 0, 0, 0, 0, 0, 0)
          Values       = [int[]]@([int]$Opcode, 0, 0, 0, 0, 0, 0)
        }
      }

      # A NUL-only Unicode string table provides no generation control codes.
      # Opcode 10 has the same meaning in every candidate, while opcode 44 is
      # RegisterDLL in official/Park1 and a font query in later Park layouts.
      $Strings = [byte[]](0, 0)
      $Equivalent = Get-NSISVersionInfo -StringsBlock $Strings -Entries @((New-TestCommandEntry 10))
      $Different = Get-NSISVersionInfo -StringsBlock $Strings -Entries @((New-TestCommandEntry 44))
      [pscustomobject]@{
        EquivalentAmbiguity  = $Equivalent.HasSemanticAmbiguity
        EquivalentConfidence = $Equivalent.DetectionConfidence
        DifferentAmbiguity   = $Different.HasSemanticAmbiguity
        DifferentConfidence  = $Different.DetectionConfidence
        DifferentSignatures  = @($Different.CandidateLayouts.SemanticSignature | Select-Object -Unique).Count
      }
    }

    $Result.EquivalentAmbiguity | Should -BeFalse
    $Result.EquivalentConfidence | Should -Be 'Ambiguous'
    $Result.DifferentAmbiguity | Should -BeTrue
    $Result.DifferentConfidence | Should -Be 'UnsupportedAmbiguous'
    $Result.DifferentSignatures | Should -BeGreaterThan 1
  }

  It 'Should resolve every catalogued NSIS edition and serialized-format route' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $Profiles = foreach ($Profile in $Script:NSISFormatCatalog.Profiles) {
        Get-NSISCatalogProfile -Id $Profile.Id
      }
      [pscustomobject]@{
        IsValid        = Test-NSISFormatCatalog
        ProfileCount   = @($Profiles).Count
        EditionIds     = @($Profiles.EditionId | Sort-Object -Unique)
        OpcodeRoutes   = @($Profiles.OpcodeRoute | Sort-Object -Unique)
        VariableRoutes = @($Profiles.VariableRoute | Sort-Object -Unique)
      }
    }

    $Result.IsValid | Should -BeTrue
    $Result.ProfileCount | Should -Be 10
    $Result.EditionIds | Should -Be @('nsisbi', 'official', 'park')
    $Result.OpcodeRoutes | Should -Be @('official', 'park1', 'park2', 'park3')
    $Result.VariableRoutes | Should -Be @('current', 'legacy-200', 'legacy-225')
  }

  It 'Should select legacy NSIS variable layouts from exact compiled command evidence' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      # ANSI NSIS 2 represents a variable-only string as 0xFD followed by a
      # packed 14-bit variable index and a NUL terminator.
      $Variable27 = [byte[]]@(0xFD, 0x9B, 0x80, 0x00)
      $Legacy200Entry = [pscustomobject]@{
        LayoutOpcode = $Script:NSIS_OPCODE_GET_DLG_ITEM
        Values       = [int[]]@($Script:NSIS_OPCODE_GET_DLG_ITEM, 29, 0, 0, 0, 0, 0)
      }
      $Legacy225Entry = [pscustomobject]@{
        LayoutOpcode = $Script:NSIS_OPCODE_GET_DLG_ITEM
        Values       = [int[]]@($Script:NSIS_OPCODE_GET_DLG_ITEM, 28, 0, 0, 0, 0, 0)
      }

      [pscustomobject]@{
        Legacy200 = (Get-NSISLegacyVariableProfileEvidence -StringsBlock $Variable27 -Entries @($Legacy200Entry)).VariableRoute
        Legacy225 = (Get-NSISLegacyVariableProfileEvidence -StringsBlock $Variable27 -Entries @($Legacy225Entry)).VariableRoute
        Current   = (Get-NSISLegacyVariableProfileEvidence -StringsBlock $Variable27 -Entries @()).VariableRoute
      }
    }

    $Result.Legacy200 | Should -Be 'legacy-200'
    $Result.Legacy225 | Should -Be 'legacy-225'
    $Result.Current | Should -Be 'current'
  }

  It 'Should report a catalogued NSIS 3 Unicode profile for a real installer' {
    $Fixture = Get-InstallerFixture -Name 'alist-desktop_3.60.0_x64-setup.exe' -Url 'https://github.com/AlistGo/desktop-release/releases/download/v3.60.0/alist-desktop_3.60.0_x64-setup.exe'
    $Result = Get-NSISFormatInfo -Path $Fixture

    $Result.EditionId | Should -Be 'official'
    $Result.Edition | Should -Be 'Nullsoft Scriptable Install System'
    $Result.Generation | Should -Be 'NSIS3'
    $Result.CharacterMode | Should -Be 'Unicode'
    $Result.CatalogProfileId | Should -Be 'official-nsis3-unicode'
    $Result.OpcodeRoute | Should -Be 'official'
    $Result.VariableRoute | Should -Be 'current'
    $Result.StubArchitecture | Should -Be 'x86'
    $Result.IsSupported | Should -BeTrue
  }

  It 'Should verify the stock archive CRC and reject corruption inside its source range' {
    $Fixture = Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'nsis204.exe') -Uri 'https://sourceforge.net/projects/nsis/files/NSIS%202/2.04/nsis204.exe/download' -Sha256 '967CC080B8CB1D5B750C324805F1687591761E91BE2EAFE1FC71677FF2DF03F3' -UseSourceForgeMetaRefresh
    $Info = Get-NSISFormatInfo -Path $Fixture
    $Info.ArchiveCrcStatus | Should -Be 'Valid'
    $Info.ArchiveCrcVerified | Should -BeTrue

    $CorruptPath = Join-Path $TestDrive 'nsis204-corrupt-crc.exe'
    Copy-Item -LiteralPath $Fixture -Destination $CorruptPath -Force
    try {
      $Stream = [IO.File]::Open($CorruptPath, 'Open', 'ReadWrite', 'None')
      try {
        $Stream.Position = 600
        $Original = $Stream.ReadByte()
        $Stream.Position = 600
        $Stream.WriteByte([byte]($Original -bxor 1))
      } finally { $Stream.Dispose() }

      { Get-NSISFormatInfo -Path $CorruptPath } | Should -Throw '*archive CRC32 does not match*'
    } finally {
      Remove-Item -LiteralPath $CorruptPath -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should select the log-enabled command layout from source-defined EW_LOG operands' {
    $Fixture = Resolve-NSISBuilderFixturePath -Version '2.46' -Scenario 'LogEnabled' -Name 'nsis-2.46-log-fixture.exe'
    if (-not (Test-Path -LiteralPath $Fixture)) {
      Set-ItResult -Skipped -Because 'The controlled NSIS 2.46 log-enabled fixture has not been built in the persistent fixture cache.'
      return
    }

    (Get-FileHash -LiteralPath $Fixture -Algorithm SHA256).Hash | Should -Be 'CFF450A72C150DA9B45583A09C4FCE0E31B01541122C336A27BE87CD3F268B0F'
    $Format = Get-NSISFormatInfo -Path $Fixture
    $Info = Get-NSISInfo -Path $Fixture

    $Format.CatalogProfileId | Should -Be 'official-nsis2-ansi'
    $Format.LogCommandEnabled | Should -BeTrue
    $Format.IsSupported | Should -BeTrue
    $Info.ProductCode | Should -Be 'Dumplings.NSIS246Log'
    $Info.DisplayName | Should -Be 'Dumplings NSIS 2.46 Log Fixture'
    $Info.ParserVersionInfo.LogCmdIsEnabled | Should -BeTrue
  }

  It 'Should distinguish log-enabled SectionSet records from non-log InstallTypeSet records' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      # SectionSetSize stores SECTION_FIELD_SET(size_kb) as -6 in offsets[2].
      # The same raw opcode would be EW_INSTTYPESET without the inserted log
      # slot, but that command accepts only operation selectors 0 and 1.
      $Entry = [pscustomobject]@{
        LayoutOpcode = [uint32]64
        Raw          = [uint32[]]@(64, 104, 3202, ([uint32]::MaxValue - 5), 0, 0, 0)
      }
      [pscustomobject]@{
        WithoutLog = Measure-NSISCommandLayoutCandidate -Entries @($Entry) -Type NSIS3 -Unicode $true -LogCmdIsEnabled $false
        WithLog    = Measure-NSISCommandLayoutCandidate -Entries @($Entry) -Type NSIS3 -Unicode $true -LogCmdIsEnabled $true
      }
    }

    $Result.WithoutLog.FatalInvalidCommandCount | Should -Be 1
    $Result.WithLog.FatalInvalidCommandCount | Should -Be 0
  }

  It 'Should use paired LockWindow operands to resolve the log-enabled command layout' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $Entries = @(
        [pscustomobject]@{ LayoutOpcode = [uint32]68; RawOpcode = [uint32]68; Raw = [uint32[]]@(68, 0, 0, 0, 0, 0, 0) }
        [pscustomobject]@{ LayoutOpcode = [uint32]68; RawOpcode = [uint32]68; Raw = [uint32[]]@(68, 1, 0, 0, 0, 0, 0) }
      )
      [pscustomobject]@{
        WithoutLog = Measure-NSISCommandLayoutCandidate -Entries $Entries -Type NSIS3 -Unicode $true -LogCmdIsEnabled $false
        WithLog    = Measure-NSISCommandLayoutCandidate -Entries $Entries -Type NSIS3 -Unicode $true -LogCmdIsEnabled $true
      }
    }

    $Result.WithoutLog.FatalInvalidCommandCount | Should -Be 0
    $Result.WithoutLog.SemanticPenalty | Should -Be 2
    $Result.WithLog.FatalInvalidCommandCount | Should -Be 0
    $Result.WithLog.SemanticPenalty | Should -Be 0
  }

  It 'Should retain opaque trailing vendor operands without making a recognized command fatal' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $Entry = [pscustomobject]@{
        LayoutOpcode = [uint32]$Script:NSIS_OPCODE_CREATE_DIR
        RawOpcode    = [uint32]$Script:NSIS_OPCODE_CREATE_DIR
        Raw          = [uint32[]]@($Script:NSIS_OPCODE_CREATE_DIR, 4864, 1, 0, 0, 0, 5626)
      }
      Measure-NSISCommandLayoutCandidate -Entries @($Entry) -Type NSIS3 -Unicode $true -LogCmdIsEnabled $true
    }

    $Result.FatalInvalidCommandCount | Should -Be 0
    $Result.IgnoredExtensionOperandCount | Should -Be 1
    $Result.IgnoredExtensionOperands[0].OperandIndexes | Should -Be 6
  }

  It 'Should parse Google Antigravity through its source-backed log-enabled command layout' {
    $Fixture = Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'Google-Antigravity-2.8.1-x64.exe') -Uri 'https://storage.googleapis.com/antigravity-public/antigravity-hub/2.8.1-6512087774658560/windows-x64/Antigravity-x64.exe' -Sha256 '05085047994932949BB6777765710CDC28ADB61C804851167995A3C285ACCA47'
    $Format = Get-NSISFormatInfo -Path $Fixture
    $Info = Get-NSISInfo -Path $Fixture

    $Format.CatalogProfileId | Should -Be 'official-nsis3-unicode'
    $Format.LogCommandEnabled | Should -BeTrue
    $Format.HasSemanticAmbiguity | Should -BeFalse
    $Format.IsSupported | Should -BeTrue
    $Info.ProductCode | Should -Be '121a0be4-63bd-531e-acf8-fc3924c7e984'
    $Info.DisplayName | Should -Be 'Antigravity 2.8.1'
  }

  It 'Should prefer stock raw-Deflate framing over an accidental legacy NSISBI header collision' {
    $Fixture = Get-DumplingsTestFixture -RelativePath 'Installers/NSIS/iQIYI.iQIYI/14.8.0.10198/IQIYIsetup_winget.exe' -Uri 'https://mesh.if.iqiyi.com/player/upgrade/file/14.8.0.10198/IQIYIsetup_winget.exe' -Sha256 'D5C1F2FF746B05A7B5ABE1C5E9E5BD736829162FE484B114B1FBAF8C7B1E1641'

    $Info = Get-NSISInfo -Path $Fixture
    $Format = $Info.ParserVersionInfo

    $Format.FirstHeaderFlagRoute | Should -Be 'standard'
    $Format.CompressionRoute | Should -Be 'Deflate'
    $Format.IsNsisBi | Should -BeFalse
    $Info.Warnings | Should -BeNullOrEmpty
    $Info.ProductCode | Should -Not -BeNullOrEmpty
  }

  It 'Should retain Tencent Video metadata without empty-INI binding failures or unbounded section walking' {
    $Fixture = Get-DumplingsTestFixture -RelativePath 'Installers/NSIS/Tencent.TencentVideo/11.180.7429.0/TencentVideo11.180.7429.0.exe' -Uri 'https://dldir1v6.qq.com/qqtv/TencentVideo11.180.7429.0.exe' -Sha256 '3FF27EE167CC4D28175D204BAEAE76E350535DF55EB216728FAAB35D3350D411'

    $Info = Get-NSISInfo -Path $Fixture -Architecture x86 -Scope machine

    $Info.ProductCode | Should -Be 'qqlive'
    $Info.Warnings | Should -Not -Match 'Cannot bind argument|execution budget'
    $Info.Notices | Should -Match 'Full section simulation was skipped'
  }

  It 'Should resolve paired LockWindow records in a vendor NSIS 3 Unicode installer' {
    $Fixture = Get-DumplingsTestFixture -RelativePath 'Installers/NSIS/NetEase.YoudaoPokeClass/2.18.9/YoudaoPokeClass-2.18.9.exe' -Uri 'https://codown.youdao.com/ke/pokeClass/2.18.9.0/YoudaoPokeClass-2.18.9.exe' -Sha256 '3C6F8A4D6FCC9023E9A4FD8D7D5A07059D372A4BBCCA452F8071F3F633CC0162'

    $Format = Get-NSISFormatInfo -Path $Fixture

    $Format.CatalogProfileId | Should -Be 'official-nsis3-unicode'
    $Format.LogCommandEnabled | Should -BeTrue
    $Format.FatalInvalidCommandCount | Should -Be 0
    $Format.HasSemanticAmbiguity | Should -BeFalse
  }

  It 'Should retain a vendor extension operand as nonfatal format evidence' {
    $Fixture = Get-DumplingsTestFixture -RelativePath 'Installers/NSIS/Tencent.Yuanbao/2.81.0/yuanbao_2.81.0.629_x64.exe' -Uri 'https://cdn-hybrid-prod.hunyuan.tencent.com/Desktop/official/b2640c59915a11b284a81d8d469c715d/yuanbao_2.81.0.629_x64.exe' -Sha256 'AB3DC14CDD2CB5EAF89B6A4CCC9EE268AF8AE5DDBDFAD84DD55DE7622FD44898'

    $Format = Get-NSISFormatInfo -Path $Fixture

    $Format.IsSupported | Should -BeTrue
    $Format.FatalInvalidCommandCount | Should -Be 0
    $Format.IgnoredExtensionOperandCount | Should -Be 1
    $Format.Notices | Should -Match 'vendor-extension operand'
  }

  It 'Should initialize CMDLINE with the quoted installer path for bounded runtime scans' {
    $Fixture = Get-DumplingsTestFixture -RelativePath 'Installers/NSIS/SonicWall.GlobalVPNClient/5.0.0.2008/GVCSetup-Win32_5.0.0.2008.exe' -Uri 'https://software.sonicwall.com/GlobalVPNClient/GVCSetup-Win32_5.0.0.2008.exe' -Sha256 'A5CA2B31C5B56D7DC616DFC7B1D3D3AB557363FEC4E207EEB6067AC4C34AFE14'

    $Info = Get-NSISInfo -Path $Fixture

    $Info.DisplayName | Should -Be 'Global VPN Client'
    $Info.DisplayVersion | Should -Be '5.0.0.2008'
    $Info.Warnings | Should -Not -Match 'execution budget'
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
        ProgramFiles   = ConvertTo-NSISManifestPath -Path '$PROGRAMFILES64\Process Lasso'
        ProgramFiles86 = ConvertTo-NSISManifestPath -Path '$PROGRAMFILES32\App'
        LocalAppData   = ConvertTo-NSISManifestPath -Path '$LOCALAPPDATA\Programs\App'
        RootOnly       = ConvertTo-NSISManifestPath -Path '$PROGRAMFILES64'
        NotAPrefix     = ConvertTo-NSISManifestPath -Path '$PROGRAMFILES64.exe'
        Unrelated      = ConvertTo-NSISManifestPath -Path 'D:\Custom\App'
      }
    }

    $Result.ProgramFiles | Should -Be '%ProgramFiles%\Process Lasso'
    $Result.ProgramFiles86 | Should -Be '%ProgramFiles(x86)%\App'
    $Result.LocalAppData | Should -Be '%LocalAppData%\Programs\App'
    $Result.RootOnly | Should -Be '%ProgramFiles%'
    $Result.NotAPrefix | Should -Be '$PROGRAMFILES64.exe'
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
