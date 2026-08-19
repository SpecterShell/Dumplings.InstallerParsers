. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\NSISTestSetup.ps1')

Describe 'NSIS compression and extraction' -Tag Unit {
  It 'Should decode bounded dictionary-backed LZ4 streams used by NSISBI MTW' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      Import-NSISLz4Decoder
      $First = [Text.Encoding]::ASCII.GetBytes('abcdefghijklmnop')
      $Expected = [Text.Encoding]::ASCII.GetBytes('abcdefghijklmnopabcdefghi12345')
      $Encoded = [Collections.Generic.List[byte]]::new()

      # First inner block: 16 literals, followed by the uint16 stream length.
      $Encoded.Add(18)
      $Encoded.Add(0)
      $Encoded.Add(0xF0)
      $Encoded.Add(1)
      $Encoded.AddRange($First)

      # Second block references nine bytes from the previous block's dictionary
      # and ends with five literals. A zero uint16 terminates the LZ4 stream.
      $Encoded.Add(9)
      $Encoded.Add(0)
      $Encoded.Add(0x05)
      $Encoded.Add(0x10)
      $Encoded.Add(0)
      $Encoded.Add(0x50)
      $Encoded.AddRange([Text.Encoding]::ASCII.GetBytes('12345'))
      $Encoded.Add(0)
      $Encoded.Add(0)

      $EncodedBytes = $Encoded.ToArray()
      $Decoded = [Dumplings.InstallerParsers.NSIS.NsisLz4BlockDecoder]::Decode($EncodedBytes, $Expected.Length)
      $Truncated = [byte[]]$EncodedBytes[0..($EncodedBytes.Length - 2)]
      $TruncatedError = {
        [Dumplings.InstallerParsers.NSIS.NsisLz4BlockDecoder]::Decode($Truncated, $Expected.Length)
      } | Should -Throw -PassThru
      [pscustomobject]@{
        Matches        = [Linq.Enumerable]::SequenceEqual([byte[]]$Expected, [byte[]]$Decoded)
        TruncatedError = [string]$TruncatedError
      }
    }

    $Result.Matches | Should -BeTrue
    $Result.TruncatedError | Should -Match 'end marker is missing|length is truncated'
  }

  It 'Should read NSISBI split sidecars as one seekable logical stream' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $SegmentDirectory = Join-Path $Script:FixtureDirectory 'nsisbi-segments'
    Remove-Item -LiteralPath $SegmentDirectory -Recurse -Force -ErrorAction SilentlyContinue
    $null = New-Item -Path $SegmentDirectory -ItemType Directory -Force
    try {
      $Result = & $Module {
        param($SegmentDirectory)
        $First = Join-Path $SegmentDirectory 'setup1.bin'
        $Second = Join-Path $SegmentDirectory 'setup2.bin'
        [IO.File]::WriteAllBytes($First, [Text.Encoding]::ASCII.GetBytes('first-'))
        [IO.File]::WriteAllBytes($Second, [Text.Encoding]::ASCII.GetBytes('second'))
        $Stream = New-NSISExternalDataStream -Path @($First, $Second)
        try {
          $Stream.Position = 4
          $Bytes = [byte[]]::new(8)
          $Read = $Stream.Read($Bytes, 0, $Bytes.Length)
          [pscustomobject]@{ Text = [Text.Encoding]::ASCII.GetString($Bytes, 0, $Read); Length = $Stream.Length }
        } finally { $Stream.Dispose() }
      } $SegmentDirectory

      $Result.Text | Should -Be 't-second'
      $Result.Length | Should -Be 12
    } finally {
      Remove-Item -LiteralPath $SegmentDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should honor an explicit ANSI source code page without using host defaults' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $Encoding = Get-NSISAnsiEncoding -LanguageId 1041 -CodePage 932
      [pscustomobject]@{ CodePage = $Encoding.CodePage; Text = $Encoding.GetString([byte[]](0x83, 0x65, 0x83, 0x58, 0x83, 0x67)) }
    }

    $Result.CodePage | Should -Be 932
    $Result.Text | Should -Be 'テスト'
  }

  It 'Should preserve multibyte ANSI literals in symbolic extraction paths' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      [Text.Encoding]::RegisterProvider([Text.CodePagesEncodingProvider]::Instance)
      $Encoding = [Text.Encoding]::GetEncoding(932)
      $Literal = $Encoding.GetBytes('テスト.exe')
      $Strings = [byte[]]::new($Literal.Length + 1)
      [Array]::Copy($Literal, $Strings, $Literal.Length)
      $State = [pscustomobject]@{
        StringsBlock = $Strings
        AnsiEncoding = $Encoding
        VersionInfo  = [pscustomobject]@{ Unicode = $false; IsV3 = $true; Type = 'NSIS3'; VariableRoute = 'current' }
      }
      Get-NSISSymbolicString -State $State -RelativeOffset 0
    }

    $Result | Should -Be 'テスト.exe'
  }

  It 'Should extract non-solid NSISBI sidecar records and enforce their CRC32' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Directory = Join-Path $Script:FixtureDirectory 'nsisbi-external-extraction'
    Remove-Item -LiteralPath $Directory -Recurse -Force -ErrorAction SilentlyContinue
    $null = New-Item -Path $Directory -ItemType Directory -Force
    try {
      $Result = & $Module {
        param($Directory)
        $Content = [Text.Encoding]::UTF8.GetBytes('external NSISBI payload')
        $Record = [byte[]]::new(4 + $Content.Length)
        [Array]::Copy([BitConverter]::GetBytes([uint32]$Content.Length), $Record, 4)
        [Array]::Copy($Content, 0, $Record, 4, $Content.Length)
        $HeaderData = [pscustomobject]@{ PackedSizeWidth = 4; Compression = 'Stored'; PayloadOffset = 0; CompressedHeaderSize = 0 }
        $OutputPath = Join-Path $Directory 'payload.bin'
        $Payload = [pscustomobject]@{
          DataOffset = [uint64]0; SourcePath = 'payload.bin'; OutputPath = $OutputPath
          TimeLow = [uint32]0; TimeHigh = [uint32]0; Crc32 = [uint32](Get-BinaryCrc32 -Bytes $Content)
        }
        $Stream = [IO.MemoryStream]::new($Record, $false)
        try { $Files = Expand-NSISNonSolidPayloads -Stream $Stream -HeaderData $HeaderData -Payload @($Payload) -MaximumExpandedBytes 1MB -DataBlockOffset 0 -DataBlockLength $Record.Length }
        finally { $Stream.Dispose() }

        $BadPath = Join-Path $Directory 'bad.bin'
        $Payload.OutputPath = $BadPath
        $Payload.Crc32 = [uint32]($Payload.Crc32 -bxor 1)
        $BadStream = [IO.MemoryStream]::new($Record, $false)
        try { $ErrorText = { Expand-NSISNonSolidPayloads -Stream $BadStream -HeaderData $HeaderData -Payload @($Payload) -MaximumExpandedBytes 1MB -DataBlockOffset 0 -DataBlockLength $Record.Length } | Should -Throw -PassThru }
        finally { $BadStream.Dispose() }

        [pscustomobject]@{
          Text          = [IO.File]::ReadAllText($Files[0].FullName)
          BadFileExists = Test-Path -LiteralPath $BadPath
          ErrorText     = [string]$ErrorText
        }
      } $Directory

      $Result.Text | Should -Be 'external NSISBI payload'
      $Result.BadFileExists | Should -BeFalse
      $Result.ErrorText | Should -Match 'CRC32 does not match'
    } finally {
      Remove-Item -LiteralPath $Directory -Recurse -Force -ErrorAction SilentlyContinue
    }
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

  It 'Should route the historical builder installer <Name> through <CatalogProfileId>' -ForEach @(
    @{
      Name             = 'nsis203.exe'
      Url              = 'https://sourceforge.net/projects/nsis/files/NSIS%202/2.03/nsis203.exe/download'
      Sha256           = 'E92B46158832393C98AC73DFC1CC95B35D453DCB40B7ABFCF1F0FB17B2F1786B'
      CatalogProfileId = 'official-legacy-200-ansi'
      EditionId        = 'official'
      CharacterMode    = 'Ansi'
      VariableRoute    = 'legacy-200'
      NoticePattern    = $null
    }
    @{
      Name             = 'nsis-2.25-setup.exe'
      Url              = 'https://sourceforge.net/projects/nsis/files/NSIS%202/2.25/nsis-2.25-setup.exe/download'
      Sha256           = 'ED90919C21352BEA6770503826AEEB13D00C3487DF3177E96A5706E27EF47CB7'
      CatalogProfileId = 'official-legacy-225-ansi'
      EditionId        = 'official'
      CharacterMode    = 'Ansi'
      VariableRoute    = 'legacy-225'
      NoticePattern    = $null
    }
    @{
      Name             = 'nsis204.exe'
      Url              = 'https://sourceforge.net/projects/nsis/files/NSIS%202/2.04/nsis204.exe/download'
      Sha256           = '967CC080B8CB1D5B750C324805F1687591761E91BE2EAFE1FC71677FF2DF03F3'
      CatalogProfileId = 'official-legacy-225-ansi'
      EditionId        = 'official'
      CharacterMode    = 'Ansi'
      VariableRoute    = 'legacy-225'
      NoticePattern    = $null
    }
    @{
      Name             = 'nsis-2.26-setup.exe'
      Url              = 'https://sourceforge.net/projects/nsis/files/NSIS%202/2.26/nsis-2.26-setup.exe/download'
      Sha256           = 'E7792E303E7DF9EF08D73583F9DE39A6FC78C5A1E8192C8C848542DDB5CC8804'
      CatalogProfileId = 'official-nsis2-ansi'
      EditionId        = 'official'
      CharacterMode    = 'Ansi'
      VariableRoute    = 'current'
      NoticePattern    = 'does not contain decisive generation control codes'
    }
    @{
      Name             = 'nsis-2.46-setup.exe'
      Url              = 'https://sourceforge.net/projects/nsis/files/NSIS%202/2.46/nsis-2.46-setup.exe/download'
      Sha256           = '69C2AE5C9F2EE45B0626905FAFFAA86D4E2FC0D3E8C118C8BC6899DF68467B32'
      CatalogProfileId = 'official-nsis2-ansi'
      EditionId        = 'official'
      CharacterMode    = 'Ansi'
      VariableRoute    = 'current'
      NoticePattern    = 'does not contain decisive generation control codes'
    }
    @{
      Name             = 'nsis-2.51-setup.exe'
      Url              = 'https://sourceforge.net/projects/nsis/files/NSIS%202/2.51/nsis-2.51-setup.exe/download'
      Sha256           = '8A4A86BD028793038A4B744281A4DF436948F3D1941ADCB68C07BA6E42FB6165'
      CatalogProfileId = 'official-nsis2-ansi'
      EditionId        = 'official'
      CharacterMode    = 'Ansi'
      VariableRoute    = 'current'
      NoticePattern    = 'does not contain decisive generation control codes'
    }
    @{
      Name             = 'nsis-2.33-Unicode-setup.exe'
      Url              = 'https://sourceforge.net/projects/nsisu/files/nsisu/nsisu-2.33/nsis-2.33-Unicode-setup.exe/download'
      Sha256           = '403A80CF3CBDF12A5C11A8AFA30BC1C7BA4551080477EC527B43AA043F764E52'
      CatalogProfileId = 'park-2461-unicode'
      EditionId        = 'park'
      CharacterMode    = 'Unicode'
      VariableRoute    = 'current'
      NoticePattern    = $null
    }
    @{
      Name             = 'nsis-2.46.2-Unicode-setup.exe'
      Url              = 'https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/unsis/nsis-2.46.2-Unicode-setup.exe'
      Sha256           = '8AD0290E8158A6E6078E7E8CD33B0D85936A65312A9DD62E2873D7456ACFCA32'
      CatalogProfileId = 'park-2462-unicode'
      EditionId        = 'park'
      CharacterMode    = 'Unicode'
      VariableRoute    = 'current'
      NoticePattern    = $null
    }
    @{
      Name             = 'nsis-2.46.3-Unicode-setup.exe'
      Url              = 'https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/unsis/nsis-2.46.3-Unicode-setup.exe'
      Sha256           = '6E660BDCC5E10EF2F4FE9430D367FD083D252728F2BE70ED74407C10515E52A6'
      CatalogProfileId = 'park-2463-unicode'
      EditionId        = 'park'
      CharacterMode    = 'Unicode'
      VariableRoute    = 'current'
      NoticePattern    = $null
    }
  ) {
    $Fixture = Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name) -Uri $Url -Sha256 $Sha256 -UseSourceForgeMetaRefresh
    $Result = Get-NSISFormatInfo -Path $Fixture

    $Result.CatalogProfileId | Should -Be $CatalogProfileId
    $Result.EditionId | Should -Be $EditionId
    $Result.CharacterMode | Should -Be $CharacterMode
    $Result.VariableRoute | Should -Be $VariableRoute
    $Result.IsSupported | Should -BeTrue
    if ($NoticePattern) {
      @($Result.Notices | Where-Object { $_ -match $NoticePattern }) | Should -Not -BeNullOrEmpty
      $Result.Warnings | Should -BeNullOrEmpty
    } else {
      $Result.Warnings | Should -BeNullOrEmpty
    }
  }

  It 'Should parse and extract controlled NSISBI 3.03.1 all-in-one and external layouts' {
    $FixtureDirectory = Resolve-NSISBuilderFixturePath -Version '3.03.1' -Scenario 'ControlledMedia'
    $AioPath = Join-Path $FixtureDirectory 'nsisbi-3.03.1-aio.exe'
    $ExternalPath = Join-Path $FixtureDirectory 'nsisbi-3.03.1-external.exe'
    $SidecarPath = Join-Path $FixtureDirectory 'nsisbi-3.03.1-external.nsisbin'
    if (-not (Test-Path -LiteralPath $AioPath) -or -not (Test-Path -LiteralPath $ExternalPath) -or -not (Test-Path -LiteralPath $SidecarPath)) {
      Set-ItResult -Skipped -Because 'The controlled NSISBI 3.03.1 fixtures have not been built in the persistent fixture cache.'
      return
    }

    (Get-FileHash -LiteralPath $AioPath -Algorithm SHA256).Hash | Should -Be '3DA8A7B47149A05AB3AE95BB2A487617F9F6685D41781156EE0386F23CCE566F'
    (Get-FileHash -LiteralPath $ExternalPath -Algorithm SHA256).Hash | Should -Be '4B0E26431892E8DA329C560A4004CE75D07CF34A89FDDE0E24A0C763E1B0BE09'
    (Get-FileHash -LiteralPath $SidecarPath -Algorithm SHA256).Hash | Should -Be 'B427D794256D18E6483FD778BBD5D8DEAE9790ADDF23CE545194ED1ABB6119C4'

    $AioFormat = Get-NSISFormatInfo -Path $AioPath
    $ExternalFormat = Get-NSISFormatInfo -Path $ExternalPath
    $AioInfo = Get-NSISInfo -Path $AioPath
    $ExternalInfo = Get-NSISInfo -Path $ExternalPath

    $AioFormat.FirstHeaderFlagRoute | Should -Be 'nsisbi-pre-3.04.1'
    $AioFormat.CompressionRoute | Should -Be 'Deflate'
    $AioFormat.IsSupported | Should -BeTrue
    $AioFormat.HasExternalFile | Should -BeFalse
    $ExternalFormat.FirstHeaderFlagRoute | Should -Be 'nsisbi-pre-3.04.1'
    $ExternalFormat.HasExternalFile | Should -BeTrue
    $ExternalFormat.ExternalFileCount | Should -Be 1
    $AioInfo.ProductCode | Should -Be 'Dumplings.NSISBI303'
    $AioInfo.DisplayName | Should -Be 'Dumplings NSISBI 3.03 Fixture'
    $ExternalInfo.ProductCode | Should -Be 'Dumplings.NSISBI303'

    $AioDestination = Join-Path $TestDrive 'nsisbi303-aio'
    $ExternalDestination = Join-Path $TestDrive 'nsisbi303-external'
    $AioExtracted = @(Expand-NSISInstaller -Path $AioPath -DestinationPath $AioDestination -Name 'payload.txt' -MaximumExpandedBytes 1048576 -CollisionAction Rename)
    $ExternalExtracted = @(Expand-NSISInstaller -Path $ExternalPath -DestinationPath $ExternalDestination -Name 'payload.txt' -ExternalDataPath $SidecarPath -MaximumExpandedBytes 1048576 -CollisionAction Rename)
    $AioExtracted.Count | Should -Be 1
    $ExternalExtracted.Count | Should -Be 1
    (Get-Content -LiteralPath $AioExtracted[0].FullName -Raw).TrimEnd() | Should -Be 'controlled NSISBI payload'
    (Get-Content -LiteralPath $ExternalExtracted[0].FullName -Raw).TrimEnd() | Should -Be 'controlled NSISBI payload'
  }

  It 'Should parse and extract current NSISBI 3.12.3 MTW codecs and split media' {
    $FixtureDirectory = Resolve-NSISBuilderFixturePath -Version '3.12.3' -Scenario 'ControlledMedia'
    $ExpectedFiles = [ordered]@{
      'nsisbi-3.12.3-mtw-bzip2.exe' = '9BBDDAA76270171D3E9B5CE20A82F0FEFF0BA852CACDCFD43953C8B9CE4AA7E6'
      'nsisbi-3.12.3-mtw-lz4.exe'   = '41F717F421857975B0DDA9A65FB232AEF87D87FDED48B64CE0AC68FAFEF6E08A'
      'nsisbi-3.12.3-mtw-lzma.exe'  = 'EBE9D7D85CF4BEED5DF6AE88C6AEA552EB1FD40AF5B7658B4C73B9AD7A9CB011'
      'nsisbi-3.12.3-mtw-zlib.exe'  = '654D5D064AD7C123C1E0BF94B31BE9952A1E4C90B125EDBF8BC3C3497AA63990'
      'nsisbi-3.12.3-split-lz4.exe' = '1E4E753A06B877548FF5A2483074E10CA928B060C6A86E54ED6420E95F222317'
      'setup1.bin'                  = '8FC6458F1309E8484AC50AC30139DA96EDA7AB22C0F393B9EF3DF5915EF383E3'
      'setup2.bin'                  = '258116D11097B191E001694092C3B219A708EAD9E1CAF936E0F20DE1852B4ED3'
      'setup3.bin'                  = '200471612C424E084B65618416C03D15887EF69E3328ACA5D0F31203EA2631B3'
      'setup4.bin'                  = 'B1A9ED365F324E83B47E1CBEA22FFDEA2DE081B008FC47D691182A758C63DB72'
    }
    foreach ($FileName in $ExpectedFiles.Keys) {
      if (-not (Test-Path -LiteralPath (Join-Path $FixtureDirectory $FileName))) {
        Set-ItResult -Skipped -Because 'The controlled NSISBI 3.12.3 fixtures have not been built in the persistent fixture cache.'
        return
      }
    }
    foreach ($Entry in $ExpectedFiles.GetEnumerator()) {
      (Get-FileHash -LiteralPath (Join-Path $FixtureDirectory $Entry.Key) -Algorithm SHA256).Hash | Should -Be $Entry.Value
    }

    $Cases = @(
      @{ Name = 'nsisbi-3.12.3-mtw-bzip2.exe'; ProductCode = 'Dumplings.NSISBI3123.bzip2'; Compression = 'Mtw-BZip2' }
      @{ Name = 'nsisbi-3.12.3-mtw-lz4.exe'; ProductCode = 'Dumplings.NSISBI3123.lz4'; Compression = 'Mtw-Lz4' }
      @{ Name = 'nsisbi-3.12.3-mtw-lzma.exe'; ProductCode = 'Dumplings.NSISBI3123.lzma'; Compression = 'Mtw-Lzma' }
      @{ Name = 'nsisbi-3.12.3-mtw-zlib.exe'; ProductCode = 'Dumplings.NSISBI3123.zlib'; Compression = 'Mtw-Deflate' }
    )
    foreach ($Case in $Cases) {
      $Path = Join-Path $FixtureDirectory $Case.Name
      $Format = Get-NSISFormatInfo -Path $Path
      $Info = Get-NSISInfo -Path $Path
      $Format.FirstHeaderFlagRoute | Should -Be 'nsisbi-compact-3.12'
      $Format.CatalogProfileId | Should -Be 'nsisbi-nsis3-unicode'
      $Format.CompressionRoute | Should -Be $Case.Compression
      $Format.IsSolid | Should -BeFalse
      $Format.IsSupported | Should -BeTrue
      $Info.ProductCode | Should -Be $Case.ProductCode

      $Destination = Join-Path $TestDrive ([IO.Path]::GetFileNameWithoutExtension($Case.Name))
      $Extracted = @(Expand-NSISInstaller -Path $Path -DestinationPath $Destination -Name 'payload.bin' -MaximumExpandedBytes 5MB -CollisionAction Rename)
      $Extracted.Count | Should -Be 1
      $Extracted[0].Length | Should -Be 393216
      (Get-FileHash -LiteralPath $Extracted[0].FullName -Algorithm SHA256).Hash | Should -Be 'E84CD435E7172FD0A416DC4B7107F74A905BAD4CF80D5CEC64B7F2A01BC43DAE'
    }

    $SplitPath = Join-Path $FixtureDirectory 'nsisbi-3.12.3-split-lz4.exe'
    $Sidecars = 1..4 | ForEach-Object { Join-Path $FixtureDirectory "setup$_.bin" }
    $SplitFormat = Get-NSISFormatInfo -Path $SplitPath
    $SplitInfo = Get-NSISInfo -Path $SplitPath
    $SplitFormat.FirstHeaderFlagRoute | Should -Be 'nsisbi-compact-3.12'
    $SplitFormat.CompressionRoute | Should -Be 'Mtw-Lz4'
    $SplitFormat.ExternalFileCount | Should -Be 4
    $SplitFormat.HasExternalFile | Should -BeTrue
    $SplitInfo.ProductCode | Should -Be 'Dumplings.NSISBI3123.lz4.Split'

    $SplitDestination = Join-Path $TestDrive 'nsisbi-3.12.3-split-lz4'
    $SplitExtracted = @(Expand-NSISInstaller -Path $SplitPath -DestinationPath $SplitDestination -Name 'payload.bin' -ExternalDataPath $Sidecars -MaximumExpandedBytes 5MB -CollisionAction Rename)
    $SplitExtracted.Count | Should -Be 1
    $SplitExtracted[0].Length | Should -Be 3407872
    (Get-FileHash -LiteralPath $SplitExtracted[0].FullName -Algorithm SHA256).Hash | Should -Be 'AA99FC11291174927E5A472F6D22E80A1302C5CC8EBF034BA27A90195E8FAA19'
  }

  It 'Should reject truncated current NSISBI split media without retaining output' {
    $FixtureDirectory = Resolve-NSISBuilderFixturePath -Version '3.12.3' -Scenario 'ControlledMedia'
    $RequiredNames = @('nsisbi-3.12.3-split-lz4.exe', 'setup1.bin', 'setup2.bin', 'setup3.bin', 'setup4.bin')
    foreach ($Name in $RequiredNames) {
      if (-not (Test-Path -LiteralPath (Join-Path $FixtureDirectory $Name))) {
        Set-ItResult -Skipped -Because 'The controlled NSISBI 3.12.3 split fixture has not been built in the persistent fixture cache.'
        return
      }
    }

    $CorruptDirectory = Join-Path $TestDrive 'nsisbi-3.12.3-truncated-split'
    $null = New-Item -Path $CorruptDirectory -ItemType Directory -Force
    foreach ($Name in $RequiredNames) {
      Copy-Item -LiteralPath (Join-Path $FixtureDirectory $Name) -Destination (Join-Path $CorruptDirectory $Name)
    }
    $TruncatedPath = Join-Path $CorruptDirectory 'setup2.bin'
    $Stream = [IO.File]::Open($TruncatedPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $Stream.SetLength($Stream.Length - 1) } finally { $Stream.Dispose() }

    $Installer = Join-Path $CorruptDirectory 'nsisbi-3.12.3-split-lz4.exe'
    $Sidecars = 1..4 | ForEach-Object { Join-Path $CorruptDirectory "setup$_.bin" }
    $Destination = Join-Path $CorruptDirectory 'expanded'
    {
      Expand-NSISInstaller -Path $Installer -DestinationPath $Destination -Name 'payload.bin' -ExternalDataPath $Sidecars -MaximumExpandedBytes 5MB -CollisionAction Rename
    } | Should -Throw
    Test-Path -LiteralPath (Join-Path $Destination 'payload.bin') | Should -BeFalse
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
      $RelativePaths = @($Extracted | ForEach-Object { [IO.Path]::GetRelativePath($ExpandedPath, $_.FullName) })
      $RelativePaths | Should -Contain '$PLUGINSDIR\System.dll'
      $RelativePaths | Should -Contain 'alist-desktop.exe'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
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
      $Extracted = @(Expand-NSISInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'Exr-IO.8bi' -MaximumExpandedBytes 33554432 -CollisionAction Rename)

      $Header.Compression | Should -Be 'BZip2'
      $Header.IsSolid | Should -BeTrue
      $Info.DisplayName | Should -Be '3d-io Exr-IO 2.06.00'
      $Info.DisplayVersion | Should -Be '2.06.00'
      # The two physical architecture payloads are referenced through four
      # compiled destinations. Preserve the $R1 collision plus the two private
      # output aliases exactly as a 7-Zip-style NSIS catalog exposes them.
      $Extracted | Should -HaveCount 4
      $RelativePaths = @($Extracted | ForEach-Object { [IO.Path]::GetRelativePath($ExpandedPath, $_.FullName) })
      $RelativePaths | Should -Contain '$R1\Exr-IO.8bi'
      $RelativePaths | Should -Contain '$R1\Exr-IO (1).8bi'
      $RelativePaths | Should -Contain '$_17_\Exr-IO.8bi'
      $RelativePaths | Should -Contain '$_18_\Exr-IO.8bi'
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
      [IO.Path]::GetRelativePath($ExpandedPath, $Extracted[0].FullName) | Should -Be 'bin\cjpeg.exe'
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
}
