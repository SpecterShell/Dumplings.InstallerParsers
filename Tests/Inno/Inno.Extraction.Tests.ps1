. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InnoTestSetup.ps1')

Describe 'Inno synthetic extraction' -Tag Unit {
  It 'Streams a payload across historical and modern external disk slices' -ForEach @(
    @{ Version = 6403; Identifier = [byte[]](0x69, 0x64, 0x73, 0x6B, 0x61, 0x33, 0x32, 0x1A); HeaderLength = 12 }
    @{ Version = 6502; Identifier = [byte[]](0x69, 0x64, 0x73, 0x6B, 0x62, 0x33, 0x32, 0x1A); HeaderLength = 16 }
  ) {
    $CaseRoot = Join-Path $TestDrive "external-$Version"
    $null = New-Item -Path $CaseRoot -ItemType Directory
    $Installer = Join-Path $CaseRoot 'setup.exe'
    [IO.File]::WriteAllBytes($Installer, [byte[]](0x4D, 0x5A))
    $Payload = [byte[]](1..20)
    $StartOffset = $HeaderLength + 4

    function Write-TestInnoSlice([string]$Path, [byte[]]$Part, [bool]$First) {
      $Body = [Collections.Generic.List[byte]]::new()
      $Body.AddRange($Identifier)
      $Body.AddRange([byte[]]::new($HeaderLength - 8))
      if ($First) {
        $Body.AddRange([byte[]]::new(4))
        $Body.AddRange([Text.Encoding]::ASCII.GetBytes("zlb$([char]0x1A)"))
      }
      $Body.AddRange($Part)
      $SizeBytes = $HeaderLength -eq 16 ? [BitConverter]::GetBytes([long]$Body.Count) : [BitConverter]::GetBytes([uint32]$Body.Count)
      for ($Index = 0; $Index -lt $SizeBytes.Length; $Index++) { $Body[8 + $Index] = $SizeBytes[$Index] }
      [IO.File]::WriteAllBytes($Path, $Body.ToArray())
    }

    Write-TestInnoSlice -Path (Join-Path $CaseRoot 'setup-1.bin') -Part $Payload[0..6] -First $true
    Write-TestInnoSlice -Path (Join-Path $CaseRoot 'setup-2.bin') -Part $Payload[7..19] -First $false
    $Location = [pscustomobject]@{
      FirstSlice = 0; LastSlice = 1; StartOffset = $StartOffset; ChunkCompressedSize = $Payload.Length
    }

    InModuleScope Inno -Parameters @{ Installer = $Installer; Location = $Location; Version = $Version; Expected = $Payload } {
      $Stream = Get-InnoFileChunkStream -Path $Installer -Offset1 0 -Location $Location `
        -InternalStructureVersion $Version -SlicesPerDisk 1
      try {
        $Actual = [byte[]]::new($Expected.Length)
        $Read = $Stream.Read($Actual, 0, $Actual.Length)
        $Read | Should -Be $Expected.Length
        $Actual | Should -Be $Expected
        $Stream.ReadByte() | Should -Be -1
      } finally { $Stream.Dispose() }
    }
  }

  It 'Resolves letter-suffixed multi-slice media and rejects missing or malformed slices' {
    $CaseRoot = Join-Path $TestDrive 'external-lettered'
    $null = New-Item -Path $CaseRoot -ItemType Directory
    $Installer = Join-Path $CaseRoot 'media.exe'
    [IO.File]::WriteAllBytes($Installer, [byte[]](0x4D, 0x5A))
    $Identifier = [byte[]](0x69, 0x64, 0x73, 0x6B, 0x62, 0x33, 0x32, 0x1A)
    $Payload = [byte[]](21..32)

    function Write-TestModernSlice([string]$Path, [byte[]]$Part, [bool]$First) {
      $Body = [Collections.Generic.List[byte]]::new()
      $Body.AddRange($Identifier)
      $Body.AddRange([byte[]]::new(8))
      if ($First) {
        $Body.AddRange([Text.Encoding]::ASCII.GetBytes("zlb$([char]0x1A)"))
      }
      $Body.AddRange($Part)
      $SizeBytes = [BitConverter]::GetBytes([long]$Body.Count)
      for ($Index = 0; $Index -lt 8; $Index++) { $Body[8 + $Index] = $SizeBytes[$Index] }
      [IO.File]::WriteAllBytes($Path, $Body.ToArray())
    }

    Write-TestModernSlice -Path (Join-Path $CaseRoot 'media-1a.bin') -Part $Payload[0..4] -First $true
    Write-TestModernSlice -Path (Join-Path $CaseRoot 'media-1b.bin') -Part $Payload[5..11] -First $false
    $Location = [pscustomobject]@{ FirstSlice = 0; LastSlice = 1; StartOffset = 16; ChunkCompressedSize = $Payload.Length }

    InModuleScope Inno -Parameters @{ Installer = $Installer; Location = $Location; Expected = $Payload; Root = $CaseRoot } {
      $Stream = Get-InnoFileChunkStream -Path $Installer -Offset1 0 -Location $Location `
        -InternalStructureVersion 6502 -SlicesPerDisk 2 -DiskSourcePath $Root
      try {
        $Actual = [byte[]]::new($Expected.Length)
        $Stream.Read($Actual, 0, $Actual.Length) | Should -Be $Expected.Length
        $Actual | Should -Be $Expected
      } finally { $Stream.Dispose() }

      Remove-Item -LiteralPath (Join-Path $Root 'media-1b.bin') -Force
      { Get-InnoFileChunkStream -Path $Installer -Offset1 0 -Location $Location `
          -InternalStructureVersion 6502 -SlicesPerDisk 2 -DiskSourcePath $Root } | Should -Throw '*media-1b.bin*'

      $Malformed = Join-Path $Root 'media-1b.bin'
      [IO.File]::WriteAllBytes($Malformed, [byte[]](0x69, 0x64, 0x73, 0x6B, 0x62, 0x33, 0x32, 0x1A, 0, 0, 0, 0, 0, 0, 0, 0))
      { Get-InnoDiskSliceHeaderInfo -Path $Malformed -InternalStructureVersion 6502 } | Should -Throw '*declares 0 bytes*'
    }
  }

  It 'Should read only the requested file-location record as a scalar object' {
    InModuleScope Inno {
      $Layout = Get-TestInnoCatalogLayout -VersionNumber 7000 -UnicodeVariant $true
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

  It 'Should use the source-backed pre-5.3.9 CALL transform without changing the sign-extension byte' {
    InModuleScope Inno {
      Import-InnoCallTransform
      $Bytes = [byte[]](0xE8, 0x00, 0x00, 0x00, 0x00, 0x90)

      [Dumplings.InstallerParsers.InnoCallTransform]::DecodeLegacy($Bytes, $Bytes.Length, 0)

      $Bytes | Should -Be ([byte[]](0xE8, 0xFB, 0xFF, 0xFF, 0x00, 0x90))
    }
  }

  It 'Should locate ANSI and Unicode variable-length file-entry candidates without accepting unrelated strings' {
    InModuleScope Inno {
      Import-InnoCallTransform
      foreach ($Case in @(
          @{ Encoding = [Text.Encoding]::UTF8; Unicode = $false },
          @{ Encoding = [Text.Encoding]::Unicode; Unicode = $true }
        )) {
        $Source = $Case.Encoding.GetBytes('payload.exe')
        $Destination = $Case.Encoding.GetBytes('{app}\payload.exe')
        $Prefix = [byte[]](0xAA, 0xBB, 0xCC)
        $Record = [BitConverter]::GetBytes([int]$Source.Length) + $Source +
        [BitConverter]::GetBytes([int]$Destination.Length) + $Destination
        $Noise = [BitConverter]::GetBytes([int]4) + $Case.Encoding.GetBytes('noop')
        $Bytes = $Prefix + $Record + $Noise
        $DestinationContentOffset = $Prefix.Length + 4 + $Source.Length + 4

        $Offsets = [Dumplings.InstallerParsers.InnoCallTransform]::FindLengthPrefixedSecondStringRecords(
          $Bytes, 0, $Bytes.Length - 8, @($DestinationContentOffset), $Case.Unicode, 1024, 1024
        )

        $Offsets | Should -Be @($Prefix.Length)
      }
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
}
