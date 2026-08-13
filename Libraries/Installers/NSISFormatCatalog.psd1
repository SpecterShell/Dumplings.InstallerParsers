# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# Format sources: https://github.com/NSIS-Dev/nsis,
# https://sourceforge.net/projects/nsisu/, https://sourceforge.net/projects/nsisbi/,
# and https://github.com/ip7z/7zip/tree/main/CPP/7zip/Archive/Nsis

@{
  SchemaVersion   = 1

  # Editions identify independently maintained compiler/runtime lines. Build
  # templates such as electron-builder and Tauri remain generator evidence.
  Editions        = @{
    official = 'Nullsoft Scriptable Install System'
    park     = 'NSIS Unicode (Jim Park)'
    nsisbi   = 'NSISBI'
  }

  VariableLayouts = @{
    'legacy-200' = @{
      HwndParent = 27; Click = 28; SavedOutDir = $null; ExePath = $null; ExeFile = $null; CustomVariableBase = 29
    }
    'legacy-225' = @{
      HwndParent = 27; Click = 28; SavedOutDir = 29; ExePath = $null; ExeFile = $null; CustomVariableBase = 30
    }
    current      = @{
      HwndParent = 29; Click = 30; SavedOutDir = 31; ExePath = 27; ExeFile = 28; CustomVariableBase = 32
    }
  }

  # Profiles describe serialized ABIs. NSIS does not write a dependable exact
  # compiler version into every installer, so byte-compatible releases share a
  # profile and expose a source-backed VersionRange instead.
  Profiles        = @(
    @{
      Id = 'official-legacy-200-ansi'; EditionId = 'official'; Generation = 'NSIS2'; VersionRange = '1.x-2.03'
      CharacterMode = 'Ansi'; CommandType = 'NSIS2'; FirstHeaderRoute = 'standard32'; HeaderRoute = 'standard'
      EntryRoute = 'standard28'; StringRoute = 'nsis2-ansi'; OpcodeRoute = 'official'; VariableRoute = 'legacy-200'
      PayloadRoute = 'standard'; CompressionRoutes = @('Stored', 'Deflate', 'Zlib', 'BZip2', 'Lzma'); ChecksumRoute = 'Crc32Optional'
      Supported = $true
    }
    @{
      Id = 'official-legacy-225-ansi'; EditionId = 'official'; Generation = 'NSIS2'; VersionRange = '2.04-2.25'
      CharacterMode = 'Ansi'; CommandType = 'NSIS2'; FirstHeaderRoute = 'standard32'; HeaderRoute = 'standard'
      EntryRoute = 'standard28'; StringRoute = 'nsis2-ansi'; OpcodeRoute = 'official'; VariableRoute = 'legacy-225'
      PayloadRoute = 'standard'; CompressionRoutes = @('Stored', 'Deflate', 'Zlib', 'BZip2', 'Lzma'); ChecksumRoute = 'Crc32Optional'
      Supported = $true
    }
    @{
      Id = 'official-nsis2-ansi'; EditionId = 'official'; Generation = 'NSIS2'; VersionRange = '2.26-2.51'
      CharacterMode = 'Ansi'; CommandType = 'NSIS2'; FirstHeaderRoute = 'standard32'; HeaderRoute = 'standard'
      EntryRoute = 'standard28'; StringRoute = 'nsis2-ansi'; OpcodeRoute = 'official'; VariableRoute = 'current'
      PayloadRoute = 'standard'; CompressionRoutes = @('Stored', 'Deflate', 'Zlib', 'BZip2', 'Lzma'); ChecksumRoute = 'Crc32Optional'
      Supported = $true
    }
    @{
      Id = 'park-2461-unicode'; EditionId = 'park'; Generation = 'Park1'; VersionRange = '<=2.46.1'
      CharacterMode = 'Unicode'; CommandType = 'Park1'; FirstHeaderRoute = 'standard32'; HeaderRoute = 'standard'
      EntryRoute = 'standard28'; StringRoute = 'park-unicode'; OpcodeRoute = 'park1'; VariableRoute = 'current'
      PayloadRoute = 'standard'; CompressionRoutes = @('Stored', 'Deflate', 'Zlib', 'BZip2', 'Lzma'); ChecksumRoute = 'Crc32Optional'
      Supported = $true
    }
    @{
      Id = 'park-2462-unicode'; EditionId = 'park'; Generation = 'Park2'; VersionRange = '2.46.2'
      CharacterMode = 'Unicode'; CommandType = 'Park2'; FirstHeaderRoute = 'standard32'; HeaderRoute = 'standard'
      EntryRoute = 'standard28'; StringRoute = 'park-unicode'; OpcodeRoute = 'park2'; VariableRoute = 'current'
      PayloadRoute = 'standard'; CompressionRoutes = @('Stored', 'Deflate', 'Zlib', 'BZip2', 'Lzma'); ChecksumRoute = 'Crc32Optional'
      Supported = $true
    }
    @{
      Id = 'park-2463-unicode'; EditionId = 'park'; Generation = 'Park3'; VersionRange = '>=2.46.3'
      CharacterMode = 'Unicode'; CommandType = 'Park3'; FirstHeaderRoute = 'standard32'; HeaderRoute = 'standard'
      EntryRoute = 'standard28'; StringRoute = 'park-unicode'; OpcodeRoute = 'park3'; VariableRoute = 'current'
      PayloadRoute = 'standard'; CompressionRoutes = @('Stored', 'Deflate', 'Zlib', 'BZip2', 'Lzma'); ChecksumRoute = 'Crc32Optional'
      Supported = $true
    }
    @{
      Id = 'official-nsis3-ansi'; EditionId = 'official'; Generation = 'NSIS3'; VersionRange = '3.x'
      CharacterMode = 'Ansi'; CommandType = 'NSIS3'; FirstHeaderRoute = 'standard32'; HeaderRoute = 'standard'
      EntryRoute = 'standard28'; StringRoute = 'nsis3-ansi'; OpcodeRoute = 'official'; VariableRoute = 'current'
      PayloadRoute = 'standard'; CompressionRoutes = @('Stored', 'Deflate', 'Zlib', 'BZip2', 'Lzma'); ChecksumRoute = 'Crc32Optional'
      Supported = $true
    }
    @{
      Id = 'official-nsis3-unicode'; EditionId = 'official'; Generation = 'NSIS3'; VersionRange = '3.x'
      CharacterMode = 'Unicode'; CommandType = 'NSIS3'; FirstHeaderRoute = 'standard32'; HeaderRoute = 'standard'
      EntryRoute = 'standard28'; StringRoute = 'nsis3-unicode'; OpcodeRoute = 'official'; VariableRoute = 'current'
      PayloadRoute = 'standard'; CompressionRoutes = @('Stored', 'Deflate', 'Zlib', 'BZip2', 'Lzma'); ChecksumRoute = 'Crc32Optional'
      Supported = $true
    }
    @{
      Id = 'nsisbi-nsis3-ansi'; EditionId = 'nsisbi'; Generation = 'NSIS3'; VersionRange = 'NSISBI 3.x'
      CharacterMode = 'Ansi'; CommandType = 'NSIS3'; FirstHeaderRoute = 'nsisbi36'; HeaderRoute = 'nsisbi'
      EntryRoute = 'nsisbi36'; StringRoute = 'nsis3-ansi'; OpcodeRoute = 'official'; VariableRoute = 'current'
      PayloadRoute = 'nsisbi'; CompressionRoutes = @('Stored', 'Deflate', 'Zlib', 'BZip2', 'Lzma', 'Mtw-Zlib', 'Mtw-BZip2', 'Mtw-Lzma', 'Mtw-Lz4'); ChecksumRoute = 'Crc32PerFile'
      Supported = $true
    }
    @{
      Id = 'nsisbi-nsis3-unicode'; EditionId = 'nsisbi'; Generation = 'NSIS3'; VersionRange = 'NSISBI 3.x'
      CharacterMode = 'Unicode'; CommandType = 'NSIS3'; FirstHeaderRoute = 'nsisbi36'; HeaderRoute = 'nsisbi'
      EntryRoute = 'nsisbi36'; StringRoute = 'nsis3-unicode'; OpcodeRoute = 'official'; VariableRoute = 'current'
      PayloadRoute = 'nsisbi'; CompressionRoutes = @('Stored', 'Deflate', 'Zlib', 'BZip2', 'Lzma', 'Mtw-Zlib', 'Mtw-BZip2', 'Mtw-Lzma', 'Mtw-Lz4'); ChecksumRoute = 'Crc32PerFile'
      Supported = $true
    }
  )
}
