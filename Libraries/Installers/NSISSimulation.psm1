# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# NSIS command interpreter and virtual system-effect simulation.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# The original parser kept format constants and the simulator in one script scope. Import the
# format layer as a nested dependency and copy its documented NSIS constants into this module's
# script scope so existing `$Script:NSIS_*` lookups remain deterministic after the split.
$FormatModule = Import-Module (Join-Path $PSScriptRoot 'NSISFormat.psm1') -PassThru
foreach ($Entry in $FormatModule.ExportedVariables.GetEnumerator()) {
  Set-Variable -Scope Script -Name $Entry.Key -Value $Entry.Value.Value
}

function Get-NSISStringCodeKind {
  <#
  .SYNOPSIS
    Resolve an NSIS control code kind for the active installer version
  .PARAMETER Character
    The candidate control code
  .PARAMETER IsV3
    Whether the installer uses NSIS v3 control codes
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate control code')]
    [uint16]$Character,

    [Parameter(Mandatory, HelpMessage = 'Whether the installer uses NSIS v3 control codes')]
    [bool]$IsV3,

    [Parameter(HelpMessage = 'The detected NSIS command layout type')]
    [string]$Type = $(if ($IsV3) { 'NSIS3' } else { 'NSIS2' })
  )

  if ($Type -like 'Park*') {
    switch ($Character) {
      0xE003 { return 'Lang' }
      0xE002 { return 'Shell' }
      0xE001 { return 'Var' }
      0xE000 { return 'Skip' }
      default { return $null }
    }
  } elseif ($IsV3) {
    switch ($Character) {
      1 { return 'Lang' }
      2 { return 'Shell' }
      3 { return 'Var' }
      4 { return 'Skip' }
      default { return $null }
    }
  } else {
    switch ($Character) {
      252 { return 'Skip' }
      253 { return 'Var' }
      254 { return 'Shell' }
      255 { return 'Lang' }
      default { return $null }
    }
  }
}

function ConvertFrom-NSISPackedNumber {
  <#
  .SYNOPSIS
    Decode the packed 15-bit NSIS number embedded in a string control code payload
  .PARAMETER Character
    The raw 16-bit control code payload
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The raw 16-bit control code payload')]
    [uint16]$Character,

    [Parameter(HelpMessage = 'The detected NSIS command layout type')]
    [string]$Type = 'NSIS3'
  )

  if ($Type -like 'Park*') { return [int]($Character -band 0x7FFF) }

  $MaskedCharacter = $Character -band 0x7F7F
  $Bytes = [System.BitConverter]::GetBytes($MaskedCharacter)
  return [int]($Bytes[0] -bor ($Bytes[1] -shl 7))
}

function Get-NSISVariableValue {
  <#
  .SYNOPSIS
    Resolve a compiled NSIS variable reference
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Index
    The compiled variable index
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled variable index')]
    [int]$Index
  )

  if ($State.Variables.ContainsKey($Index)) { return [string]$State.Variables[$Index] }

  switch ($Index) {
    $Script:NSIS_PREDEFINED_VAR_CMDLINE { return '' }
    $Script:NSIS_PREDEFINED_VAR_EXEDIR { return Split-Path -Path $State.Path -Parent }
    $Script:NSIS_PREDEFINED_VAR_LANGUAGE { return [string]$State.LanguageTable.LanguageId }
    $Script:NSIS_PREDEFINED_VAR_TEMP { return [System.IO.Path]::GetTempPath().TrimEnd('\') }
    $Script:NSIS_PREDEFINED_VAR_PLUGINSDIR { return Join-Path ([System.IO.Path]::GetTempPath().TrimEnd('\')) 'NSIS' }
    $Script:NSIS_PREDEFINED_VAR_EXEPATH { return $State.Path }
    $Script:NSIS_PREDEFINED_VAR_EXEFILE { return Split-Path -Path $State.Path -Leaf }
    $Script:NSIS_PREDEFINED_VAR_CLICK { return 'Click Next to continue.' }
    default { return '' }
  }
}

function Set-NSISVariableValue {
  <#
  .SYNOPSIS
    Update a compiled NSIS variable and keep the derived install paths in sync
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Index
    The compiled variable index
  .PARAMETER Value
    The resolved string value
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled variable index')]
    [int]$Index,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The resolved string value')]
    [string]$Value
  )

  $State.Variables[$Index] = $Value

  switch ($Index) {
    $Script:NSIS_PREDEFINED_VAR_INSTDIR {
      $State.Variables[$Script:NSIS_PREDEFINED_VAR_OUTDIR] = $Value
      $State.Variables[$Script:NSIS_PREDEFINED_VAR__OUTDIR] = $Value
      if (-not [string]::IsNullOrWhiteSpace($Value)) { $State.Metadata.DefaultInstallLocation = $Value }
    }
    $Script:NSIS_PREDEFINED_VAR_OUTDIR { $State.Variables[$Script:NSIS_PREDEFINED_VAR__OUTDIR] = $Value }
    $Script:NSIS_PREDEFINED_VAR__OUTDIR { $State.Variables[$Script:NSIS_PREDEFINED_VAR_OUTDIR] = $Value }
    default { }
  }
}

function Resolve-NSISShellValue {
  <#
  .SYNOPSIS
    Resolve a compiled NSIS shell-folder control code
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Character
    The raw 16-bit shell payload
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The raw 16-bit shell payload')]
    [uint16]$Character
  )

  # NSIS packs two shell-folder indexes or an indirect string reference into one
  # 16-bit control payload. Decode both bytes without consulting the host shell.
  $Bytes = [System.BitConverter]::GetBytes($Character)
  $Index1 = $Bytes[0]
  $Index2 = $Bytes[1]

  # The high bit selects an indirect registry-name string; bit 6 distinguishes
  # 64-bit Program Files/Common Files from their 32-bit counterparts.
  if (($Index1 -band 0x80) -ne 0) {
    $StringOffset = $Index1 -band 0x3F
    $Is64BitFolder = ($Index1 -band 0x40) -ne 0
    $ShellString = Get-NSISString -State $State -RelativeOffset $StringOffset

    switch ($ShellString) {
      'ProgramFilesDir' {
        if ($Is64BitFolder) {
          return $(if (${env:ProgramW6432}) { ${env:ProgramW6432} } else { $env:ProgramFiles })
        } else {
          return $(if (${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} } else { $env:ProgramFiles })
        }
      }
      'CommonFilesDir' {
        if ($Is64BitFolder) {
          return $(if (${env:CommonProgramW6432}) { ${env:CommonProgramW6432} } else { $env:CommonProgramFiles })
        } else {
          return $(if (${env:CommonProgramFiles(x86)}) { ${env:CommonProgramFiles(x86)} } else { $env:CommonProgramFiles })
        }
      }
      default { return $ShellString }
    }
  }

  # Ordinary payloads carry primary/fallback CSIDL indexes. Return the first
  # mapped deterministic path and leave unknown identifiers unresolved.
  if ($Index1 -lt $Script:NSIS_SHELL_STRINGS.Count -and $Script:NSIS_SHELL_STRINGS[$Index1]) { return [string]$Script:NSIS_SHELL_STRINGS[$Index1] }
  if ($Index2 -lt $Script:NSIS_SHELL_STRINGS.Count -and $Script:NSIS_SHELL_STRINGS[$Index2]) { return [string]$Script:NSIS_SHELL_STRINGS[$Index2] }
  return ''
}

function ConvertTo-NSISSymbolicVariable {
  <#
  .SYNOPSIS
    Render a compiled NSIS variable index using the stable source spelling
  .PARAMETER Index
    Zero-based NSIS variable-table index encoded in a string control sequence.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The compiled NSIS variable index')]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$Index
  )

  # User variables occupy $0..$9 and $R0..$R9. Modern NSIS then exposes twelve
  # predefined variables; compiler-private variables use the $_N_ notation that
  # 7-Zip presents in its NSIS archive catalog.
  if ($Index -lt 10) { return '$' + $Index }
  if ($Index -lt 20) { return '$R' + ($Index - 10) }
  $InternalIndex = $Index - 20
  if ($InternalIndex -lt $Script:NSIS_SYMBOLIC_VARIABLE_NAMES.Count) {
    return '$' + $Script:NSIS_SYMBOLIC_VARIABLE_NAMES[$InternalIndex]
  }
  return '$_' + ($InternalIndex - $Script:NSIS_SYMBOLIC_VARIABLE_NAMES.Count) + '_'
}

function Resolve-NSISSymbolicShellValue {
  <#
  .SYNOPSIS
    Render an NSIS shell-folder control payload without consulting the host
  .PARAMETER State
    Initialized NSIS parser state containing the source string table.
  .PARAMETER Character
    Packed primary and fallback shell-folder indexes.
  .PARAMETER Depth
    Current bounded symbolic-string recursion depth.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][uint16]$Character,
    [ValidateRange(0, 32)][int]$Depth = 0
  )

  $Bytes = [BitConverter]::GetBytes($Character)
  $Index1 = [int]$Bytes[0]
  $Index2 = [int]$Bytes[1]

  # The high bit selects a registry-backed Program Files/Common Files lookup;
  # bit 6 selects its 64-bit view. Keep unsupported values explicit rather than
  # resolving them against the machine running Dumplings.
  if (($Index1 -band 0x80) -ne 0) {
    $StringOffset = $Index1 -band 0x3F
    $RegistryName = Get-NSISSymbolicString -State $State -RelativeOffset $StringOffset -Depth ($Depth + 1)
    $Suffix = if (($Index1 -band 0x40) -ne 0) { '64' } else { '' }
    switch ($RegistryName) {
      'ProgramFilesDir' { return '$PROGRAMFILES' + $Suffix }
      'CommonFilesDir' { return '$COMMONFILES' + $Suffix }
      default { return '$_ERROR_UNSUPPORTED_VALUE_REGISTRY_(' + $RegistryName + ')' }
    }
  }

  foreach ($Index in @($Index1, $Index2)) {
    if ($Index -lt $Script:NSIS_SYMBOLIC_SHELL_STRINGS.Count -and $Script:NSIS_SYMBOLIC_SHELL_STRINGS[$Index]) {
      return '$' + $Script:NSIS_SYMBOLIC_SHELL_STRINGS[$Index]
    }
  }
  return '$_ERROR_UNSUPPORTED_SHELL_[' + $Index1 + ',' + $Index2 + ']'
}

function Get-NSISSymbolicString {
  <#
  .SYNOPSIS
    Decode an NSIS string while preserving variables, shell folders, and language references
  .PARAMETER State
    Initialized NSIS parser state containing strings and command-layout evidence.
  .PARAMETER RelativeOffset
    String-table offset, measured in characters for Unicode installers.
  .PARAMETER Depth
    Current recursion depth for registry-backed shell strings.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][int]$RelativeOffset,
    [ValidateRange(0, 32)][int]$Depth = 0
  )

  if ($Depth -ge 8) { return '$_ERROR_STRING_RECURSION_' }
  if ($RelativeOffset -lt 0) {
    return '$(LSTR_' + [Math]::Abs($RelativeOffset + 1) + ')'
  }

  $Multiplier = if ($State.VersionInfo.Unicode) { 2 } else { 1 }
  $Offset = $RelativeOffset * $Multiplier
  if ($Offset -lt 0 -or $Offset -ge $State.StringsBlock.Length) { return '$_ERROR_BAD_STRING_' }

  # Decode the bounded code-unit sequence once, then render control sequences in
  # a second pass. This follows the same NSIS 2/3/Park layouts as Get-NSISString
  # but intentionally does not read mutable simulated variable values.
  if ($State.VersionInfo.Unicode) {
    $EndOffset = $Offset
    while ($EndOffset + 1 -lt $State.StringsBlock.Length -and
      -not ($State.StringsBlock[$EndOffset] -eq 0 -and $State.StringsBlock[$EndOffset + 1] -eq 0)) { $EndOffset += 2 }
    if ($EndOffset -le $Offset) { return '' }
    $Characters = [uint16[]]::new(($EndOffset - $Offset) / 2)
    [Buffer]::BlockCopy($State.StringsBlock, $Offset, $Characters, 0, $EndOffset - $Offset)
  } else {
    $EndOffset = $Offset
    while ($EndOffset -lt $State.StringsBlock.Length -and $State.StringsBlock[$EndOffset] -ne 0) { $EndOffset++ }
    if ($EndOffset -le $Offset) { return '' }
    $Characters = [uint16[]]::new($EndOffset - $Offset)
    for ($CharacterIndex = 0; $CharacterIndex -lt $Characters.Length; $CharacterIndex++) {
      $Characters[$CharacterIndex] = $State.StringsBlock[$Offset + $CharacterIndex]
    }
  }

  $Builder = [Text.StringBuilder]::new()
  for ($Index = 0; $Index -lt $Characters.Count; $Index++) {
    $Current = $Characters[$Index]
    $CodeKind = Get-NSISStringCodeKind -Character $Current -IsV3 $State.VersionInfo.IsV3 -Type $State.VersionInfo.Type
    if (-not $CodeKind) {
      $null = $Builder.Append([char]$Current)
      continue
    }
    if ($Index + 1 -ge $Characters.Count) { break }

    if ($CodeKind -eq 'Skip') {
      $Index++
      $null = $Builder.Append([char]$Characters[$Index])
      continue
    }

    if ($State.VersionInfo.Unicode) {
      $Index++
      $Payload = $Characters[$Index]
    } else {
      if ($Index + 2 -ge $Characters.Count) { break }
      $Index++
      $Low = $Characters[$Index]
      $Index++
      $Payload = [uint16]($Low -bor ($Characters[$Index] -shl 8))
    }
    $Number = ConvertFrom-NSISPackedNumber -Character $Payload -Type $State.VersionInfo.Type
    switch ($CodeKind) {
      'Var' { $null = $Builder.Append((ConvertTo-NSISSymbolicVariable -Index $Number)) }
      'Shell' { $null = $Builder.Append((Resolve-NSISSymbolicShellValue -State $State -Character $Payload -Depth $Depth)) }
      'Lang' { $null = $Builder.Append(('$(LSTR_' + $Number + ')')) }
    }
  }
  return $Builder.ToString()
}

function Get-NSISPayloadEntries {
  <#
  .SYNOPSIS
    Build a 7-Zip-style payload path catalog from normalized NSIS commands.
  .PARAMETER State
    Initialized NSIS parser state containing normalized command and string tables.
  .PARAMETER HeaderData
    Validated first-header and archive layout evidence.
  .PARAMETER Name
    Wildcard matched against the compiled operand, archive path, safe path, and base name.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][pscustomobject]$HeaderData,
    [Parameter(Mandatory)][string]$Name
  )

  $Payloads = [System.Collections.Generic.List[object]]::new()
  $CurrentPrefix = '$INSTDIR'
  $SavedPrefix = ''
  foreach ($Entry in $State.Entries) {
    if ($Entry.Opcode -eq $Script:NSIS_OPCODE_CREATE_DIR -and $Entry.Values[2] -ne 0) {
      # SetOutPath is encoded as EW_CREATEDIR with a nonzero second operand. A literal $OUTDIR
      # or compiler-private $_OUTDIR prefix extends the corresponding tracked path.
      $SetOutPath = Get-NSISSymbolicString -State $State -RelativeOffset $Entry.Values[1]
      $CurrentPrefix = Resolve-NSISArchiveOutputPrefix -Path $SetOutPath -CurrentPrefix $CurrentPrefix -SavedPrefix $SavedPrefix
      continue
    }

    if ($Entry.Opcode -eq $Script:NSIS_OPCODE_ASSIGN_VAR -and [int]$Entry.Raw[1] -eq $Script:NSIS_PREDEFINED_VAR__OUTDIR) {
      # NSIS macros use the private _OUTDIR variable to save and restore the active output path.
      $SavedPrefix = ''
      if ($Entry.Raw[3] -eq 0 -and $Entry.Raw[4] -eq 0) {
        $AssignedValue = Get-NSISSymbolicString -State $State -RelativeOffset $Entry.Values[2]
        if ($AssignedValue.Equals('$OUTDIR', [StringComparison]::OrdinalIgnoreCase)) { $SavedPrefix = $CurrentPrefix }
      }
      continue
    }

    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_EXTRACT_FILE) { continue }

    # NSISBI widens the standard uint32 data offset over two operands and shifts FILETIME/CRC.
    $DataOffset = if ($HeaderData.IsNsisBi) {
      [uint64]$Entry.Raw[3] -bor ([uint64]$Entry.Raw[4] -shl 32)
    } else {
      [uint64]$Entry.Raw[3]
    }
    $SourcePath = Get-NSISSymbolicString -State $State -RelativeOffset $Entry.Values[2]
    $ArchivePath = Get-NSISReducedArchivePath -SourcePath $SourcePath -OutputPrefix $CurrentPrefix
    $RelativePath = ConvertTo-NSISExtractionRelativePath -Path $ArchivePath -DataOffset $DataOffset
    if (-not (Test-ExtractionPattern -Path $SourcePath -Pattern $Name) -and
      -not (Test-ExtractionPattern -Path $ArchivePath -Pattern $Name) -and
      -not (Test-ExtractionPattern -Path $RelativePath -Pattern $Name)) { continue }

    $TimeLowIndex = if ($HeaderData.IsNsisBi) { 5 } else { 4 }
    $TimeHighIndex = if ($HeaderData.IsNsisBi) { 6 } else { 5 }
    $Payloads.Add([pscustomobject]@{
        SourcePath   = $SourcePath
        ArchivePath  = $ArchivePath
        RelativePath = $RelativePath
        DataOffset   = $DataOffset
        TimeLow      = $Entry.Raw[$TimeLowIndex]
        TimeHigh     = $Entry.Raw[$TimeHighIndex]
        Crc32        = if ($HeaderData.IsNsisBi) { $Entry.Raw[8] } else { $null }
      })
    if ($Payloads.Count -gt $Script:NSIS_MAX_EXTRACTION_FILE_COUNT) {
      throw "The NSIS extraction selection exceeds the supported $($Script:NSIS_MAX_EXTRACTION_FILE_COUNT)-file limit"
    }
  }

  return $Payloads.ToArray()
}

function Get-NSISString {
  <#
  .SYNOPSIS
    Decode a compiled NSIS string from the strings block
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER RelativeOffset
    The compiled relative string offset
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled relative string offset')]
    [int]$RelativeOffset
  )

  if ($RelativeOffset -lt 0) {
    # Negative offsets encode language-table indices rather than byte positions.
    $LanguageIndex = [Math]::Abs($RelativeOffset + 1)
    if (-not $State.LanguageTable -or $LanguageIndex -ge $State.LanguageTable.StringOffsets.Count) { return '' }
    $ResolvedOffset = $State.LanguageTable.StringOffsets[$LanguageIndex]
    if ($ResolvedOffset -eq 0) { return '' }
    return Get-NSISString -State $State -RelativeOffset $ResolvedOffset
  }

  $Multiplier = if ($State.VersionInfo.Unicode) { 2 } else { 1 }
  $Offset = $RelativeOffset * $Multiplier
  if ($Offset -lt 0 -or $Offset -ge $State.StringsBlock.Length) { return '' }

  if ($State.VersionInfo.Unicode) {
    # Decode the bounded NUL-terminated UTF-16LE or ANSI code-unit sequence first;
    # control-code expansion is performed in a second pass below.
    $EndOffset = $Offset
    while ($EndOffset + 1 -lt $State.StringsBlock.Length -and -not ($State.StringsBlock[$EndOffset] -eq 0x00 -and $State.StringsBlock[$EndOffset + 1] -eq 0x00)) { $EndOffset += 2 }
    if ($EndOffset -le $Offset) { return '' }
    $Characters = [uint16[]]::new(($EndOffset - $Offset) / 2)
    [Buffer]::BlockCopy($State.StringsBlock, $Offset, $Characters, 0, $EndOffset - $Offset)
  } else {
    $EndOffset = $Offset
    while ($EndOffset -lt $State.StringsBlock.Length -and $State.StringsBlock[$EndOffset] -ne 0x00) { $EndOffset++ }
    if ($EndOffset -le $Offset) { return '' }
    $Characters = [uint16[]]::new($EndOffset - $Offset)
    for ($CharacterIndex = 0; $CharacterIndex -lt $Characters.Length; $CharacterIndex++) {
      $Characters[$CharacterIndex] = $State.StringsBlock[$Offset + $CharacterIndex]
    }
  }

  $Builder = [System.Text.StringBuilder]::new()
  $Index = 0

  # Expand variable, shell-folder, and language indirections while preserving
  # escaped control characters. Truncated control payloads terminate safely.
  while ($Index -lt $Characters.Count) {
    $Current = $Characters[$Index]
    $CodeKind = Get-NSISStringCodeKind -Character $Current -IsV3 $State.VersionInfo.IsV3 -Type $State.VersionInfo.Type

    if ($CodeKind) {
      if ($Index + 1 -ge $Characters.Count) { break }

      if ($CodeKind -eq 'Skip') {
        $Current = $Characters[$Index + 1]
        $Index++
      } else {
        if ($State.VersionInfo.Unicode) {
          $Payload = $Characters[$Index + 1]
          $Index++
        } else {
          if ($Index + 2 -ge $Characters.Count) { break }
          $Payload = [uint16]($Characters[$Index + 1] -bor ($Characters[$Index + 2] -shl 8))
          $Index += 2
        }

        switch ($CodeKind) {
          'Var' { $null = $Builder.Append((Get-NSISVariableValue -State $State -Index (ConvertFrom-NSISPackedNumber -Character $Payload -Type $State.VersionInfo.Type))) }
          'Shell' { $null = $Builder.Append((Resolve-NSISShellValue -State $State -Character $Payload)) }
          'Lang' {
            $LanguageIndex = ConvertFrom-NSISPackedNumber -Character $Payload -Type $State.VersionInfo.Type
            if ($State.LanguageTable -and $LanguageIndex -lt $State.LanguageTable.StringOffsets.Count) {
              $StringOffset = $State.LanguageTable.StringOffsets[$LanguageIndex]
              if ($StringOffset -ne 0) { $null = $Builder.Append((Get-NSISString -State $State -RelativeOffset $StringOffset)) }
            }
          }
        }

        $Index++
        continue
      }
    }

    $null = $Builder.Append([char]$Current)
    $Index++
  }

  return $Builder.ToString()
}

function Get-NSISStringVariableIndex {
  <#
  .SYNOPSIS
    Read the variable references encoded in one compiled NSIS string
  .PARAMETER State
    The mutable NSIS execution state containing the strings block
  .PARAMETER RelativeOffset
    The string-table offset, measured in characters for Unicode installers
  #>
  [OutputType([int[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled relative string offset')]
    [int]$RelativeOffset
  )

  if ($RelativeOffset -lt 0) { return [int[]]@() }
  $Multiplier = if ($State.VersionInfo.Unicode) { 2 } else { 1 }
  $Offset = $RelativeOffset * $Multiplier
  if ($Offset -lt 0 -or $Offset -ge $State.StringsBlock.Length) { return [int[]]@() }

  $Indexes = [System.Collections.Generic.HashSet[int]]::new()
  while ($Offset -lt $State.StringsBlock.Length) {
    if ($State.VersionInfo.Unicode) {
      if ($Offset + 1 -ge $State.StringsBlock.Length) { break }
      $Character = [System.BitConverter]::ToUInt16($State.StringsBlock, $Offset)
      $Offset += 2
    } else {
      $Character = [uint16]$State.StringsBlock[$Offset]
      $Offset++
    }
    if ($Character -eq 0) { break }

    $CodeKind = Get-NSISStringCodeKind -Character $Character -IsV3 $State.VersionInfo.IsV3 -Type $State.VersionInfo.Type
    if (-not $CodeKind) { continue }
    if ($State.VersionInfo.Unicode) {
      if ($Offset + 1 -ge $State.StringsBlock.Length) { break }
      $Payload = [System.BitConverter]::ToUInt16($State.StringsBlock, $Offset)
      $Offset += 2
    } else {
      if ($Offset + 1 -ge $State.StringsBlock.Length) { break }
      $Payload = [uint16]($State.StringsBlock[$Offset] -bor ($State.StringsBlock[$Offset + 1] -shl 8))
      $Offset += 2
    }

    if ($CodeKind -eq 'Var') {
      $null = $Indexes.Add((ConvertFrom-NSISPackedNumber -Character $Payload -Type $State.VersionInfo.Type))
    }
  }

  return [int[]]@($Indexes)
}

function Resolve-NSISDirectString {
  <#
  .SYNOPSIS
    Resolve a direct registry string using nearby compiled StrCpy assignments
  .DESCRIPTION
    A direct uninstall-write scan does not follow control flow. Resolve only the
    nearest lexical assignments needed by the registry operand so unrelated
    plug-in stack values cannot leak into ARP paths.
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER RelativeOffset
    The compiled string-table offset to resolve
  .PARAMETER EntryIndex
    The zero-based command index containing the string operand
  .PARAMETER VisitedVariables
    Variable indexes already being resolved, used to stop assignment cycles
  .PARAMETER Depth
    The current bounded recursive-resolution depth
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled string-table offset')]
    [int]$RelativeOffset,

    [Parameter(Mandatory, HelpMessage = 'The command index containing the string operand')]
    [int]$EntryIndex,

    [Parameter(HelpMessage = 'Variable indexes already being resolved')]
    [System.Collections.Generic.HashSet[int]]$VisitedVariables,

    [Parameter(HelpMessage = 'The current recursive-resolution depth')]
    [int]$Depth = 0
  )

  if ($Depth -ge 16) { return Get-NSISString -State $State -RelativeOffset $RelativeOffset }
  if (-not $VisitedVariables) { $VisitedVariables = [System.Collections.Generic.HashSet[int]]::new() }

  $SavedVariables = [System.Collections.Generic.List[object]]::new()
  try {
    foreach ($VariableIndex in @(Get-NSISStringVariableIndex -State $State -RelativeOffset $RelativeOffset)) {
      # Predefined runtime paths are established by initialization and must not
      # be replaced by unrelated lexical assignments from other code segments.
      if ($VariableIndex -ge $Script:NSIS_PREDEFINED_VAR_CMDLINE -and $VariableIndex -le $Script:NSIS_PREDEFINED_VAR__OUTDIR) { continue }
      if (-not $VisitedVariables.Add($VariableIndex)) { continue }

      $Assignment = $null
      for ($Index = [Math]::Min($EntryIndex - 1, $State.Entries.Count - 1); $Index -ge 0; $Index--) {
        $Candidate = $State.Entries[$Index]
        if ($Candidate.Opcode -eq $Script:NSIS_OPCODE_ASSIGN_VAR -and [Math]::Abs($Candidate.Values[1]) -eq $VariableIndex) {
          $Assignment = [pscustomobject]@{ Entry = $Candidate; Index = $Index }
          break
        }
      }
      if (-not $Assignment) {
        $null = $VisitedVariables.Remove($VariableIndex)
        continue
      }

      $HadValue = $State.Variables.ContainsKey($VariableIndex)
      $SavedVariables.Add([pscustomobject]@{
          Index    = $VariableIndex
          HadValue = $HadValue
          Value    = if ($HadValue) { $State.Variables[$VariableIndex] } else { $null }
        })
      $ResolvedValue = Resolve-NSISDirectString -State $State -RelativeOffset $Assignment.Entry.Values[2] -EntryIndex $Assignment.Index -VisitedVariables $VisitedVariables -Depth ($Depth + 1)
      $State.Variables[$VariableIndex] = $ResolvedValue
      $null = $VisitedVariables.Remove($VariableIndex)
    }

    return Get-NSISString -State $State -RelativeOffset $RelativeOffset
  } finally {
    # Temporary data-flow values must not alter later control-flow simulation.
    for ($Index = $SavedVariables.Count - 1; $Index -ge 0; $Index--) {
      $Saved = $SavedVariables[$Index]
      if ($Saved.HadValue) {
        $State.Variables[$Saved.Index] = $Saved.Value
      } else {
        $null = $State.Variables.Remove($Saved.Index)
      }
    }
  }
}

function Get-NSISInt {
  <#
  .SYNOPSIS
    Resolve a compiled NSIS string operand into an integer
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER RelativeOffset
    The compiled relative string offset
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled relative string offset')]
    [int]$RelativeOffset
  )

  $Value = (Get-NSISString -State $State -RelativeOffset $RelativeOffset).Trim()
  if ([string]::IsNullOrWhiteSpace($Value)) { return 0 }

  if ($Value.StartsWith('0x', [System.StringComparison]::OrdinalIgnoreCase)) {
    return [int]::Parse($Value.Substring(2), [System.Globalization.NumberStyles]::HexNumber, [System.Globalization.CultureInfo]::InvariantCulture)
  }

  $ParsedValue = 0
  if ([int]::TryParse($Value, [ref]$ParsedValue)) {
    return $ParsedValue
  } else {
    return 0
  }
}

function Resolve-NSISAddress {
  <#
  .SYNOPSIS
    Resolve an NSIS jump address, including the negative address indirection form
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Address
    The compiled jump address
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled jump address')]
    [int]$Address
  )

  if ($Address -ge 0) { return $Address }

  $Index = [Math]::Abs($Address) - 1
  $VariableValue = Get-NSISVariableValue -State $State -Index $Index
  $ResolvedAddress = 0
  if ([int]::TryParse($VariableValue, [ref]$ResolvedAddress)) {
    return $ResolvedAddress
  } else {
    return 0
  }
}

function Add-NSISDirectory {
  <#
  .SYNOPSIS
    Record a directory in the simulated NSIS file system
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Path
    The directory path
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The directory path')]
    [string]$Path
  )

  if (-not [string]::IsNullOrWhiteSpace($Path)) { $null = $State.Directories.Add($Path.TrimEnd('\')) }
}

function Add-NSISFile {
  <#
  .SYNOPSIS
    Record a file in the simulated NSIS file system
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Path
    The file path
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The file path')]
    [string]$Path
  )

  if (-not [string]::IsNullOrWhiteSpace($Path)) { $null = $State.Files.Add($Path) }
}

function Test-NSISPathExists {
  <#
  .SYNOPSIS
    Test whether a simulated NSIS path exists
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Path
    The file or directory path
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The file or directory path')]
    [string]$Path
  )

  $NormalizedPath = $Path.TrimEnd('\')
  if ($NormalizedPath.EndsWith('\*.*', [System.StringComparison]::OrdinalIgnoreCase)) {
    return $State.Directories.Contains($NormalizedPath.Substring(0, $NormalizedPath.Length - 4).TrimEnd('\'))
  }

  return $State.Directories.Contains($NormalizedPath) -or $State.Files.Contains($Path)
}

function Resolve-NSISRegistryRoot {
  <#
  .SYNOPSIS
    Resolve an NSIS registry root to a deterministic logical hive
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Root
    The compiled NSIS registry root value
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled NSIS registry root value')]
    [uint32]$Root
  )

  switch ($Root) {
    $Script:NSIS_REG_ROOT_HKCR { return 'HKCR' }
    $Script:NSIS_REG_ROOT_HKCU { return 'HKCU' }
    $Script:NSIS_REG_ROOT_HKLM { return 'HKLM' }
    $Script:NSIS_REG_ROOT_HKU { return 'HKU' }
    $Script:NSIS_REG_ROOT_HKCC { return 'HKCC' }
    $Script:NSIS_REG_ROOT_SHCTX {
      if ($State.ShellVarContext) { return $State.ShellVarContext }

      $InstallLocation = $State.Metadata.DefaultInstallLocation
      if ($InstallLocation -and (
          $InstallLocation.StartsWith($env:ProgramFiles, [System.StringComparison]::OrdinalIgnoreCase) -or
          (${env:ProgramFiles(x86)} -and $InstallLocation.StartsWith(${env:ProgramFiles(x86)}, [System.StringComparison]::OrdinalIgnoreCase))
        )) {
        return 'HKLM'
      }

      return 'HKCU'
    }
    default { return 'HKCU' }
  }
}

function Set-NSISRegistryValue {
  <#
  .SYNOPSIS
    Store a registry value in the simulated NSIS registry and update uninstall metadata
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Root
    The registry root
  .PARAMETER Key
    The registry key path
  .PARAMETER Name
    The registry value name
  .PARAMETER Value
    The registry value data
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The registry root')]
    [string]$Root,

    [Parameter(Mandatory, HelpMessage = 'The registry key path')]
    [string]$Key,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The registry value name')]
    [string]$Name,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The registry value data')]
    [string]$Value
  )

  # The simulated registry exists only to make later ReadReg/branch operations
  # deterministic; it never reads from or writes to the host registry.
  if (-not $State.Registry.ContainsKey($Root)) { $State.Registry[$Root] = @{} }
  if (-not $State.Registry[$Root].ContainsKey($Key)) { $State.Registry[$Root][$Key] = @{} }
  $State.Registry[$Root][$Key][$Name] = $Value

  # Only explicit writes beneath the Windows uninstall path become ARP evidence.
  # SystemComponent=1 hides the otherwise-created entry from WinGet matching.
  if ($Key -match $Script:NSIS_UNINSTALL_KEY_PATTERN) {
    $State.Metadata.ProductCode = Split-Path -Path $Key -Leaf
    $State.Metadata.Scope = if ($Root -eq 'HKLM') { 'machine' } elseif ($Root -eq 'HKCU') { 'user' } else { $State.Metadata.Scope }
    $State.Metadata.RegistryValues[$Name] = $Value
    $State.Metadata.WritesAppsAndFeaturesEntry = $true

    switch ($Name) {
      'DisplayName' { $State.Metadata.DisplayName = $Value }
      'DisplayVersion' { $State.Metadata.DisplayVersion = $Value }
      'Publisher' { $State.Metadata.Publisher = $Value }
      'InstallLocation' { $State.Metadata.DefaultInstallLocation = $Value.Trim('"') }
      'UninstallString' { $State.Metadata.UninstallString = $Value }
      'QuietUninstallString' { $State.Metadata.QuietUninstallString = $Value }
      'DisplayIcon' { $State.Metadata.DisplayIcon = $Value }
      'SystemComponent' {
        $State.Metadata.SystemComponent = $Value
        if ($Value -eq '1' -or $Value -eq '0x00000001') { $State.Metadata.WritesAppsAndFeaturesEntry = $false }
      }
      default { }
    }
  }
}

function Get-NSISRegistryWriteFromEntry {
  <#
  .SYNOPSIS
    Convert a normalized EW_WRITEREG command into explicit registry-write evidence
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Entry
    The normalized NSIS command entry
  .PARAMETER EntryIndex
    Optional command index used to resolve nearby StrCpy assignments during a direct scan
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The normalized NSIS command entry')]
    [pscustomobject]$Entry,

    [Parameter(HelpMessage = 'The command index used for direct lexical data-flow')]
    [int]$EntryIndex = -1
  )

  if ($Entry.Opcode -ne $Script:NSIS_OPCODE_WRITE_REG) { return $null }

  # EW_WRITEREG operand positions differ for NSISBI's expanded records. Decode
  # type fields from the detected layout instead of the obsolete fake opcode map.
  $IsNsisBi = $State.VersionInfo.PSObject.Properties.Name -contains 'IsNsisBi' -and $State.VersionInfo.IsNsisBi
  $TypeIndex = if ($IsNsisBi) { 6 } else { 5 }
  $RegistryTypeIndex = if ($IsNsisBi) { 7 } else { 6 }
  $Type = [uint32]$Entry.Raw[$TypeIndex]
  $RegistryType = [uint32]$Entry.Raw[$RegistryTypeIndex]
  $RegistryKind = switch ($Type) {
    $Script:NSIS_REG_TYPE_DWORD { 'REG_DWORD'; break }
    $Script:NSIS_REG_TYPE_EXPAND_STRING { 'REG_EXPAND_SZ'; break }
    $Script:NSIS_REG_TYPE_STRING {
      if ($RegistryType -eq $Script:NSIS_REG_TYPE_EXPAND_STRING) { 'REG_EXPAND_SZ' } else { 'REG_SZ' }
      break
    }
    default {
      switch ($RegistryType) {
        $Script:NSIS_REG_TYPE_DWORD { 'REG_DWORD'; break }
        $Script:NSIS_REG_TYPE_EXPAND_STRING { 'REG_EXPAND_SZ'; break }
        default { 'REG_SZ' }
      }
    }
  }

  # String operands pass through the NSIS string decoder so variable and language
  # references resolve using the same state as simulated execution.
  $Root = Resolve-NSISRegistryRoot -State $State -Root $Entry.Raw[1]
  $Key = if ($EntryIndex -ge 0) {
    Resolve-NSISDirectString -State $State -RelativeOffset $Entry.Values[2] -EntryIndex $EntryIndex
  } else {
    Get-NSISString -State $State -RelativeOffset $Entry.Values[2]
  }
  $Name = if ($EntryIndex -ge 0) {
    Resolve-NSISDirectString -State $State -RelativeOffset $Entry.Values[3] -EntryIndex $EntryIndex
  } else {
    Get-NSISString -State $State -RelativeOffset $Entry.Values[3]
  }
  $Value = if ($RegistryKind -eq 'REG_DWORD') {
    [string](Get-NSISInt -State $State -RelativeOffset $Entry.Values[4])
  } elseif ($EntryIndex -ge 0) {
    Resolve-NSISDirectString -State $State -RelativeOffset $Entry.Values[4] -EntryIndex $EntryIndex
  } else {
    Get-NSISString -State $State -RelativeOffset $Entry.Values[4]
  }

  return [pscustomobject]@{
    Root           = $Root
    Key            = $Key
    Name           = $Name
    Value          = $Value
    Type           = $RegistryKind
    RawType        = $Type
    RegistryType   = $RegistryType
    IsUninstallKey = $Key -match $Script:NSIS_UNINSTALL_KEY_PATTERN
    Opcode         = $Entry.Opcode
    RawOpcode      = $Entry.RawOpcode
  }
}

function Add-NSISRegistryWrite {
  <#
  .SYNOPSIS
    Store source-accurate EW_WRITEREG evidence and apply it to simulated registry state
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Entry
    The normalized NSIS command entry
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The normalized NSIS command entry')]
    [pscustomobject]$Entry
  )

  $Write = Get-NSISRegistryWriteFromEntry -State $State -Entry $Entry
  if (-not $Write) { return }

  $State.RegistryWrites.Add($Write)
  Set-NSISRegistryValue -State $State -Root $Write.Root -Key $Write.Key -Name $Write.Name -Value $Write.Value
}

function Add-NSISExecutedPayload {
  <#
  .SYNOPSIS
    Record static evidence that NSIS runs a nested payload
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Command
    The executed command or file
  .PARAMETER Parameters
    Optional command-line parameters
  .PARAMETER Kind
    The NSIS execution command kind
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The executed command or file')]
    [string]$Command,

    [AllowEmptyString()]
    [Parameter(HelpMessage = 'Optional command-line parameters')]
    [string]$Parameters = '',

    [Parameter(Mandatory, HelpMessage = 'The NSIS execution command kind')]
    [string]$Kind
  )

  if ([string]::IsNullOrWhiteSpace($Command)) { return }
  $State.ExecutedPayloads.Add([pscustomobject]@{
      Kind       = $Kind
      Command    = $Command
      Parameters = $Parameters
    })
}

function Get-NSISRegistryValue {
  <#
  .SYNOPSIS
    Read a value from the simulated NSIS registry
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Root
    The registry root
  .PARAMETER Key
    The registry key path
  .PARAMETER Name
    The registry value name
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The registry root')]
    [string]$Root,

    [Parameter(Mandatory, HelpMessage = 'The registry key path')]
    [string]$Key,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The registry value name')]
    [string]$Name
  )

  if ($State.Registry.ContainsKey($Root) -and $State.Registry[$Root].ContainsKey($Key) -and $State.Registry[$Root][$Key].ContainsKey($Name)) {
    return [string]$State.Registry[$Root][$Key][$Name]
  }

  return ''
}

function Remove-NSISRegistryValue {
  <#
  .SYNOPSIS
    Remove a value or key from the simulated NSIS registry
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Root
    The registry root
  .PARAMETER Key
    The registry key path
  .PARAMETER Name
    The registry value name, or an empty string to remove the whole key
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The registry root')]
    [string]$Root,

    [Parameter(Mandatory, HelpMessage = 'The registry key path')]
    [string]$Key,

    [AllowEmptyString()]
    [Parameter(Mandatory, HelpMessage = 'The registry value name, or an empty string to remove the whole key')]
    [string]$Name
  )

  if (-not ($State.Registry.ContainsKey($Root) -and $State.Registry[$Root].ContainsKey($Key))) { return }

  if ([string]::IsNullOrEmpty($Name)) {
    $null = $State.Registry[$Root].Remove($Key)
  } else {
    $null = $State.Registry[$Root][$Key].Remove($Name)
  }
}

function Get-NSISEntries {
  <#
  .SYNOPSIS
    Parse the NSIS opcode table from the decompressed header
  .PARAMETER HeaderBytes
    The decompressed NSIS header bytes
  .PARAMETER BlockHeaders
    The parsed NSIS block headers
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header bytes')]
    [byte[]]$HeaderBytes,

    [Parameter(Mandatory, HelpMessage = 'The parsed NSIS block headers')]
    [pscustomobject[]]$BlockHeaders,

    [Parameter(HelpMessage = 'The detected command layout')]
    [pscustomobject]$VersionInfo,

    [Parameter(HelpMessage = 'Whether the entry table uses eight NSISBI operands')]
    [bool]$IsNsisBi = $false
  )

  # Block 2 is the compiled command table. Its declared count and generation-
  # specific record width must fit before any operand is read.
  $EntryBlock = Get-NSISBlockBytes -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Index 2
  if ($BlockHeaders[2].Count -gt $Script:NSIS_MAX_ENTRY_COUNT) { throw 'The NSIS entry table exceeds the supported parser limit' }
  $EntryCount = [int]$BlockHeaders[2].Count
  $EntrySize = if ($IsNsisBi) { $Script:NSISBI_ENTRY_SIZE } else { $Script:NSIS_ENTRY_SIZE }
  $ValueCount = if ($IsNsisBi) { 9 } else { 7 }
  if ($EntryBlock.Length -lt ($EntryCount * $EntrySize)) { throw 'The NSIS entry table is truncated' }

  $Entries = [System.Collections.Generic.List[object]]::new()

  for ($EntryIndex = 0; $EntryIndex -lt $EntryCount; $EntryIndex++) {
    $Offset = $EntryIndex * $EntrySize
    $Raw = New-Object 'uint32[]' $ValueCount
    $Values = New-Object 'int[]' $ValueCount

    for ($ValueIndex = 0; $ValueIndex -lt $ValueCount; $ValueIndex++) {
      $ValueOffset = $Offset + ($ValueIndex * 4)
      $Raw[$ValueIndex] = [System.BitConverter]::ToUInt32($EntryBlock, $ValueOffset)
      $Values[$ValueIndex] = [System.BitConverter]::ToInt32($EntryBlock, $ValueOffset)
    }

    # Retain raw operands for source-accurate registry decoding while exposing a
    # normalized opcode for the static simulator.
    $LayoutOpcode = if ($IsNsisBi) { ConvertFrom-NSISBiOpcode -Opcode $Raw[0] } else { [int]$Raw[0] }
    $Opcode = if ($VersionInfo) {
      Get-NSISNormalizedOpcode -Opcode $LayoutOpcode -Type $VersionInfo.Type -Unicode $VersionInfo.Unicode -LogCmdIsEnabled $VersionInfo.LogCmdIsEnabled
    } else {
      $LayoutOpcode
    }

    $Entries.Add([pscustomobject]@{
        Opcode       = $Opcode
        RawOpcode    = $Raw[0]
        LayoutOpcode = $LayoutOpcode
        Raw          = $Raw
        Values       = $Values
      })
  }

  return $Entries.ToArray()
}

function Get-NSISSections {
  <#
  .SYNOPSIS
    Parse the NSIS section table so install sections can be simulated in order
  .PARAMETER HeaderBytes
    The decompressed NSIS header bytes
  .PARAMETER BlockHeaders
    The parsed NSIS block headers
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header bytes')]
    [byte[]]$HeaderBytes,

    [Parameter(Mandatory, HelpMessage = 'The parsed NSIS block headers')]
    [pscustomobject[]]$BlockHeaders
  )

  $SectionBlock = Get-NSISBlockBytes -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Index 1
  $SectionCount = [int]$BlockHeaders[1].Count
  if ($SectionCount -eq 0 -or $SectionBlock.Length -eq 0) { return @() }

  $SectionSize = [int]($SectionBlock.Length / $SectionCount)
  $Sections = [System.Collections.Generic.List[object]]::new()

  for ($SectionIndex = 0; $SectionIndex -lt $SectionCount; $SectionIndex++) {
    $Offset = $SectionIndex * $SectionSize
    $Sections.Add([pscustomobject]@{
        NameOffset = [System.BitConverter]::ToInt32($SectionBlock, $Offset + $Script:NSIS_SECTION_OFFSET_NAME)
        CodeOffset = [System.BitConverter]::ToInt32($SectionBlock, $Offset + $Script:NSIS_SECTION_OFFSET_CODE)
        CodeSize   = [System.BitConverter]::ToInt32($SectionBlock, $Offset + $Script:NSIS_SECTION_OFFSET_CODE_SIZE)
      })
  }

  return $Sections.ToArray()
}

function Initialize-NSISState {
  <#
  .SYNOPSIS
    Build the mutable execution state used for deterministic NSIS metadata parsing
  .PARAMETER HeaderData
    The decompressed NSIS header data
  .PARAMETER Architecture
    The target Windows architecture used to resolve source-backed runtime architecture checks
  .PARAMETER Scope
    The target installation scope used to resolve compiled MultiUser scope setters
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed NSIS header data')]
    [pscustomobject]$HeaderData,

    [Parameter(HelpMessage = 'The target Windows architecture used to resolve runtime architecture checks')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [Parameter(HelpMessage = 'The target installation scope used to resolve runtime scope checks')]
    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  $HeaderBytes = $HeaderData.HeaderBytes
  $BlockHeaders = Get-NSISBlockHeaders -HeaderBytes $HeaderBytes -Is64Bit $HeaderData.PEInfo.Is64Bit
  $Layout = Get-NSISHeaderLayout -HeaderBytes $HeaderBytes -Is64Bit $HeaderData.PEInfo.Is64Bit
  $StringsBlock = Get-NSISBlockBytes -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Index 3
  $LanguageTables = @(Get-NSISLanguageTable -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Layout $Layout)
  $LanguageTable = @($LanguageTables.Where({ $_.LanguageId -eq $Script:NSIS_DEFAULT_LANGUAGE }, 'First'))[0]
  if (-not $LanguageTable) { $LanguageTable = $LanguageTables | Select-Object -First 1 }
  $Entries = Get-NSISEntries -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -IsNsisBi $HeaderData.IsNsisBi
  $VersionInfo = Get-NSISVersionInfo -StringsBlock $StringsBlock -Entries $Entries -IsNsisBi $HeaderData.IsNsisBi
  # Account-sensitive NSIS plug-ins observe the installer's process token. Read
  # the PE manifest once so requireAdministrator installers can take the same
  # deterministic elevated branch without consulting the parser host's token.
  $RequestedExecutionLevel = try { Get-PERequestedExecutionLevel -Path $HeaderData.Path } catch { $null }
  $VersionInfo | Add-Member -NotePropertyName FirstHeaderFlags -NotePropertyValue $HeaderData.FirstHeaderFlags
  $VersionInfo | Add-Member -NotePropertyName HasLongDataBlockOffsets -NotePropertyValue $HeaderData.HasLongDataBlockOffsets
  $VersionInfo | Add-Member -NotePropertyName HasLargeFileSource -NotePropertyValue $HeaderData.HasLargeFileSource
  $VersionInfo | Add-Member -NotePropertyName SupportsExternalFiles -NotePropertyValue $HeaderData.SupportsExternalFiles
  $VersionInfo | Add-Member -NotePropertyName HasExternalFile -NotePropertyValue $HeaderData.HasExternalFile
  $VersionInfo | Add-Member -NotePropertyName IsStubInstaller -NotePropertyValue $HeaderData.IsStubInstaller
  foreach ($Entry in $Entries) {
    $Entry.Opcode = Get-NSISNormalizedOpcode -Opcode $Entry.LayoutOpcode -Type $VersionInfo.Type -Unicode $VersionInfo.Unicode -LogCmdIsEnabled $VersionInfo.LogCmdIsEnabled
  }

  $State = [pscustomobject]@{
    Path                = $HeaderData.Path
    Entries             = $Entries
    Sections            = Get-NSISSections -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders
    StringsBlock        = $StringsBlock
    LanguageTable       = $LanguageTable
    LanguageTables      = $LanguageTables
    VersionInfo         = $VersionInfo
    Variables           = @{}
    Registry            = @{}
    RegistryWrites      = [System.Collections.Generic.List[object]]::new()
    ExecutedPayloads    = [System.Collections.Generic.List[object]]::new()
    Warnings            = [System.Collections.Generic.List[string]]::new()
    Stack               = [System.Collections.Generic.List[string]]::new()
    SystemVariableStack = [System.Collections.Generic.List[object]]::new()
    Directories         = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Files               = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    ExecFlags           = @{}
    LastExecFlags       = @{}
    ShellVarContext     = $null
    TargetArchitecture  = $Architecture
    TargetScope         = $Scope
    Metadata            = [ordered]@{
      Path                               = $HeaderData.Path
      InstallerType                      = 'Nullsoft'
      TargetArchitecture                 = $Architecture
      HasArchitectureRuntimeCheck        = $false
      TargetScope                        = $Scope
      HasScopeRuntimeCheck               = $false
      SupportedScopes                    = [string[]]@()
      RequestedExecutionLevel            = $RequestedExecutionLevel
      IsTauri                            = $false
      TauriInstallerMode                 = $null
      TauriEvidence                      = [string[]]@()
      IsPortable                         = $false
      PortableEvidence                   = [string[]]@()
      ProductCode                        = $null
      UpgradeCode                        = $null
      DisplayName                        = $null
      DisplayVersion                     = $null
      Publisher                          = $null
      Scope                              = $null
      DefaultInstallLocation             = $null
      WritesAppsAndFeaturesEntry         = $false
      AppsAndFeaturesProductCode         = $null
      AppsAndFeaturesInstallerType       = $null
      Warnings                           = [string[]]@()
      UnresolvedFields                   = [string[]]@()
      UninstallString                    = $null
      QuietUninstallString               = $null
      DisplayIcon                        = $null
      SystemComponent                    = $null
      RegistryValues                     = @{}
      RegistryWrites                     = @()
      AppsAndFeaturesEntries             = @()
      AppsAndFeaturesEntryEvidence       = @()
      HasLocalizedAppsAndFeaturesEntries = $false
      Notices                            = [string[]]@()
      ExtractedFiles                     = @()
      ExecutedPayloads                   = @()
      ParserVersionInfo                  = $null
    }
  }

  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_EXEPATH -Value $HeaderData.Path
  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_EXEDIR -Value (Split-Path -Path $HeaderData.Path -Parent)
  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_EXEFILE -Value (Split-Path -Path $HeaderData.Path -Leaf)
  $LanguageId = if ($LanguageTable) { $LanguageTable.LanguageId } else { $Script:NSIS_DEFAULT_LANGUAGE }
  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_LANGUAGE -Value ([string]$LanguageId)
  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_TEMP -Value ([System.IO.Path]::GetTempPath().TrimEnd('\'))

  if ($HeaderData.IsNsisBi) {
    $State.Warnings.Add('The installer uses the NSISBI large-installer format; metadata was parsed from its expanded first-header and command layouts.')
  }
  if ($HeaderData.HasExternalFile) {
    $State.Warnings.Add('The NSISBI installer references an external payload file; embedded script metadata is available, but payload evidence may be incomplete without the sidecar file.')
  }

  # InstallDir and its auto-append suffix are stored as header pointers instead of script directives.
  if ($Layout.InstallDirectoryPointer -ne 0) {
    $InstallDirectory = Get-NSISString -State $State -RelativeOffset $Layout.InstallDirectoryPointer
    $AutoAppend = if ($Layout.InstallDirectoryAutoAppend -ne 0) { Get-NSISString -State $State -RelativeOffset $Layout.InstallDirectoryAutoAppend } else { '' }

    if (-not [string]::IsNullOrWhiteSpace($AutoAppend) -and -not $InstallDirectory.EndsWith($AutoAppend, [System.StringComparison]::OrdinalIgnoreCase)) {
      $InstallDirectory = Join-Path $InstallDirectory $AutoAppend
    }

    Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_INSTDIR -Value $InstallDirectory
    Add-NSISDirectory -State $State -Path $InstallDirectory
  }

  return [pscustomobject]@{
    State        = $State
    Layout       = $Layout
    BlockHeaders = $BlockHeaders
  }
}

function Pop-NSISStackValue {
  <#
  .SYNOPSIS
    Remove and return the value at the top of the simulated NSIS stack
  .PARAMETER State
    The mutable NSIS execution state that owns the stack
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  if ($State.Stack.Count -eq 0) { return '' }
  $Index = $State.Stack.Count - 1
  $Value = [string]$State.Stack[$Index]
  $State.Stack.RemoveAt($Index)
  return $Value
}

function Get-NSISNativeMachineValue {
  <#
  .SYNOPSIS
    Convert a WinGet architecture into the IMAGE_FILE_MACHINE value returned by Windows
  .PARAMETER Architecture
    The target Windows architecture
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The target Windows architecture')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  switch ($Architecture) {
    'x86' { return $Script:NSIS_IMAGE_FILE_MACHINE_I386 }
    'x64' { return $Script:NSIS_IMAGE_FILE_MACHINE_AMD64 }
    'arm64' { return $Script:NSIS_IMAGE_FILE_MACHINE_ARM64 }
  }
}

function Resolve-NSISKnownFolderPath {
  <#
  .SYNOPSIS
    Resolve a compiled Windows known-folder identifier without querying the parser host shell
  .DESCRIPTION
    NSIS 3 GetKnownFolderPath and older System plug-in macros carry the same
    canonical GUID. Only installer-related folders derived from stable Windows
    environment roots are resolved. Redirectable content folders such as
    Desktop, Documents, and Downloads remain unresolved because synthesizing
    them below the parser host's profile would contradict the target machine's
    SHGetKnownFolderPath result. Unknown identifiers return an empty string,
    matching the NSIS runtime's failed-call destination.
  .PARAMETER FolderId
    The brace-delimited known-folder GUID compiled into the NSIS string table
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The brace-delimited Windows known-folder GUID')]
    [string]$FolderId
  )

  $ParsedFolderId = [guid]::Empty
  if (-not [guid]::TryParse($FolderId, [ref]$ParsedFolderId)) { return '' }
  $CanonicalFolderId = $ParsedFolderId.ToString('B').ToUpperInvariant()

  # Resolve from well-known environment roots so paths are deterministic and
  # ConvertTo-NSISManifestPath can normalize them without retaining a username
  # or drive letter. Do not call SHGetKnownFolderPath on the parser host.
  $WindowsDirectory = $Script:NSIS_WINDOWS_DIRECTORY
  $SystemDirectory = $Script:NSIS_SYSTEM_DIRECTORY
  $SystemX86Directory = if ([Environment]::Is64BitOperatingSystem) { Join-Path $WindowsDirectory 'SysWOW64' } else { $SystemDirectory }
  $ProgramFiles64 = if (${env:ProgramW6432}) { ${env:ProgramW6432} } else { $env:ProgramFiles }
  $ProgramFilesX86 = if (${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} } else { $ProgramFiles64 }
  $CommonProgramFiles64 = if (${env:CommonProgramW6432}) { ${env:CommonProgramW6432} } else { $env:CommonProgramFiles }
  $CommonProgramFilesX86 = if (${env:CommonProgramFiles(x86)}) { ${env:CommonProgramFiles(x86)} } else { $CommonProgramFiles64 }
  $UserStartMenu = if ($env:APPDATA) { Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu' } else { $null }
  $CommonStartMenu = if ($env:ProgramData) { Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu' } else { $null }

  switch ($CanonicalFolderId) {
    # Application-data and machine-data roots.
    '{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}' { return [string]$env:LOCALAPPDATA } # FOLDERID_LocalAppData
    '{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}' { return [string]$env:APPDATA } # FOLDERID_RoamingAppData
    '{A520A1A4-1780-4FF6-BD18-167343C5AF16}' { return $(if ($env:USERPROFILE) { Join-Path $env:USERPROFILE 'AppData\LocalLow' } else { '' }) } # FOLDERID_LocalAppDataLow
    '{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}' { return [string]$env:ProgramData } # FOLDERID_ProgramData
    '{5E6C858F-0E22-4760-9AFE-EA3317B67173}' { return [string]$env:USERPROFILE } # FOLDERID_Profile

    # Windows and system roots.
    '{F38BF404-1D43-42F2-9305-67DE0B28FC23}' { return $WindowsDirectory } # FOLDERID_Windows
    '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}' { return $SystemDirectory } # FOLDERID_System
    '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}' { return $SystemX86Directory } # FOLDERID_SystemX86
    '{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}' { return Join-Path $WindowsDirectory 'Fonts' } # FOLDERID_Fonts

    # Program Files and Common Files variants. Generic IDs use the native
    # Program Files roots, while explicit X86/X64 IDs retain their bitness.
    '{905E63B6-C1BF-494E-B29C-65B732D3D21A}' { return [string]$ProgramFiles64 } # FOLDERID_ProgramFiles
    '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}' { return [string]$ProgramFilesX86 } # FOLDERID_ProgramFilesX86
    '{6D809377-6AF0-444B-8957-A3773F02200E}' { return [string]$ProgramFiles64 } # FOLDERID_ProgramFilesX64
    '{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}' { return [string]$CommonProgramFiles64 } # FOLDERID_ProgramFilesCommon
    '{DE974D24-D9C6-4D3E-BF91-F4455120B917}' { return [string]$CommonProgramFilesX86 } # FOLDERID_ProgramFilesCommonX86
    '{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}' { return [string]$CommonProgramFiles64 } # FOLDERID_ProgramFilesCommonX64
    $Script:NSIS_FOLDER_ID_USER_PROGRAM_FILES { return $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Programs' } else { '' }) }
    '{BCBD3057-CA5C-4622-B42D-BC56DB0AE516}' { return $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Programs\Common' } else { '' }) } # FOLDERID_UserProgramFilesCommon

    # Per-user Start Menu folders.
    '{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}' { return [string]$UserStartMenu } # FOLDERID_StartMenu
    '{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}' { return $(if ($UserStartMenu) { Join-Path $UserStartMenu 'Programs' } else { '' }) } # FOLDERID_Programs
    '{B97D20BB-F46A-4C97-BA10-5E3608430854}' { return $(if ($UserStartMenu) { Join-Path $UserStartMenu 'Programs\Startup' } else { '' }) } # FOLDERID_Startup
    '{724EF170-A42D-4FEF-9F26-B60E846FBA4F}' { return $(if ($UserStartMenu) { Join-Path $UserStartMenu 'Programs\Administrative Tools' } else { '' }) } # FOLDERID_AdminTools

    # All-users Start Menu folders.
    '{A4115719-D62E-491D-AA7C-E74B8BE3B067}' { return [string]$CommonStartMenu } # FOLDERID_CommonStartMenu
    '{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}' { return $(if ($CommonStartMenu) { Join-Path $CommonStartMenu 'Programs' } else { '' }) } # FOLDERID_CommonPrograms
    '{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}' { return $(if ($CommonStartMenu) { Join-Path $CommonStartMenu 'Programs\Startup' } else { '' }) } # FOLDERID_CommonStartup
    '{D0384E7D-BAC3-4797-8F14-CBA229B392B5}' { return $(if ($CommonStartMenu) { Join-Path $CommonStartMenu 'Programs\Administrative Tools' } else { '' }) } # FOLDERID_CommonAdminTools
    default { return '' }
  }
}

function Get-NSISOsInfoMemoryValue {
  <#
  .SYNOPSIS
    Resolve source-generated GetWinVer reads from the NSIS runtime ABI block
  .DESCRIPTION
    NSIS compiles GetWinVer to EW_GETOSINFO/READMEMORY against an eight-byte
    osinfo record following fourteen 32-bit execution flags. Dumplings models
    the Windows 10 1809 baseline supported by WinGet instead of leaking the
    parser host's OS version into static installer control flow. Arbitrary
    ReadMemory addresses and unrecognized byte ranges remain unresolved.
  .PARAMETER Address
    The compiled source address; zero is NSIS ABI_OSINFOADDRESS
  .PARAMETER Specification
    Packed byte count in bits 0..7 and osinfo byte offset in bits 24..31
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The compiled memory address')]
    [long]$Address,

    [Parameter(Mandatory, HelpMessage = 'The packed byte-count and osinfo offset')]
    [uint32]$Specification
  )

  if ($Address -ne 0) { return $null }
  $ByteCount = [int]($Specification -band 0xFF)
  $FieldOffset = [int]($Specification -shr 24) - $Script:NSIS_ABI_OS_INFO_OFFSET

  # This mirrors little-endian mini_memcpy from NSIS exec.c. The two-byte
  # major/minor form starts at WVMin, so major occupies the high byte.
  switch ("$FieldOffset`:$ByteCount") {
    '0:4' { return [string]$Script:NSIS_TARGET_WINDOWS_BUILD }
    '4:1' { return [string]$Script:NSIS_TARGET_WINDOWS_PRODUCT }
    '5:1' { return [string]$Script:NSIS_TARGET_WINDOWS_SERVICE_PACK }
    '6:1' { return [string]$Script:NSIS_TARGET_WINDOWS_MINOR }
    '7:1' { return [string]$Script:NSIS_TARGET_WINDOWS_MAJOR }
    '6:2' { return [string](($Script:NSIS_TARGET_WINDOWS_MAJOR -shl 8) -bor $Script:NSIS_TARGET_WINDOWS_MINOR) }
    default { return $null }
  }
}

function Invoke-NSISSystemPluginCall {
  <#
  .SYNOPSIS
    Simulate deterministic NSIS System plug-in operations used by installer scripts
  .DESCRIPTION
    NSIS compiles System::Call arguments as stack pushes followed by EW_REGISTERDLL.
    This helper consumes those arguments where the plug-in would and models the
    known-folder and Windows architecture APIs used by electron-builder and
    x64.nsh. System::Store is also modeled because electron-builder protects
    its temporary registers around the legacy Windows 7 known-folder path.
    Other calls receive empty outputs rather than values derived from the
    parser host.
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER FunctionName
    The exported System plug-in function invoked by EW_REGISTERDLL
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The exported System plug-in function')]
    [string]$FunctionName
  )

  if ($FunctionName -ieq 'Int64Op') {
    # System::Int64Op pops ARG1, OP, and ARG2, then pushes one result. x64.nsh
    # uses bitwise OR to combine IsWow64Process2 with its legacy fallback.
    $LeftText = Pop-NSISStackValue -State $State
    $Operator = Pop-NSISStackValue -State $State
    $RightText = if ($Operator -in @('~', '!')) { '0' } else { Pop-NSISStackValue -State $State }
    $Left = 0L
    $Right = 0L
    $null = [long]::TryParse($LeftText, [ref]$Left)
    $null = [long]::TryParse($RightText, [ref]$Right)
    $Result = switch ($Operator) {
      '|' { $Left -bor $Right }
      '||' { [long]($Left -ne 0 -or $Right -ne 0) }
      default { 0L }
    }
    $State.Stack.Add([string]$Result)
    return $true
  }

  if ($FunctionName -ieq 'Store') {
    # System::Store consumes a compact operation string. S/L save and restore
    # all general registers on the plug-in's private stack; p/r transfer one
    # numbered register through the ordinary NSIS stack. This follows
    # Contrib/System/Source/Buffers.c instead of treating Store as a no-op.
    $Command = Pop-NSISStackValue -State $State
    if (-not $State.PSObject.Properties['SystemVariableStack']) {
      $State | Add-Member -NotePropertyName SystemVariableStack -NotePropertyValue ([System.Collections.Generic.List[object]]::new())
    }

    for ($Index = 0; $Index -lt $Command.Length; $Index++) {
      switch -CaseSensitive ($Command[$Index]) {
        { $_ -in @('s', 'S') } {
          $Snapshot = [string[]]::new(20)
          for ($RegisterIndex = 0; $RegisterIndex -lt $Snapshot.Length; $RegisterIndex++) {
            $Snapshot[$RegisterIndex] = Get-NSISVariableValue -State $State -Index $RegisterIndex
          }
          $State.SystemVariableStack.Add($Snapshot)
        }
        { $_ -in @('l', 'L') } {
          if ($State.SystemVariableStack.Count -eq 0) { continue }
          $SnapshotIndex = $State.SystemVariableStack.Count - 1
          $Snapshot = $State.SystemVariableStack[$SnapshotIndex]
          $State.SystemVariableStack.RemoveAt($SnapshotIndex)
          for ($RegisterIndex = 0; $RegisterIndex -lt 20; $RegisterIndex++) {
            # These indexes are exactly $0-$9 and $R0-$R9, so restoring them
            # cannot alter predefined paths such as $INSTDIR or $OUTDIR.
            $State.Variables[$RegisterIndex] = [string]$Snapshot[$RegisterIndex]
          }
        }
        { $_ -in @('p', 'P') } {
          if ($Index + 1 -ge $Command.Length -or -not [char]::IsDigit($Command[$Index + 1])) { continue }
          $RegisterIndex = [int][char]::GetNumericValue($Command[++$Index])
          if ($_ -ceq 'P') { $RegisterIndex += 10 }
          $State.Stack.Add((Get-NSISVariableValue -State $State -Index $RegisterIndex))
        }
        { $_ -in @('r', 'R') } {
          if ($Index + 1 -ge $Command.Length -or -not [char]::IsDigit($Command[$Index + 1])) { continue }
          $RegisterIndex = [int][char]::GetNumericValue($Command[++$Index])
          if ($_ -ceq 'R') { $RegisterIndex += 10 }
          Set-NSISVariableValue -State $State -Index $RegisterIndex -Value (Pop-NSISStackValue -State $State)
        }
      }
    }
    return $true
  }

  if ($FunctionName -ine 'Call') { return $false }
  $Command = Pop-NSISStackValue -State $State
  if ([string]::IsNullOrWhiteSpace($Command)) { return $true }

  if ($Command -match '(?i)SHELL32::SHGetKnownFolderPath\(g\s+"?(?<FolderId>\{[0-9A-F-]{36}\})"?.*\*p\s+\.r(?<PathRegister>\d+)\)i\.r(?<ResultRegister>\d+)') {
    # electron-builder resolves FOLDERID_UserProgramFiles and copies the
    # allocated result into its per-user installation root. The System plug-in
    # writes both values directly to NSIS variables; neither value is pushed.
    $KnownFolderPath = Resolve-NSISKnownFolderPath -FolderId $Matches.FolderId
    Set-NSISVariableValue -State $State -Index ([int]$Matches.PathRegister) -Value $KnownFolderPath
    Set-NSISVariableValue -State $State -Index ([int]$Matches.ResultRegister) -Value $(if ($KnownFolderPath) { '0' } else { '-2147024894' })
    return $true
  }

  if ($Command -match '(?i)KERNEL32::lstrcpynW\(w\s+\.r(?<DestinationRegister>\d+)\s*,\s*p\s+r(?<SourceRegister>\d+)') {
    # lstrcpynW writes into the destination buffer represented by the direct
    # NSIS register operand. Copy the deterministic source value without
    # attempting to model the transient native pointer.
    $SourceValue = Get-NSISVariableValue -State $State -Index ([int]$Matches.SourceRegister)
    Set-NSISVariableValue -State $State -Index ([int]$Matches.DestinationRegister) -Value $SourceValue
    return $true
  }

  if ($Command -match '(?i)OLE32::CoTaskMemFree\(') {
    # The allocation belongs to the simulated shell call; freeing it has no
    # additional script-visible output.
    return $true
  }

  if ($Command -match '(?i)kernel32::GetCurrentProcess\(\)p\.s') {
    # The pseudo handle is only consumed by later static API emulation.
    $State.Stack.Add('-1')
    return $true
  }

  if ($Command -match '(?i)kernel32::IsWow64Process2\((?<Arguments>[^)]*)\)') {
    # Architecture-dependent calls need an explicit target. Keep the stack
    # contract deterministic when the caller requested architecture-neutral
    # metadata, but do not derive the result from the parser host.
    $Architecture = [string]$State.TargetArchitecture
    $NativeMachine = if ($Architecture) { Get-NSISNativeMachineValue -Architecture $Architecture } else { 0 }
    $Arguments = @($Matches.Arguments -split '\s*,\s*')
    if ($Arguments.Count -gt 0 -and $Arguments[0] -match '(?i)^ps$') {
      $null = Pop-NSISStackValue -State $State
    }

    # A 32-bit stub reports I386 as its process machine on x64/ARM64 and zero
    # when it runs natively on x86. The second output is the native OS machine.
    $ProcessMachine = if ($Architecture -eq 'x86') { 0 } else { $Script:NSIS_IMAGE_FILE_MACHINE_I386 }
    for ($Index = 1; $Index -lt $Arguments.Count; $Index++) {
      if ($Arguments[$Index] -notmatch '(?i)^\*[^,]*s$') { continue }
      $OutputMachine = if ($Index -eq 1) { $ProcessMachine } else { $NativeMachine }
      $State.Stack.Add([string]$OutputMachine)
    }
    return $true
  }

  if ($Command -match '(?i)kernel32::IsWow64Process\((?<Arguments>[^)]*)\)') {
    $Architecture = [string]$State.TargetArchitecture
    $Arguments = @($Matches.Arguments -split '\s*,\s*')
    if ($Arguments.Count -gt 0 -and $Arguments[0] -match '(?i)^ps$') {
      $null = Pop-NSISStackValue -State $State
    }

    # The legacy API returns FALSE for native x86 and for x86 emulation on
    # ARM64. Current x64.nsh combines it with IsWow64Process2 on ARM64.
    $IsWow64 = [int]($Architecture -eq 'x64')
    foreach ($Argument in $Arguments | Select-Object -Skip 1) {
      if ($Argument -match '(?i)^\*[^,]*s$') { $State.Stack.Add([string]$IsWow64) }
    }
    return $true
  }

  if ($Command -match '(?i)^\*0x7FFE002E\(&i2\.s\)') {
    # GetNativeMachineArchitecture reads this shared-user-data processor field
    # as the fallback on Windows versions predating IsWow64Process2.
    $Architecture = [string]$State.TargetArchitecture
    $NativeMachine = if ($Architecture) { Get-NSISNativeMachineValue -Architecture $Architecture } else { 0 }
    $State.Stack.Add([string]$NativeMachine)
    return $true
  }

  # Consume unsupported System::Call input like the real plug-in. Direct .rN
  # outputs write variables, whereas .s outputs are pushed onto the NSIS stack.
  # Preserve those contracts without fabricating values from the parser host.
  foreach ($RegisterMatch in [regex]::Matches($Command, '(?i)\.r(?<Register>\d+)')) {
    Set-NSISVariableValue -State $State -Index ([int]$RegisterMatch.Groups['Register'].Value) -Value ''
  }
  if ($Command -match '\((?<Arguments>[^)]*)\)') {
    foreach ($Argument in @($Matches.Arguments -split '\s*,\s*')) {
      if ($Argument -match '(?i)^\*[^,]*s$') { $State.Stack.Add('') }
    }
  }
  if ($Command -match '(?i)\)[a-z0-9&*]+\.s(?:\s|$)') { $State.Stack.Add('') }
  return $true
}

function Invoke-NSISUserInfoPluginCall {
  <#
  .SYNOPSIS
    Simulate deterministic outputs from the standard NSIS UserInfo plug-in
  .DESCRIPTION
    UserInfo reads the process token and pushes its result onto the NSIS stack.
    A requireAdministrator PE necessarily runs with an administrator token once
    its code starts, so GetAccountType deterministically returns Admin. Account
    membership under asInvoker or highestAvailable remains runtime-dependent;
    those calls retain the simulator's previous no-op behavior rather than
    being derived from the parser host or a requested manifest scope.
  .PARAMETER State
    The mutable NSIS execution state whose stack receives the plug-in result
  .PARAMETER FunctionName
    The UserInfo.dll export invoked by EW_REGISTERDLL
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The exported UserInfo plug-in function')]
    [string]$FunctionName
  )

  if ($FunctionName -ieq 'GetName' -and $State.Metadata.RequestedExecutionLevel -eq 'requireAdministrator') {
    # The caller normally uses GetName only to establish that UserInfo can read
    # the token. Return a stable, nonempty symbolic value so scripts that test
    # the result follow the supported Windows path without leaking the parser
    # host's actual account name.
    $State.Stack.Add('<current-user>')
    return $true
  }

  if ($FunctionName -notin @('GetAccountType', 'GetOriginalAccountType')) { return $false }
  if ($State.Metadata.RequestedExecutionLevel -ne 'requireAdministrator') { return $false }

  # NSIS calls the plug-in only after Windows has granted the requested
  # elevated token. Rejecting UAC means installer code never executes.
  $State.Stack.Add('Admin')
  return $true
}

function Get-NSISArchitectureProbeStart {
  <#
  .SYNOPSIS
    Locate the start of a compiled NSIS x64.nsh architecture probe
  .PARAMETER State
    The mutable NSIS execution state containing normalized command entries
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  for ($Index = 0; $Index -lt $State.Entries.Count; $Index++) {
    $Entry = $State.Entries[$Index]
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_PUSH_POP -or $Entry.Values[2] -ne 0) { continue }
    $Command = Get-NSISString -State $State -RelativeOffset $Entry.Values[1]
    if ($Command -notmatch '(?i)kernel32::IsWow64Process2?\(') { continue }

    # x64.nsh first pushes GetCurrentProcess, then invokes one or both WOW64
    # APIs. Start there so the System plug-in stack contract remains intact.
    $MinimumIndex = [Math]::Max(0, $Index - 24)
    for ($Candidate = $Index - 1; $Candidate -ge $MinimumIndex; $Candidate--) {
      $CandidateEntry = $State.Entries[$Candidate]
      if ($CandidateEntry.Opcode -ne $Script:NSIS_OPCODE_PUSH_POP -or $CandidateEntry.Values[2] -ne 0) { continue }
      $CandidateCommand = Get-NSISString -State $State -RelativeOffset $CandidateEntry.Values[1]
      if ($CandidateCommand -match '(?i)kernel32::GetCurrentProcess\(\)') { return $Candidate }
    }
  }

  return -1
}

function Get-NSISScopeSelectionStart {
  <#
  .SYNOPSIS
    Locate a compiled NSIS function that selects one installation scope
  .DESCRIPTION
    NSIS MultiUser templates compile their scope setters to a mode assignment
    followed by SetShellVarContext. Some Tauri-derived templates instead compare
    an already-selected mode with AllUsers immediately before changing context.
    These structural pairs are stronger evidence than switch text and let the
    simulator enter the selected branch without modeling UAC UI.
  .PARAMETER State
    The mutable NSIS execution state containing normalized command entries
  .PARAMETER Scope
    The scope whose compiled setter should be located
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The installation scope whose compiled setter should be located')]
    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  $ModeNames = if ($Scope -eq 'machine') {
    [string[]]@('AllUsers', 'all')
  } else {
    [string[]]@('CurrentUser')
  }
  $ExpectedContext = if ($Scope -eq 'machine') { 1 } else { 0 }

  for ($Index = 0; $Index -lt $State.Entries.Count; $Index++) {
    $Entry = $State.Entries[$Index]
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_ASSIGN_VAR) { continue }

    try { $AssignedValue = Get-NSISString -State $State -RelativeOffset $Entry.Values[2] } catch { continue }
    if ($ModeNames -cnotcontains $AssignedValue) { continue }

    # Require the nearby shell-context opcode so unrelated variables named
    # AllUsers or CurrentUser cannot become scope-selector false positives.
    $ContextEntry = $null
    for ($Candidate = $Index + 1; $Candidate -le [Math]::Min($Index + 4, $State.Entries.Count - 1); $Candidate++) {
      $CandidateEntry = $State.Entries[$Candidate]
      if ($CandidateEntry.Opcode -ne $Script:NSIS_OPCODE_SET_FLAG -or
        $CandidateEntry.Values[1] -ne $Script:NSIS_EXEC_FLAG_SHELL_VAR_CONTEXT) { continue }
      if ((Get-NSISInt -State $State -RelativeOffset $CandidateEntry.Values[2]) -ne $ExpectedContext) { continue }
      $ContextEntry = $CandidateEntry
      break
    }
    if (-not $ContextEntry) { continue }

    # Include the idempotence comparison at the function entrance when present.
    # Starting there preserves the source macro's normal return behavior.
    if ($Index -ge 2 -and $State.Entries[$Index - 1].Opcode -eq $Script:NSIS_OPCODE_RETURN -and
      $State.Entries[$Index - 2].Opcode -eq $Script:NSIS_OPCODE_STR_CMP) {
      $Comparison = $State.Entries[$Index - 2]
      $Left = Get-NSISString -State $State -RelativeOffset $Comparison.Values[1]
      $Right = Get-NSISString -State $State -RelativeOffset $Comparison.Values[2]
      if ($ModeNames -ccontains $Left -or $ModeNames -ccontains $Right) { return $Index - 2 }
    }

    return $Index
  }

  # Custom Tauri templates can select the mode earlier, then guard the machine
  # context with `StrCmp $MultiUser.InstallMode AllUsers 0 <user-branch>`. Accept
  # only an equality fall-through directly into the matching context opcode;
  # this avoids treating dormant uninstaller or unrelated mode strings as an
  # installer scope selector.
  for ($Index = 1; $Index -lt $State.Entries.Count; $Index++) {
    $ContextEntry = $State.Entries[$Index]
    if ($ContextEntry.Opcode -ne $Script:NSIS_OPCODE_SET_FLAG -or
      $ContextEntry.Values[1] -ne $Script:NSIS_EXEC_FLAG_SHELL_VAR_CONTEXT) { continue }
    if ((Get-NSISInt -State $State -RelativeOffset $ContextEntry.Values[2]) -ne $ExpectedContext) { continue }

    # A section can contain a similar comparison for updater or payload logic.
    # NSIS records each section's exact command range, so exclude those records
    # and accept only initialization callbacks or helper functions here.
    $IsSectionInstruction = $false
    foreach ($Section in $State.Sections) {
      if ($Section.CodeOffset -lt 0 -or $Section.CodeSize -le 0) { continue }
      $SectionEnd = [long]$Section.CodeOffset + $Section.CodeSize
      if ($Index - 1 -ge $Section.CodeOffset -and $Index - 1 -lt $SectionEnd) {
        $IsSectionInstruction = $true
        break
      }
    }
    if ($IsSectionInstruction) { continue }

    $Comparison = $State.Entries[$Index - 1]
    if ($Comparison.Opcode -ne $Script:NSIS_OPCODE_STR_CMP -or $Comparison.Values[3] -ne 0) { continue }
    $Left = Get-NSISString -State $State -RelativeOffset $Comparison.Values[1]
    $Right = Get-NSISString -State $State -RelativeOffset $Comparison.Values[2]
    if ($ModeNames -ccontains $Left -or $ModeNames -ccontains $Right) { return $Index - 1 }
  }

  return -1
}

function Initialize-NSISScopeSelectionInput {
  <#
  .SYNOPSIS
    Seed a requested mode variable for an equality-guarded scope branch
  .DESCRIPTION
    Some custom Tauri installers parse /AllUsers before entering a branch that
    compares $MultiUser.InstallMode with AllUsers. Static simulation enters that
    branch directly, so it must reproduce the already-parsed mode value first.
    This helper accepts only a direct variable-versus-literal comparison whose
    equality path falls through to the matching SetShellVarContext instruction.
  .PARAMETER State
    The mutable NSIS execution state containing normalized command entries
  .PARAMETER Position
    The zero-based command index returned by Get-NSISScopeSelectionStart
  .PARAMETER Scope
    The requested user or machine installation scope
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The zero-based scope-selector command index')]
    [int]$Position,

    [Parameter(Mandatory, HelpMessage = 'The requested installation scope')]
    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  if ($Position -lt 0 -or $Position + 1 -ge $State.Entries.Count) { return }

  $Comparison = $State.Entries[$Position]
  $ContextEntry = $State.Entries[$Position + 1]
  $ExpectedContext = if ($Scope -eq 'machine') { 1 } else { 0 }
  if ($Comparison.Opcode -ne $Script:NSIS_OPCODE_STR_CMP -or $Comparison.Values[3] -ne 0 -or
    $ContextEntry.Opcode -ne $Script:NSIS_OPCODE_SET_FLAG -or
    $ContextEntry.Values[1] -ne $Script:NSIS_EXEC_FLAG_SHELL_VAR_CONTEXT -or
    (Get-NSISInt -State $State -RelativeOffset $ContextEntry.Values[2]) -ne $ExpectedContext) { return }

  $ModeNames = if ($Scope -eq 'machine') { [string[]]@('AllUsers', 'all') } else { [string[]]@('CurrentUser') }
  foreach ($VariableOperand in 1, 2) {
    $LiteralOperand = if ($VariableOperand -eq 1) { 2 } else { 1 }
    $LiteralValue = Get-NSISString -State $State -RelativeOffset $Comparison.Values[$LiteralOperand]
    if ($ModeNames -cnotcontains $LiteralValue) { continue }

    # Require the other operand to consist of one direct variable value. This
    # prevents seeding variables referenced only as part of a larger string.
    $VariableIndexes = @(Get-NSISStringVariableIndex -State $State -RelativeOffset $Comparison.Values[$VariableOperand])
    if ($VariableIndexes.Count -ne 1) { continue }
    $VariableValue = Get-NSISVariableValue -State $State -Index $VariableIndexes[0]
    $ResolvedOperand = Get-NSISString -State $State -RelativeOffset $Comparison.Values[$VariableOperand]
    if ($ResolvedOperand -cne $VariableValue) { continue }

    Set-NSISVariableValue -State $State -Index $VariableIndexes[0] -Value $LiteralValue
    return
  }
}

function Initialize-NSISTargetRegistryState {
  <#
  .SYNOPSIS
    Remove registry evidence collected before an explicit runtime branch is selected
  .DESCRIPTION
    Initialization can visit a default architecture or scope path before the
    caller-requested branch is applied. Clearing only registry-derived metadata
    preserves other initialized variables while preventing alternate ARP entries
    from contaminating the targeted result.
  .PARAMETER State
    The mutable NSIS execution state to reset
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state to reset')]
    [pscustomobject]$State
  )

  $State.Registry.Clear()
  $State.RegistryWrites.Clear()
  foreach ($Name in @('ProductCode', 'DisplayName', 'DisplayVersion', 'Publisher', 'Scope', 'DefaultInstallLocation', 'UninstallString', 'QuietUninstallString', 'DisplayIcon', 'SystemComponent')) {
    $State.Metadata[$Name] = $null
  }
  $State.Metadata.RegistryValues = @{}
  $State.Metadata.WritesAppsAndFeaturesEntry = $false
  $State.Metadata.AppsAndFeaturesProductCode = $null
  $State.Metadata.AppsAndFeaturesInstallerType = $null
  $State.Metadata.AppsAndFeaturesEntries = @()
  $State.Metadata.AppsAndFeaturesEntryEvidence = @()
}

function Add-NSISDirectUninstallWrites {
  <#
  .SYNOPSIS
    Apply direct uninstall registry writes that can be recovered without executing control flow
  .PARAMETER State
    The mutable NSIS execution state
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  foreach ($Write in @(Get-NSISDirectUninstallWrites -State $State)) {
    $State.RegistryWrites.Add($Write)
    Set-NSISRegistryValue -State $State -Root $Write.Root -Key $Write.Key -Name $Write.Name -Value $Write.Value
  }
}

function Get-NSISDirectUninstallWrites {
  <#
  .SYNOPSIS
    Decode explicit uninstall-key writes without following installer control flow
  .PARAMETER State
    The mutable NSIS execution state whose current variables and shell context resolve operands
  .OUTPUTS
    Source-backed EW_WRITEREG evidence in command-table order
  #>
  [OutputType([object[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  $Writes = [System.Collections.Generic.List[object]]::new()
  for ($EntryIndex = 0; $EntryIndex -lt $State.Entries.Count; $EntryIndex++) {
    $Entry = $State.Entries[$EntryIndex]
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_WRITE_REG) { continue }
    $Write = Get-NSISRegistryWriteFromEntry -State $State -Entry $Entry -EntryIndex $EntryIndex
    if ($Write -and $Write.IsUninstallKey) { $Writes.Add($Write) }
  }
  return [object[]]$Writes.ToArray()
}

function Add-NSISUnambiguousTargetUninstallWrites {
  <#
  .SYNOPSIS
    Recover stable ARP identity when targeted section simulation stops before registry creation
  .DESCRIPTION
    Custom installer hooks can abort static section simulation before a standard
    registry macro runs. This fallback accepts compiled EW_WRITEREG evidence only
    when uninstall writes in the hive selected by the requested scope resolve to
    one key. Writes compiled for another scope are ignored because templates can
    retain both HKCU and HKLM command paths even when only one is reachable.
    Branch-dependent command strings are deliberately left unresolved because a
    lexical scan cannot prove their runtime assignments.
  .PARAMETER State
    The mutable NSIS execution state after target scope selection and section simulation
  .OUTPUTS
    True when one deterministic uninstall identity was applied; otherwise false
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The targeted NSIS execution state')]
    [pscustomobject]$State
  )

  if ([string]::IsNullOrWhiteSpace([string]$State.TargetScope)) { return $false }
  $ExpectedRoot = $State.TargetScope -eq 'machine' ? 'HKLM' : 'HKCU'
  $Candidates = @(Get-NSISDirectUninstallWrites -State $State | Where-Object Root -CEQ $ExpectedRoot)
  if ($Candidates.Count -eq 0) { return $false }

  $Identities = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($Candidate in $Candidates) { $null = $Identities.Add("$($Candidate.Root)`0$($Candidate.Key)") }
  if ($Identities.Count -ne 1) { return $false }

  # DisplayName and DisplayVersion prove that the single key is an ARP entry,
  # rather than an unrelated helper value under an uninstall-like path.
  $Names = @($Candidates.Name)
  if ('DisplayName' -cnotin $Names -or 'DisplayVersion' -cnotin $Names) { return $false }

  $StableNames = @('DisplayName', 'DisplayVersion', 'Publisher', 'SystemComponent')
  foreach ($Write in @($Candidates | Where-Object Name -CIn $StableNames)) {
    $State.RegistryWrites.Add($Write)
    Set-NSISRegistryValue -State $State -Root $Write.Root -Key $Write.Key -Name $Write.Name -Value $Write.Value
  }

  # The standard electron-builder registry macro composes these values from
  # scope-dependent registers. Preserve that limitation explicitly instead of
  # reporting a lexically nearest but potentially wrong switch or path.
  $DynamicNames = @('UninstallString', 'QuietUninstallString', 'DisplayIcon') | Where-Object { $_ -cin $Names }
  $State.Metadata.UnresolvedFields = [string[]]@($State.Metadata.UnresolvedFields + $DynamicNames | Select-Object -Unique)
  return [bool]$State.Metadata.WritesAppsAndFeaturesEntry
}

function Invoke-NSISCodeSegment {
  <#
  .SYNOPSIS
    Simulate a compiled NSIS code segment until it returns
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Position
    The starting entry index
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The starting entry index')]
    [int]$Position
  )

  $Watchdog = 0
  $WatchdogLimit = [Math]::Max($State.Entries.Count * $Script:NSIS_MAX_WATCHDOG_MULTIPLIER, 1)

  # Follow only statically resolvable control flow. Every dispatched instruction
  # consumes watchdog budget so loops and recursive callback patterns fail fast.
  while ($Position -ge 0 -and $Position -lt $State.Entries.Count) {
    $Result = Invoke-NSISEntry -State $State -Entry $State.Entries[$Position]

    if ($Result.Action -eq 'Return' -or $Result.Action -eq 'Quit' -or $Result.Action -eq 'Abort') {
      return $Result.Action
    }

    $ResolvedAddress = Resolve-NSISAddress -State $State -Address $Result.Address
    if ($ResolvedAddress -eq 0) {
      $Position++
    } else {
      $Position = $ResolvedAddress - 1
    }

    $Watchdog++
    if ($Watchdog -gt $WatchdogLimit) { throw 'The NSIS code segment exceeded the static execution watchdog' }
  }

  return 'Return'
}

function Invoke-NSISEntry {
  <#
  .SYNOPSIS
    Simulate one compiled NSIS entry relevant to deterministic metadata parsing
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Entry
    The parsed entry record
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The parsed entry record')]
    [pscustomobject]$Entry
  )

  $Opcode = $Entry.Opcode
  $Values = $Entry.Values
  $Raw = $Entry.Raw

  # Simulate only deterministic state needed for paths, variables, registry
  # writes, and nested execution. UI and unsupported runtime opcodes are no-ops.
  switch ($Opcode) {
    $Script:NSIS_OPCODE_INVALID { return $Script:NSIS_RETURN_RESULT }
    $Script:NSIS_OPCODE_RETURN { return $Script:NSIS_RETURN_RESULT }
    $Script:NSIS_OPCODE_ABORT { return $Script:NSIS_ABORT_RESULT }
    $Script:NSIS_OPCODE_QUIT { return $Script:NSIS_QUIT_RESULT }
    $Script:NSIS_OPCODE_JUMP { return [pscustomobject]@{ Action = 'Continue'; Address = $Values[1] } }
    $Script:NSIS_OPCODE_CALL {
      $Result = Invoke-NSISCodeSegment -State $State -Position ((Resolve-NSISAddress -State $State -Address $Values[1]) - 1)
      if ($Result -eq 'Quit' -or $Result -eq 'Abort') {
        return [pscustomobject]@{ Action = $Result; Address = 0 }
      } else {
        return $Script:NSIS_CONTINUE_RESULT
      }
    }
    $Script:NSIS_OPCODE_CREATE_DIR {
      $Path = Get-NSISString -State $State -RelativeOffset $Values[1]
      Add-NSISDirectory -State $State -Path $Path

      if ($Values[2] -ne 0) {
        Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_OUTDIR -Value $Path
        if ([string]::IsNullOrWhiteSpace((Get-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_INSTDIR))) {
          Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_INSTDIR -Value $Path
        }
      }

      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_IF_FILE_EXISTS {
      $FileName = Get-NSISString -State $State -RelativeOffset $Values[1]
      $Address = if (Test-NSISPathExists -State $State -Path $FileName) { $Values[2] } else { $Values[3] }
      return [pscustomobject]@{ Action = 'Continue'; Address = $Address }
    }
    $Script:NSIS_OPCODE_EXTRACT_FILE {
      $Path = Get-NSISString -State $State -RelativeOffset $Values[2]
      Add-NSISFile -State $State -Path $Path
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_SET_FLAG {
      $FlagType = $Values[1]
      $Value = Get-NSISInt -State $State -RelativeOffset $Values[2]
      $Mode = $Values[3]
      $RestoreControl = $Values[4]

      # Save/restore semantics matter for ShellVarContext and registry-view
      # selection, which determine whether uninstall evidence belongs to HKCU/HKLM.
      if ($Mode -le 0) {
        if ($State.ExecFlags.ContainsKey($FlagType)) {
          $State.LastExecFlags[$FlagType] = $State.ExecFlags[$FlagType]
        }
        $State.ExecFlags[$FlagType] = $Value
      } elseif ($State.LastExecFlags.ContainsKey($FlagType)) {
        $State.ExecFlags[$FlagType] = $State.LastExecFlags[$FlagType]
      }

      if ($FlagType -eq $Script:NSIS_EXEC_FLAG_SHELL_VAR_CONTEXT) {
        $ShellVarContextValue = if ($State.ExecFlags.ContainsKey($FlagType)) { $State.ExecFlags[$FlagType] } else { 0 }
        $State.ShellVarContext = if ($ShellVarContextValue -eq 0) { 'HKCU' } else { 'HKLM' }
      }

      if ($FlagType -eq $Script:NSIS_EXEC_FLAG_REG_VIEW -and $RestoreControl -lt 0 -and -not $State.ExecFlags.ContainsKey($FlagType)) {
        $State.ExecFlags[$FlagType] = $Value
      }

      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_IF_FLAG {
      $FlagValue = if ($State.ExecFlags.ContainsKey($Values[3])) { $State.ExecFlags[$Values[3]] } else { 0 }
      return [pscustomobject]@{ Action = 'Continue'; Address = if ($FlagValue -ne 0) { $Values[1] } else { $Values[2] } }
    }
    $Script:NSIS_OPCODE_GET_FLAG {
      $FlagValue = if ($State.ExecFlags.ContainsKey($Values[2])) { $State.ExecFlags[$Values[2]] } else { 0 }
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ([string]$FlagValue)
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_STR_LEN {
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ([string](Get-NSISString -State $State -RelativeOffset $Values[2]).Length)
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_ASSIGN_VAR {
      # EW_ASSIGNVAR stores MaxLen and StartOffset as string-table operands, not
      # immediate integers. This mirrors GetIntFromParmEx(2)/GetIntFromParm(3)
      # in the NSIS runtime, including negative lengths and start positions.
      $Result = Get-NSISString -State $State -RelativeOffset $Values[2]
      $MaximumLengthText = Get-NSISString -State $State -RelativeOffset $Values[3]
      $NewLength = if ([string]::IsNullOrEmpty($MaximumLengthText)) { $Result.Length } else { Get-NSISInt -State $State -RelativeOffset $Values[3] }
      $Start = Get-NSISInt -State $State -RelativeOffset $Values[4]

      if ($Start -lt 0) { $Start += $Result.Length }
      if ($Start -lt 0) {
        $Result = ''
      } else {
        if ($Start -gt $Result.Length) { $Start = $Result.Length }
        $Result = $Result.Substring($Start)
      }

      # A negative MaxLen removes characters from the end of the selected
      # substring. NSIS clamps an underflow to an empty destination variable.
      if ($NewLength -lt 0) { $NewLength += $Result.Length }
      if ($NewLength -lt 0) { $NewLength = 0 }
      if ($Result.Length -gt $NewLength) { $Result = $Result.Substring(0, $NewLength) }
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $Result
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_STR_CMP {
      $Left = Get-NSISString -State $State -RelativeOffset $Values[1]
      $Right = Get-NSISString -State $State -RelativeOffset $Values[2]
      $Equal = if ($Values[5] -eq 0) {
        $Left.Equals($Right, [System.StringComparison]::OrdinalIgnoreCase)
      } else {
        $Left -ceq $Right
      }

      return [pscustomobject]@{ Action = 'Continue'; Address = if ($Equal) { $Values[3] } else { $Values[4] } }
    }
    $Script:NSIS_OPCODE_READ_ENV {
      $EnvironmentName = Get-NSISString -State $State -RelativeOffset $Values[2]
      $EnvironmentValue = [System.Environment]::GetEnvironmentVariable($EnvironmentName)
      if ($null -eq $EnvironmentValue) { $EnvironmentValue = '' }
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $EnvironmentValue
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_GET_OS_INFO {
      # NSIS 3 compiles GetKnownFolderPath into EW_GETOSINFO rather than a
      # System plug-in call. offsets[1] is the output variable, offsets[2] is
      # the GUID string, and offsets[3] selects the operation. Tauri's standard
      # dual-scope template reaches this path through upstream MultiUser.nsh.
      $Operation = $Values[4]
      if ($Operation -eq $Script:NSIS_GET_OS_INFO_KNOWN_FOLDER) {
        $FolderId = Get-NSISString -State $State -RelativeOffset $Values[3]
        $KnownFolderPath = Resolve-NSISKnownFolderPath -FolderId $FolderId
        Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[2])) -Value $KnownFolderPath
      } elseif ($Operation -eq $Script:NSIS_GET_OS_INFO_READ_MEMORY) {
        $Address = Get-NSISInt -State $State -RelativeOffset $Values[3]
        $Specification = [uint32](Get-NSISInt -State $State -RelativeOffset $Values[5])
        $OsInfoValue = Get-NSISOsInfoMemoryValue -Address $Address -Specification $Specification
        if ($null -ne $OsInfoValue) {
          Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[2])) -Value $OsInfoValue
        }
      }

      # Arbitrary GETOSINFO_READMEMORY addresses remain unresolved; never copy
      # process memory from the parser host into installer evidence.
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_INT_CMP {
      $Left = Get-NSISInt -State $State -RelativeOffset $Values[1]
      $Right = Get-NSISInt -State $State -RelativeOffset $Values[2]

      if ($Left -eq $Right) {
        return [pscustomobject]@{ Action = 'Continue'; Address = $Values[3] }
      } elseif ($Left -lt $Right) {
        return [pscustomobject]@{ Action = 'Continue'; Address = $Values[4] }
      } else {
        return [pscustomobject]@{ Action = 'Continue'; Address = $Values[5] }
      }
    }
    $Script:NSIS_OPCODE_INT_OP {
      $Left = Get-NSISInt -State $State -RelativeOffset $Values[2]
      $Right = Get-NSISInt -State $State -RelativeOffset $Values[3]

      $Result = switch ($Values[4]) {
        0 { $Left + $Right }
        1 { $Left - $Right }
        2 { $Left * $Right }
        3 { if ($Right -eq 0) { 0 } else { [int]($Left / $Right) } }
        4 { $Left -bor $Right }
        5 { $Left -band $Right }
        6 { $Left -bxor $Right }
        7 { -bnot $Left }
        8 { [int]($Left -ne 0 -or $Right -ne 0) }
        9 { [int]($Left -ne 0 -and $Right -ne 0) }
        10 { if ($Right -eq 0) { 0 } else { $Left % $Right } }
        11 { $Left -shl $Right }
        12 { $Left -shr $Right }
        13 { [int](([uint32]$Left) -shr $Right) }
        default { $Left }
      }

      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ([string]$Result)
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_INT_FMT {
      $Format = Get-NSISString -State $State -RelativeOffset $Values[2]
      $Result = if ($Format.StartsWith('0x', [System.StringComparison]::OrdinalIgnoreCase)) {
        ('0x{0:X8}' -f [uint32]$Values[3])
      } else {
        [string]$Values[3]
      }

      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $Result
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_PUSH_POP {
      if ($Values[3] -ne 0) {
        $ExchangeIndex = $Values[3]
        if ($ExchangeIndex -lt $State.Stack.Count) {
          $TopIndex = $State.Stack.Count - 1
          $TargetIndex = $TopIndex - $ExchangeIndex
          $Temporary = $State.Stack[$TopIndex]
          $State.Stack[$TopIndex] = $State.Stack[$TargetIndex]
          $State.Stack[$TargetIndex] = $Temporary
        }
      } elseif ($Values[2] -eq $Script:NSIS_POP_OPERATION) {
        $PoppedValue = if ($State.Stack.Count -gt 0) {
          $State.Stack[$State.Stack.Count - 1]
        } else {
          ''
        }

        if ($State.Stack.Count -gt 0) { $State.Stack.RemoveAt($State.Stack.Count - 1) }
        Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $PoppedValue
      } else {
        $State.Stack.Add((Get-NSISString -State $State -RelativeOffset $Values[1]))
      }

      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_REGISTER_DLL {
      # Plug-in calls are encoded as EW_REGISTERDLL even though no COM
      # registration occurs. Resolve deterministic System architecture calls
      # and UserInfo token checks; all other plug-ins remain no-ops.
      $LibraryPath = Get-NSISString -State $State -RelativeOffset $Values[1]
      $FunctionName = Get-NSISString -State $State -RelativeOffset $Values[2]
      $LibraryName = [IO.Path]::GetFileName($LibraryPath)
      if ($LibraryName -ieq 'System.dll') {
        $null = Invoke-NSISSystemPluginCall -State $State -FunctionName $FunctionName
      } elseif ($LibraryName -ieq 'UserInfo.dll') {
        $null = Invoke-NSISUserInfoPluginCall -State $State -FunctionName $FunctionName
      }
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_SHELL_EXEC {
      # Record configured nested execution as evidence only; never launch it.
      $Verb = Get-NSISString -State $State -RelativeOffset $Values[1]
      $File = Get-NSISString -State $State -RelativeOffset $Values[2]
      $Parameters = Get-NSISString -State $State -RelativeOffset $Values[3]
      $Kind = if ([string]::IsNullOrWhiteSpace($Verb)) { 'ShellExec' } else { "ShellExec:$Verb" }
      Add-NSISExecutedPayload -State $State -Command $File -Parameters $Parameters -Kind $Kind
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_EXECUTE {
      $Command = Get-NSISString -State $State -RelativeOffset $Values[1]
      $Kind = if ($Values[3] -ne 0) { 'ExecWait' } else { 'Exec' }
      Add-NSISExecutedPayload -State $State -Command $Command -Kind $Kind
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_DELETE_REG {
      $Root = Resolve-NSISRegistryRoot -State $State -Root $Raw[2]
      $Key = Get-NSISString -State $State -RelativeOffset $Values[3]
      $Name = Get-NSISString -State $State -RelativeOffset $Values[4]
      Remove-NSISRegistryValue -State $State -Root $Root -Key $Key -Name $Name
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_WRITE_REG {
      # Registry parsing maps the source-accurate EW_WRITEREG operands and updates
      # ARP metadata only for explicit uninstall-key writes.
      Add-NSISRegistryWrite -State $State -Entry $Entry
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_READ_REG {
      $Root = Resolve-NSISRegistryRoot -State $State -Root $Raw[2]
      $Key = Get-NSISString -State $State -RelativeOffset $Values[3]
      $Name = Get-NSISString -State $State -RelativeOffset $Values[4]
      $Value = Get-NSISRegistryValue -State $State -Root $Root -Key $Key -Name $Name
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $Value
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Script:NSIS_OPCODE_WRITE_UNINSTALLER {
      $UninstallerPath = Get-NSISString -State $State -RelativeOffset $Values[1]
      Add-NSISFile -State $State -Path $UninstallerPath
      return $Script:NSIS_CONTINUE_RESULT
    }
    default {
      # Unsupported entries are ignored unless the resulting metadata stays incomplete and the caller throws.
      return $Script:NSIS_CONTINUE_RESULT
    }
  }
}

function ConvertTo-NSISManifestPath {
  <#
  .SYNOPSIS
    Convert a host-resolved installer path to the WinGet environment-variable form
  .DESCRIPTION
    NSIS simulation resolves special folders to live host paths such as
    C:\Program Files. WinGet manifests use stable environment-variable tokens
    instead, mirroring the directory-constant mapping of the Inno parser.
  .PARAMETER Path
    The resolved path to convert
  #>
  [OutputType([string])]
  param (
    [Parameter(HelpMessage = 'The resolved path to convert')]
    [AllowNull()]
    [string]$Path
  )

  if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }

  $ProgramFiles64 = if (${env:ProgramW6432}) { ${env:ProgramW6432} } else { $env:ProgramFiles }
  $ProgramFilesX86 = if (${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} } else { $ProgramFiles64 }
  $CommonProgramFiles64 = if (${env:CommonProgramW6432}) { ${env:CommonProgramW6432} } else { $env:CommonProgramFiles }
  $CommonProgramFilesX86 = if (${env:CommonProgramFiles(x86)}) { ${env:CommonProgramFiles(x86)} } else { $env:CommonProgramFiles }

  # Longest prefixes first so Common Files and the x86 roots win over the
  # shorter 64-bit Program Files prefix.
  $Mappings = @(
    @($CommonProgramFilesX86, '%ProgramFiles(x86)%\Common Files'),
    @($CommonProgramFiles64, '%ProgramFiles%\Common Files'),
    @($ProgramFilesX86, '%ProgramFiles(x86)%'),
    @($ProgramFiles64, '%ProgramFiles%'),
    @($env:LOCALAPPDATA, '%LocalAppData%'),
    @($env:APPDATA, '%AppData%'),
    @($env:ProgramData, '%ProgramData%'),
    @($env:USERPROFILE, '%UserProfile%'),
    @($Script:NSIS_WINDOWS_DIRECTORY, '%SystemRoot%')
  ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_[0]) } | Sort-Object -Property { - $_[0].Length } -Stable

  foreach ($Mapping in $Mappings) {
    $Prefix = $Mapping[0]
    if ($Path.Equals($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $Mapping[1] }
    if ($Path.StartsWith("$Prefix\", [System.StringComparison]::OrdinalIgnoreCase)) {
      return $Mapping[1] + $Path.Substring($Prefix.Length)
    }
  }
  return $Path
}

function Get-NSISLanguageLocaleName {
  <#
  .SYNOPSIS
    Convert an NSIS Windows language identifier to a BCP47 culture name
  .PARAMETER LanguageId
    The unsigned Windows language identifier stored in the NSIS language record
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The Windows language identifier')]
    [uint16]$LanguageId
  )

  try {
    return [System.Globalization.CultureInfo]::GetCultureInfo([int]$LanguageId).Name
  } catch {
    # Custom or obsolete LANGIDs remain useful numeric evidence even when .NET
    # cannot map them to a current BCP47 culture name.
    return $null
  }
}

function Get-NSISAppsAndFeaturesEntryInfo {
  <#
  .SYNOPSIS
    Resolve visible uninstall registry identities across every compiled NSIS language
  .DESCRIPTION
    NSIS language strings are selected at runtime. This function reevaluates only
    explicit EW_WRITEREG commands for each compiled language table; it does not
    probe arbitrary strings or execute the installer. The simulation's primary
    scalar metadata remains unchanged for compatibility.
  .PARAMETER State
    The mutable NSIS execution state after direct or simulated registry discovery
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  $LanguageTables = if ($State.PSObject.Properties.Name -contains 'LanguageTables') {
    @($State.LanguageTables)
  } elseif ($State.LanguageTable) {
    @($State.LanguageTable)
  } else {
    @()
  }
  if ($LanguageTables.Count -eq 0) {
    # Installers without a language block still need one pass for literal ARP writes.
    $LanguageTables = @([pscustomobject]@{
        LanguageId = [uint16]$Script:NSIS_DEFAULT_LANGUAGE; DialogOffset = [uint32]0
        RightToLeft = $false; StringOffsets = [int[]]@()
      })
  }

  $TargetArchitectureProperty = $State.PSObject.Properties['TargetArchitecture']
  $HasTargetArchitecture = $null -ne $TargetArchitectureProperty -and
  -not [string]::IsNullOrWhiteSpace([string]$TargetArchitectureProperty.Value)
  $TargetScopeProperty = $State.PSObject.Properties['TargetScope']
  $HasTargetScope = $null -ne $TargetScopeProperty -and
  -not [string]::IsNullOrWhiteSpace([string]$TargetScopeProperty.Value)
  $AllowedRegistryIdentities = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  if ($HasTargetArchitecture -and $State.PSObject.Properties.Name -contains 'RegistryWrites') {
    foreach ($RegistryWrite in @($State.RegistryWrites)) {
      if ($RegistryWrite.IsUninstallKey) {
        $null = $AllowedRegistryIdentities.Add("$($RegistryWrite.Root)`0$($RegistryWrite.Key)")
      }
    }
  }

  $Evidence = [System.Collections.Generic.List[object]]::new()
  if ($HasTargetScope -and $State.PSObject.Properties.Name -contains 'RegistryWrites') {
    $EntriesByRegistryKey = [ordered]@{}

    # A selected MultiUser branch has already resolved temporary variables and
    # SHCTX. Preserve only the uninstall writes reached by that branch instead
    # of re-reading every compiled EW_WRITEREG instruction from both scopes.
    foreach ($Write in @($State.RegistryWrites)) {
      if (-not $Write.IsUninstallKey) { continue }
      $ResolvedScope = if ($Write.Root -eq 'HKLM') { 'machine' } elseif ($Write.Root -eq 'HKCU') { 'user' } else { $null }
      if ($ResolvedScope -ne $TargetScopeProperty.Value) { continue }

      $RegistryIdentity = "$($Write.Root)`0$($Write.Key)"
      if (-not $EntriesByRegistryKey.Contains($RegistryIdentity)) {
        $EntriesByRegistryKey[$RegistryIdentity] = [pscustomobject]@{
          Root   = $Write.Root
          Key    = $Write.Key
          Scope  = $ResolvedScope
          Values = [ordered]@{}
        }
      }
      $EntriesByRegistryKey[$RegistryIdentity].Values[$Write.Name] = $Write.Value
    }

    $SelectedLanguageTable = if ($State.LanguageTable) {
      $State.LanguageTable
    } else {
      $LanguageTables | Select-Object -First 1
    }
    foreach ($RegistryEntry in $EntriesByRegistryKey.Values) {
      $Values = $RegistryEntry.Values
      if ([string]::IsNullOrWhiteSpace([string]$Values['DisplayName']) -and
        [string]::IsNullOrWhiteSpace([string]$Values['DisplayVersion']) -and
        [string]::IsNullOrWhiteSpace([string]$Values['Publisher'])) { continue }

      $SystemComponent = [string]$Values['SystemComponent']
      $Evidence.Add([pscustomobject][ordered]@{
          LanguageId      = [uint16]$SelectedLanguageTable.LanguageId
          Locale          = Get-NSISLanguageLocaleName -LanguageId $SelectedLanguageTable.LanguageId
          RegistryRoot    = $RegistryEntry.Root
          RegistryKey     = $RegistryEntry.Key
          Scope           = $RegistryEntry.Scope
          ProductCode     = $RegistryEntry.Key.Substring($RegistryEntry.Key.LastIndexOf('\') + 1)
          DisplayName     = $Values['DisplayName']
          DisplayVersion  = $Values['DisplayVersion']
          Publisher       = $Values['Publisher']
          InstallerType   = 'nullsoft'
          SystemComponent = $SystemComponent
          IsVisible       = $SystemComponent -notin @('1', '0x00000001')
        })
    }
  }

  $HadLanguageTableProperty = $State.PSObject.Properties.Name -contains 'LanguageTable'
  $OriginalLanguageTable = if ($HadLanguageTableProperty) { $State.LanguageTable } else { $null }
  if (-not $HadLanguageTableProperty) {
    $State | Add-Member -NotePropertyName LanguageTable -NotePropertyValue $null
  }
  $HadLanguageVariable = $State.Variables.ContainsKey($Script:NSIS_PREDEFINED_VAR_LANGUAGE)
  $OriginalLanguageVariable = if ($HadLanguageVariable) { $State.Variables[$Script:NSIS_PREDEFINED_VAR_LANGUAGE] } else { $null }
  $LanguageTablesToScan = if ($HasTargetScope) { @() } else { $LanguageTables }
  try {
    # Untargeted analysis intentionally evaluates every language table. A
    # targeted scope uses reached writes above because rescanning source entries
    # would lose runtime-computed key suffixes such as " (current user)".
    foreach ($LanguageTable in $LanguageTablesToScan) {
      $State.LanguageTable = $LanguageTable
      Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_LANGUAGE -Value ([string]$LanguageTable.LanguageId)
      $EntriesByRegistryKey = [ordered]@{}

      # Re-resolve only source-backed registry commands. This catches $(LangString)
      # values while retaining the exact uninstall key, hive, and registry type.
      foreach ($Entry in $State.Entries) {
        if ($Entry.Opcode -ne $Script:NSIS_OPCODE_WRITE_REG) { continue }
        $Write = Get-NSISRegistryWriteFromEntry -State $State -Entry $Entry
        if (-not $Write -or -not $Write.IsUninstallKey) { continue }

        $RegistryIdentity = "$($Write.Root)`0$($Write.Key)"
        if ($HasTargetArchitecture -and $AllowedRegistryIdentities.Count -gt 0 -and
          -not $AllowedRegistryIdentities.Contains($RegistryIdentity)) { continue }
        if (-not $EntriesByRegistryKey.Contains($RegistryIdentity)) {
          $EntriesByRegistryKey[$RegistryIdentity] = [pscustomobject]@{
            Root   = $Write.Root
            Key    = $Write.Key
            Values = [ordered]@{}
          }
        }
        $EntriesByRegistryKey[$RegistryIdentity].Values[$Write.Name] = $Write.Value
      }

      foreach ($RegistryEntry in $EntriesByRegistryKey.Values) {
        $Values = $RegistryEntry.Values
        $SystemComponent = [string]$Values['SystemComponent']
        $IsVisible = $SystemComponent -notin @('1', '0x00000001')
        $ProductCode = $RegistryEntry.Key.Substring($RegistryEntry.Key.LastIndexOf('\') + 1)
        $Scope = if ($RegistryEntry.Root -eq 'HKLM') { 'machine' } elseif ($RegistryEntry.Root -eq 'HKCU') { 'user' } else { $null }

        # Omit empty registry shells that do not establish an ARP identity.
        if ([string]::IsNullOrWhiteSpace([string]$Values['DisplayName']) -and
          [string]::IsNullOrWhiteSpace([string]$Values['DisplayVersion']) -and
          [string]::IsNullOrWhiteSpace([string]$Values['Publisher'])) { continue }

        $Evidence.Add([pscustomobject][ordered]@{
            LanguageId      = [uint16]$LanguageTable.LanguageId
            Locale          = Get-NSISLanguageLocaleName -LanguageId $LanguageTable.LanguageId
            RegistryRoot    = $RegistryEntry.Root
            RegistryKey     = $RegistryEntry.Key
            Scope           = $Scope
            ProductCode     = $ProductCode
            DisplayName     = $Values['DisplayName']
            DisplayVersion  = $Values['DisplayVersion']
            Publisher       = $Values['Publisher']
            InstallerType   = 'nullsoft'
            SystemComponent = $SystemComponent
            IsVisible       = $IsVisible
          })
      }
    }
  } finally {
    if ($HadLanguageTableProperty) {
      $State.LanguageTable = $OriginalLanguageTable
    } else {
      $State.PSObject.Properties.Remove('LanguageTable')
    }
    if ($HadLanguageVariable) {
      $State.Variables[$Script:NSIS_PREDEFINED_VAR_LANGUAGE] = $OriginalLanguageVariable
    } else {
      $null = $State.Variables.Remove($Script:NSIS_PREDEFINED_VAR_LANGUAGE)
    }
  }

  $ManifestEntries = [System.Collections.Generic.List[object]]::new()
  $SeenManifestEntries = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
  foreach ($Entry in $Evidence) {
    if (-not $Entry.IsVisible) { continue }
    $Identity = "$($Entry.ProductCode)`0$($Entry.DisplayName)`0$($Entry.DisplayVersion)`0$($Entry.Publisher)`0$($Entry.InstallerType)"
    if (-not $SeenManifestEntries.Add($Identity)) { continue }

    # Keep this projection schema-shaped. Language and registry provenance stay
    # in AppsAndFeaturesEntryEvidence for analyzer display and VM correlation.
    $ManifestEntry = [ordered]@{}
    foreach ($Name in @('DisplayName', 'DisplayVersion', 'Publisher', 'ProductCode', 'InstallerType')) {
      if (-not [string]::IsNullOrWhiteSpace([string]$Entry.$Name)) { $ManifestEntry[$Name] = $Entry.$Name }
    }
    $ManifestEntries.Add([pscustomobject]$ManifestEntry)
  }

  $LocalizedRegistryKeys = [System.Collections.Generic.List[string]]::new()
  foreach ($Group in @($Evidence | Where-Object IsVisible | Group-Object { "$($_.RegistryRoot)`0$($_.RegistryKey)" })) {
    $Identities = @($Group.Group | ForEach-Object { "$($_.DisplayName)`0$($_.Publisher)" } | Select-Object -Unique)
    if ($Identities.Count -gt 1) { $LocalizedRegistryKeys.Add($Group.Name) }
  }

  $Notices = [System.Collections.Generic.List[string]]::new()
  if ($LocalizedRegistryKeys.Count -gt 0) {
    $Locales = @($Evidence | Where-Object IsVisible | ForEach-Object { $_.Locale ?? "LANGID-$($_.LanguageId)" } | Select-Object -Unique)
    $Notices.Add("NSIS uninstall DisplayName or Publisher varies by installer language ($($Locales -join ', ')); AppsAndFeaturesEntries contains $($ManifestEntries.Count) distinct visible ARP identities. Preserve the applicable localized identities and validate installed-language behavior in a VM when authoring the manifest.")
  }

  return [pscustomobject][ordered]@{
    AppsAndFeaturesEntries       = $ManifestEntries.ToArray()
    AppsAndFeaturesEntryEvidence = $Evidence.ToArray()
    Notices                      = [string[]]$Notices.ToArray()
    HasLocalizedEntries          = $LocalizedRegistryKeys.Count -gt 0
  }
}

function Repair-NSISIncompleteInstallMetadata {
  <#
  .SYNOPSIS
    Recover a missing install root from a unique explicit compiled path assignment
  .DESCRIPTION
    Custom directory pages can initialize INSTDIR only after UI interaction. If
    static simulation therefore observes a root-relative suffix, this helper
    accepts a replacement only when one explicit StrCpy source is an absolute
    known install-root path ending in that exact suffix.
  .PARAMETER State
    The mutable NSIS execution state and metadata to repair
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  $ObservedInstallRoot = Get-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_INSTDIR
  if ([string]::IsNullOrWhiteSpace($ObservedInstallRoot)) { $ObservedInstallRoot = [string]$State.Metadata.DefaultInstallLocation }
  $EffectiveScope = [string]$State.Metadata.Scope
  $UninstallRoots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

  # Reached registry writes retain the shell context selected when each command
  # executed. Prefer them over re-decoding every compiled EW_WRITEREG command
  # with the simulator's final ambient context, which can incorrectly turn a
  # targeted HKLM branch back into the template's default HKCU scope.
  if ($State.PSObject.Properties.Name -contains 'RegistryWrites') {
    foreach ($Write in @($State.RegistryWrites)) {
      if ($Write.IsUninstallKey) { $null = $UninstallRoots.Add($Write.Root) }
    }
  }
  if ($UninstallRoots.Count -eq 0) {
    # Incomplete UI-driven simulations may not reach registry creation. Retain
    # the previous source-backed fallback only for that evidence-free case.
    foreach ($Entry in $State.Entries) {
      if ($Entry.Opcode -ne $Script:NSIS_OPCODE_WRITE_REG) { continue }
      $Write = Get-NSISRegistryWriteFromEntry -State $State -Entry $Entry
      if ($Write.IsUninstallKey) { $null = $UninstallRoots.Add($Write.Root) }
    }
  }
  if ($UninstallRoots.Count -eq 1) {
    # An explicit uninstall hive is stronger scope evidence than a temporary
    # path left by incomplete simulation of a custom directory page.
    $EffectiveScope = if (@($UninstallRoots)[0] -eq 'HKLM') { 'machine' } elseif (@($UninstallRoots)[0] -eq 'HKCU') { 'user' } else { $EffectiveScope }
    if ($EffectiveScope) { $State.Metadata.Scope = $EffectiveScope }
  }

  $IsRootRelative = $ObservedInstallRoot -match '^[\\/](?![\\/])'
  $TemporaryRoot = [System.IO.Path]::GetTempPath().TrimEnd('\')
  $IsTemporaryMachineRoot = $EffectiveScope -eq 'machine' -and $ObservedInstallRoot.StartsWith($TemporaryRoot, [System.StringComparison]::OrdinalIgnoreCase)
  if (-not $IsRootRelative -and -not $IsTemporaryMachineRoot) { return }

  $InstallSuffix = if ($IsRootRelative) {
    $ObservedInstallRoot.TrimStart('\', '/')
  } else {
    Split-Path -Path $ObservedInstallRoot -Leaf
  }
  if ([string]::IsNullOrWhiteSpace($InstallSuffix)) { return }
  $SuffixPath = '\' + $InstallSuffix

  $KnownRoots = if ($EffectiveScope -eq 'machine') {
    @($env:ProgramFiles, ${env:ProgramFiles(x86)}, ${env:ProgramW6432})
  } elseif ($EffectiveScope -eq 'user') {
    @($env:LOCALAPPDATA, $env:APPDATA)
  } else {
    @($env:ProgramFiles, ${env:ProgramFiles(x86)}, ${env:ProgramW6432}, $env:LOCALAPPDATA, $env:APPDATA)
  }
  $KnownRoots = @($KnownRoots) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique
  $DirectInstallDirectoryCandidates = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $SuffixCandidates = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

  foreach ($Entry in $State.Entries) {
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_ASSIGN_VAR) { continue }
    $Candidate = Get-NSISString -State $State -RelativeOffset $Entry.Values[2]
    if ([string]::IsNullOrWhiteSpace($Candidate) -or -not [System.IO.Path]::IsPathFullyQualified($Candidate)) { continue }
    if (-not @($KnownRoots).Where({ $Candidate.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) }, 'First')) { continue }

    if ([Math]::Abs($Entry.Values[1]) -eq $Script:NSIS_PREDEFINED_VAR_INSTDIR) {
      $ResolvedCandidate = if ($Candidate.EndsWith($SuffixPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        $Candidate
      } else {
        Join-Path $Candidate $InstallSuffix
      }
      $null = $DirectInstallDirectoryCandidates.Add($ResolvedCandidate.TrimEnd('\'))
    } elseif ($Candidate.EndsWith($SuffixPath, [System.StringComparison]::OrdinalIgnoreCase)) {
      $null = $SuffixCandidates.Add($Candidate.TrimEnd('\'))
    }
  }

  # Multiple explicit roots represent conditional behavior and must remain
  # unresolved until the caller supplies scope/architecture or VM evidence.
  $Candidates = if ($DirectInstallDirectoryCandidates.Count -gt 0) { $DirectInstallDirectoryCandidates } else { $SuffixCandidates }
  if ($Candidates.Count -ne 1) { return }
  $InstallRoot = @($Candidates)[0]

  # Variables derived while INSTDIR was root-relative retain that same prefix.
  # Replace it before re-evaluating explicit ARP writes so versioned paths keep
  # their compiled suffix without inheriting a branch-only lexical value.
  foreach ($VariableIndex in @($State.Variables.Keys)) {
    $VariableValue = [string]$State.Variables[$VariableIndex]
    if ($VariableValue.StartsWith($ObservedInstallRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
      $State.Variables[$VariableIndex] = $InstallRoot + $VariableValue.Substring($ObservedInstallRoot.Length)
    }
  }
  $State.Metadata.DefaultInstallLocation = $InstallRoot
  $State.Variables[$Script:NSIS_PREDEFINED_VAR_INSTDIR] = $InstallRoot

  foreach ($PropertyName in @('UninstallString', 'QuietUninstallString', 'DisplayIcon')) {
    $Value = [string]$State.Metadata[$PropertyName]
    if ($Value.StartsWith('"' + $ObservedInstallRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
      $State.Metadata[$PropertyName] = '"' + $InstallRoot + $Value.Substring($ObservedInstallRoot.Length + 1)
    } elseif ($Value.StartsWith($ObservedInstallRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
      $State.Metadata[$PropertyName] = $InstallRoot + $Value.Substring($ObservedInstallRoot.Length)
    }
  }

  # Keep the structured registry projection consistent with the top-level
  # metadata returned to bridge and analyzer callers.
  foreach ($PropertyName in @('InstallLocation', 'UninstallString', 'QuietUninstallString', 'DisplayIcon')) {
    $MetadataName = if ($PropertyName -eq 'InstallLocation') { 'DefaultInstallLocation' } else { $PropertyName }
    if ($State.Metadata.RegistryValues.ContainsKey($PropertyName) -and $State.Metadata[$MetadataName]) {
      $State.Metadata.RegistryValues[$PropertyName] = $State.Metadata[$MetadataName]
    }
  }
  foreach ($Write in $State.RegistryWrites) {
    $MetadataName = if ($Write.Name -eq 'InstallLocation') { 'DefaultInstallLocation' } else { [string]$Write.Name }
    if ($MetadataName -in @('DefaultInstallLocation', 'UninstallString', 'QuietUninstallString', 'DisplayIcon') -and $State.Metadata[$MetadataName]) {
      $Write.Value = $State.Metadata[$MetadataName]
    }
  }

  # Re-evaluate path-valued uninstall writes with the repaired live variables.
  # This intentionally bypasses direct lexical data-flow: current variables now
  # contain the branch selected by simulation rather than every compiled branch.
  foreach ($Entry in $State.Entries) {
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_WRITE_REG) { continue }
    $Write = Get-NSISRegistryWriteFromEntry -State $State -Entry $Entry
    if (-not $Write.IsUninstallKey -or $Write.Name -notin @('InstallLocation', 'UninstallString', 'QuietUninstallString', 'DisplayIcon')) { continue }
    Set-NSISRegistryValue -State $State -Root $Write.Root -Key $Write.Key -Name $Write.Name -Value $Write.Value
    foreach ($ExistingWrite in $State.RegistryWrites) {
      if ($ExistingWrite.Root -eq $Write.Root -and $ExistingWrite.Key -eq $Write.Key -and $ExistingWrite.Name -eq $Write.Name) {
        $ExistingWrite.Value = $Write.Value
      }
    }
  }
}

function Get-NSISPortableLauncherInfo {
  <#
  .SYNOPSIS
    Detect a source-backed NSIS portable-launcher layout
  .DESCRIPTION
    electron-builder's portable.nsi template sets three PORTABLE_EXECUTABLE_*
    environment variables before executing the unpacked application from a
    temporary directory. Requiring that complete marker set, temporary payload
    execution, and no visible uninstall write avoids classifying ordinary NSIS
    bootstrappers as portable merely because they also unpack into TEMP.
  .PARAMETER State
    The completed NSIS simulation state containing strings, files, execution,
    and Apps & Features evidence
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The completed NSIS simulation state')]
    [pscustomobject]$State
  )

  $RequiredMarkers = [string[]]@(
    'PORTABLE_EXECUTABLE_DIR'
    'PORTABLE_EXECUTABLE_FILE'
    'PORTABLE_EXECUTABLE_APP_FILENAME'
  )
  $PresentMarkers = [System.Collections.Generic.List[string]]::new()
  $MarkerEncoding = if ($State.VersionInfo.Unicode) { [System.Text.Encoding]::Unicode } else { [System.Text.Encoding]::ASCII }
  foreach ($Marker in $RequiredMarkers) {
    # Search the bounded decoded strings block directly. Materializing every
    # string solely for three exact markers is slower and allocates many
    # short-lived PowerShell objects on large generated installers.
    $Pattern = $MarkerEncoding.GetBytes($Marker)
    if (@(Find-BinaryPattern -Bytes $State.StringsBlock -Pattern $Pattern -Maximum 1).Count -gt 0) {
      $PresentMarkers.Add($Marker)
    }
  }

  # The portable template extracts under $PLUGINSDIR or an optional $TEMP
  # unpack directory, then waits for the application before deleting that tree.
  $TemporaryRoots = [System.Collections.Generic.List[string]]::new()
  foreach ($Root in @(
      [System.IO.Path]::GetTempPath().TrimEnd('\')
      (Get-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_PLUGINSDIR)
    )) {
    if (-not [string]::IsNullOrWhiteSpace($Root) -and -not $TemporaryRoots.Contains($Root)) {
      $TemporaryRoots.Add($Root)
    }
  }
  $TemporaryPayloads = [System.Collections.Generic.List[string]]::new()
  foreach ($Payload in @($State.ExecutedPayloads)) {
    $Command = ([string]$Payload.Command).Trim().TrimStart('"')
    if (@($TemporaryRoots).Where({
          $Command.Equals($_, [System.StringComparison]::OrdinalIgnoreCase) -or
          $Command.StartsWith("$_\", [System.StringComparison]::OrdinalIgnoreCase)
        }, 'First').Count -gt 0) {
      $TemporaryPayloads.Add([string]$Payload.Command)
    }
  }

  $AppPackageFiles = @(
    foreach ($Value in @($State.Files)) {
      if ($Value -match '(?i)(app-(?:32|64|arm64)(?:\.(?:7z|zip))?)') {
        $Matches[1].ToLowerInvariant()
      }
    }
  ) | Select-Object -Unique
  $HasPortableMarkers = $PresentMarkers.Count -eq $RequiredMarkers.Count
  $IsPortable = $HasPortableMarkers -and $TemporaryPayloads.Count -gt 0 -and -not $State.Metadata.WritesAppsAndFeaturesEntry

  $Evidence = [System.Collections.Generic.List[string]]::new()
  foreach ($Marker in $PresentMarkers) { $Evidence.Add("EnvironmentVariable:$Marker") }
  foreach ($AppPackageFile in $AppPackageFiles) { $Evidence.Add("AppPackage:$AppPackageFile") }
  foreach ($Payload in $TemporaryPayloads) { $Evidence.Add("TemporaryExecution:$Payload") }
  if (-not $State.Metadata.WritesAppsAndFeaturesEntry) { $Evidence.Add('NoAppsAndFeaturesEntry') }

  return [pscustomobject][ordered]@{
    IsPortable                = $IsPortable
    Family                    = if ($HasPortableMarkers) { 'electron-builder' } else { $null }
    EnvironmentVariables      = [string[]]$PresentMarkers.ToArray()
    AppPackageFiles           = [string[]]@($AppPackageFiles)
    TemporaryExecutedPayloads = [string[]]$TemporaryPayloads.ToArray()
    Evidence                  = [string[]]$Evidence.ToArray()
  }
}

function Test-NSISStringBlockLiteral {
  <#
  .SYNOPSIS
    Test whether the decoded NSIS string block contains one exact template marker
  .PARAMETER State
    The mutable NSIS execution state containing the decoded strings block
  .PARAMETER Value
    The case-sensitive literal emitted by the installer template
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The exact template marker to locate')]
    [string]$Value
  )

  # Search bytes directly instead of materializing every decoded string merely
  # to identify a few compiler-generated markers on large installers.
  $Encoding = if ($State.VersionInfo.Unicode) { [Text.Encoding]::Unicode } else { [Text.Encoding]::Default }
  $Pattern = $Encoding.GetBytes($Value)
  return @(Find-BinaryPattern -Bytes $State.StringsBlock -Pattern $Pattern -Maximum 1).Count -gt 0
}

function Get-NSISTauriInstallerInfo {
  <#
  .SYNOPSIS
    Identify the standard Tauri NSIS template and its compiled install mode
  .DESCRIPTION
    Tauri permits custom NSIS templates, so generic product strings are not
    enough. Detection requires three markers emitted together by Tauri's
    standard template: its native utility plug-in, MainBinaryName registry
    value, and placeholder installation directory. The mode then comes from
    compiled MultiUser setters, the visible ARP scope, and the PE execution
    level rather than a package-name allowlist.
  .PARAMETER State
    The mutable NSIS execution state after scope selectors were discovered
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  if (-not $State.PSObject.Properties['TauriTemplateEvidence']) {
    $Markers = [System.Collections.Generic.List[string]]::new()
    foreach ($Marker in @('nsis_tauri_utils.dll', 'MainBinaryName', 'placeholder\')) {
      if (Test-NSISStringBlockLiteral -State $State -Value $Marker) { $Markers.Add($Marker) }
    }

    $IsTauri = $Markers.Count -eq 3
    $RequestedExecutionLevel = if ($IsTauri) { $State.Metadata.RequestedExecutionLevel } else { $null }
    $State | Add-Member -NotePropertyName TauriTemplateEvidence -NotePropertyValue ([pscustomobject]@{
        IsTauri                 = $IsTauri
        Markers                 = [string[]]$Markers.ToArray()
        RequestedExecutionLevel = $RequestedExecutionLevel
      })
  }

  $Template = $State.TauriTemplateEvidence
  $InstallerMode = $null
  if ($Template.IsTauri) {
    $SupportedScopes = @($State.Metadata.SupportedScopes)
    if ($SupportedScopes -contains 'user' -and $SupportedScopes -contains 'machine') {
      $InstallerMode = 'both'
    } elseif ($State.Metadata.Scope -eq 'user' -and $Template.RequestedExecutionLevel -eq 'asInvoker') {
      $InstallerMode = 'currentUser'
    } elseif ($State.Metadata.Scope -eq 'machine' -and $Template.RequestedExecutionLevel -eq 'requireAdministrator') {
      $InstallerMode = 'perMachine'
    }
  }

  $Evidence = [System.Collections.Generic.List[string]]::new()
  foreach ($Marker in @($Template.Markers)) { $Evidence.Add("String:$Marker") }
  if ($Template.RequestedExecutionLevel) { $Evidence.Add("RequestedExecutionLevel:$($Template.RequestedExecutionLevel)") }
  foreach ($SupportedScope in @($State.Metadata.SupportedScopes)) { $Evidence.Add("CompiledScope:$SupportedScope") }
  if ($State.Metadata.Scope) { $Evidence.Add("ObservedArpScope:$($State.Metadata.Scope)") }

  return [pscustomobject][ordered]@{
    IsTauri                 = [bool]$Template.IsTauri
    InstallerMode           = $InstallerMode
    RequestedExecutionLevel = $Template.RequestedExecutionLevel
    Evidence                = [string[]]$Evidence.ToArray()
  }
}

function Complete-NSISMetadata {
  <#
  .SYNOPSIS
    Apply deterministic fallbacks after the NSIS simulation completes
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER SkipLocalizedAppsAndFeaturesEntries
    Skip the all-language registry projection during intermediate completeness checks
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(HelpMessage = 'Skip localized ARP projection during an intermediate parser pass')]
    [switch]$SkipLocalizedAppsAndFeaturesEntries
  )

  # Language-table name and split VersionMajor/VersionMinor values are structured
  # fallbacks only; arbitrary strings are never probed as metadata candidates.
  if (-not $State.Metadata.DisplayName -and $State.LanguageTable -and $State.LanguageTable.StringOffsets.Count -gt 2) {
    $NameOffset = $State.LanguageTable.StringOffsets[2]
    if ($NameOffset -ne 0) { $State.Metadata.DisplayName = Get-NSISString -State $State -RelativeOffset $NameOffset }
  }

  if (-not $State.Metadata.DisplayVersion) {
    $Major = $State.Metadata.RegistryValues['VersionMajor']
    $Minor = $State.Metadata.RegistryValues['VersionMinor']
    if (-not [string]::IsNullOrWhiteSpace($Major) -and -not [string]::IsNullOrWhiteSpace($Minor)) {
      $State.Metadata.DisplayVersion = "$Major.$Minor"
    }
  }

  if (-not $State.Metadata.DefaultInstallLocation) {
    $State.Metadata.DefaultInstallLocation = Get-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_INSTDIR
  }

  if (-not $SkipLocalizedAppsAndFeaturesEntries) {
    # Some custom directory pages establish the root only after UI interaction.
    # Run this only for the final projection; intermediate completeness checks
    # must not mutate variables before section simulation selects its branches.
    Repair-NSISIncompleteInstallMetadata -State $State
  }

  if (-not $State.Metadata.Scope) {
    # Scope fallback uses the resolved install root only when no explicit
    # uninstall hive or ShellVarContext evidence established it during simulation.
    if ($State.Metadata.DefaultInstallLocation -and (
        $State.Metadata.DefaultInstallLocation.StartsWith($env:ProgramFiles, [System.StringComparison]::OrdinalIgnoreCase) -or
        (${env:ProgramFiles(x86)} -and $State.Metadata.DefaultInstallLocation.StartsWith(${env:ProgramFiles(x86)}, [System.StringComparison]::OrdinalIgnoreCase))
      )) {
      $State.Metadata.Scope = 'machine'
    } else {
      $State.Metadata.Scope = 'user'
    }
  }

  # Tauri's standard template has three install-mode variants. Record only a
  # mode proven by its template markers plus compiled scope/execution evidence;
  # custom templates remain ordinary NSIS when those markers do not agree.
  $TauriInfo = Get-NSISTauriInstallerInfo -State $State
  $State.Metadata.IsTauri = $TauriInfo.IsTauri
  $State.Metadata.TauriInstallerMode = $TauriInfo.InstallerMode
  if ($TauriInfo.IsTauri) {
    $State.Metadata.RequestedExecutionLevel = $TauriInfo.RequestedExecutionLevel
  }
  $State.Metadata.TauriEvidence = [string[]]$TauriInfo.Evidence
  if ($TauriInfo.IsTauri) {
    if ($TauriInfo.InstallerMode -eq 'currentUser' -and @($State.Metadata.SupportedScopes).Count -eq 0) {
      $State.Metadata.SupportedScopes = [string[]]@('user')
    } elseif ($TauriInfo.InstallerMode -eq 'perMachine' -and @($State.Metadata.SupportedScopes).Count -eq 0) {
      $State.Metadata.SupportedScopes = [string[]]@('machine')
    } elseif (-not $TauriInfo.InstallerMode) {
      $State.Warnings.Add('The standard Tauri NSIS template was detected, but its compiled installer mode could not be resolved from scope and PE execution-level evidence.')
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$State.TargetScope) -and
      @($State.Metadata.SupportedScopes).Count -gt 0 -and
      $State.Metadata.SupportedScopes -notcontains $State.TargetScope) {
      $State.Warnings.Add("The Tauri installer supports '$($State.Metadata.SupportedScopes -join ', ')' scope, not the requested '$($State.TargetScope)' scope.")
    }
  }

  if ($State.Metadata.SystemComponent -eq '1' -or $State.Metadata.SystemComponent -eq '0x00000001') {
    $State.Metadata.WritesAppsAndFeaturesEntry = $false
  }

  if (-not $SkipLocalizedAppsAndFeaturesEntries) {
    # Portable launchers have an extraction directory rather than a persistent
    # installation location. Detect the compiled template before path
    # normalization and prevent that transient directory entering manifests.
    $PortableInfo = Get-NSISPortableLauncherInfo -State $State
    $State.Metadata.IsPortable = $PortableInfo.IsPortable
    $State.Metadata.PortableEvidence = [string[]]$PortableInfo.Evidence
    if ($PortableInfo.IsPortable) {
      $State.Metadata.DefaultInstallLocation = $null
      $State.Warnings.Add('The NSIS executable is an electron-builder portable launcher: it sets the PORTABLE_EXECUTABLE_* environment variables, executes the unpacked application from a temporary directory, and writes no visible Apps & Features entry. Treat the outer EXE as portable payload evidence rather than an installed NSIS package.')
    }
  }

  # Manifests carry environment-variable install roots, not host-absolute paths.
  # Scope detection above already consumed the resolved path, so normalize only
  # the reported value.
  if ($State.Metadata.DefaultInstallLocation) {
    $State.Metadata.DefaultInstallLocation = ConvertTo-NSISManifestPath -Path $State.Metadata.DefaultInstallLocation
  }

  $ExtractedFiles = @($State.Files) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique
  $ExecutedPayloads = @($State.ExecutedPayloads)
  $SeenRegistryWrites = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

  # Deduplicate exact registry evidence while preserving first-observed order.
  $RegistryWrites = @(
    foreach ($Write in @($State.RegistryWrites)) {
      $WriteKey = "$($Write.Root)`0$($Write.Key)`0$($Write.Name)`0$($Write.Value)`0$($Write.Type)"
      if ($SeenRegistryWrites.Add($WriteKey)) { $Write }
    }
  )
  $NestedInstallerEvidence = @($ExtractedFiles + @($ExecutedPayloads | ForEach-Object { "$($_.Command) $($_.Parameters)" })).Where({
      $_ -match '(?i)\.(msi|msp|msu)(\s|$)|(^|[\\/])(setup|install|installer)\.exe(\s|$)'
    })

  if (-not $State.Metadata.WritesAppsAndFeaturesEntry -and $NestedInstallerEvidence.Count -gt 0) {
    # A wrapper that extracts or executes another installer may delegate ARP
    # ownership; surface that ambiguity instead of inventing an NSIS ProductCode.
    $State.Warnings.Add('The NSIS installer has nested installer evidence but no visible uninstall registry write was found; inspect the nested payload or validate ARP in a VM.')
  }
  if (-not $SkipLocalizedAppsAndFeaturesEntries -and
    -not $State.Metadata.IsPortable -and
    $State.Metadata.HasArchitectureRuntimeCheck -and
    [string]::IsNullOrWhiteSpace([string]$State.TargetArchitecture) -and
    [string]::IsNullOrWhiteSpace([string]$State.Metadata.ProductCode)) {
    $State.Warnings.Add('The installer contains a runtime architecture branch; pass -Architecture x86, x64, or arm64 to resolve architecture-specific ARP metadata deterministically.')
  }
  if (-not $SkipLocalizedAppsAndFeaturesEntries -and
    $State.Metadata.HasScopeRuntimeCheck -and
    [string]::IsNullOrWhiteSpace([string]$State.TargetScope) -and
    @($State.Metadata.SupportedScopes).Count -gt 1) {
    $State.Warnings.Add('The installer contains runtime user and machine scope branches; pass -Scope user or machine to resolve scope-specific ARP metadata deterministically.')
  }
  if (-not $SkipLocalizedAppsAndFeaturesEntries -and
    $State.Metadata.HasScopeRuntimeCheck -and
    -not [string]::IsNullOrWhiteSpace([string]$State.TargetScope) -and
    -not [string]::IsNullOrWhiteSpace([string]$State.Metadata.Scope) -and
    $State.TargetScope -ne $State.Metadata.Scope) {
    $State.Warnings.Add("The requested '$($State.TargetScope)' scope did not resolve to matching uninstall registry evidence; the parser observed '$($State.Metadata.Scope)' scope instead.")
  }

  $State.Metadata.AppsAndFeaturesProductCode = if ($State.Metadata.WritesAppsAndFeaturesEntry) { $State.Metadata.ProductCode } else { $null }
  $State.Metadata.AppsAndFeaturesInstallerType = if ($State.Metadata.WritesAppsAndFeaturesEntry) { 'nullsoft' } else { $null }
  $State.Metadata.RegistryWrites = @($RegistryWrites)
  if (-not $SkipLocalizedAppsAndFeaturesEntries) {
    # The all-language projection scans explicit registry commands once per
    # language. Defer it until a result is returned rather than repeating it for
    # the simulator's intermediate completeness checks.
    $AppsAndFeaturesInfo = Get-NSISAppsAndFeaturesEntryInfo -State $State
    $State.Metadata.AppsAndFeaturesEntries = @($AppsAndFeaturesInfo.AppsAndFeaturesEntries)
    $State.Metadata.AppsAndFeaturesEntryEvidence = @($AppsAndFeaturesInfo.AppsAndFeaturesEntryEvidence)
    $State.Metadata.Notices = [string[]]@($AppsAndFeaturesInfo.Notices)
    $State.Metadata.HasLocalizedAppsAndFeaturesEntries = $AppsAndFeaturesInfo.HasLocalizedEntries

    # Architecture-targeted simulation can intentionally skip a direct scan.
    # Recover a missing scalar only when every explicit visible ARP projection
    # agrees, preserving localized or architecture-specific differences.
    foreach ($PropertyName in @('DisplayName', 'DisplayVersion', 'Publisher')) {
      if (-not [string]::IsNullOrWhiteSpace([string]$State.Metadata[$PropertyName])) { continue }
      $Values = @($AppsAndFeaturesInfo.AppsAndFeaturesEntryEvidence | Where-Object IsVisible | ForEach-Object { $_.$PropertyName } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
      if ($Values.Count -eq 1) { $State.Metadata[$PropertyName] = $Values[0] }
    }
  }
  $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
  foreach ($Warning in @($RegistryAssociationInfo.Warnings)) { $State.Warnings.Add($Warning) }
  $State.Metadata.RegistryAssociationInfo = $RegistryAssociationInfo
  $State.Metadata.Protocols = $RegistryAssociationInfo.Protocols
  $State.Metadata.FileExtensions = $RegistryAssociationInfo.FileExtensions
  $State.Metadata.ExtractedFiles = @($ExtractedFiles)
  $State.Metadata.ExecutedPayloads = @($ExecutedPayloads)
  $State.Metadata.Warnings = [string[]]@($State.Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
  $State.Metadata.UnresolvedFields = [string[]]@($State.Metadata.UnresolvedFields | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
  $State.Metadata.ParserVersionInfo = $State.VersionInfo

  return [pscustomobject]$State.Metadata
}

function Invoke-NSISStaticSimulation {
  <#
  .SYNOPSIS
    Simulate NSIS installer code paths needed for deterministic static metadata
  .PARAMETER Path
    The path to the NSIS installer
  .PARAMETER Mode
    The simulation mode. Full runs initialization and sections; Fast returns early when direct uninstall metadata is complete.
  .PARAMETER Architecture
    The target Windows architecture used to resolve compiled runtime architecture checks
  .PARAMETER Scope
    The target installation scope used to resolve compiled MultiUser scope setters
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The simulation mode')]
    [ValidateSet('Full', 'Fast')]
    [string]$Mode = 'Full',

    [Parameter(HelpMessage = 'The target Windows architecture used to resolve runtime architecture checks')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [Parameter(HelpMessage = 'The target installation scope used to resolve runtime scope checks')]
    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  process {
    # Parse and normalize the compiled header once; all later phases share the
    # same mutable state so callbacks and sections observe prior variable writes.
    $HeaderData = Get-NSISHeaderData -Path $Path
    $InitializationArguments = @{ HeaderData = $HeaderData }
    if (-not [string]::IsNullOrWhiteSpace($Architecture)) { $InitializationArguments.Architecture = $Architecture }
    if (-not [string]::IsNullOrWhiteSpace($Scope)) { $InitializationArguments.Scope = $Scope }
    $InitializedState = Initialize-NSISState @InitializationArguments
    $State = $InitializedState.State
    $Layout = $InitializedState.Layout
    $ArchitectureProbeStart = Get-NSISArchitectureProbeStart -State $State
    $State.Metadata.HasArchitectureRuntimeCheck = $ArchitectureProbeStart -ge 0
    $ScopeSelectionStarts = [ordered]@{
      user    = Get-NSISScopeSelectionStart -State $State -Scope user
      machine = Get-NSISScopeSelectionStart -State $State -Scope machine
    }
    $State.Metadata.SupportedScopes = [string[]]@($ScopeSelectionStarts.Keys | Where-Object { $ScopeSelectionStarts[$_] -ge 0 })
    $State.Metadata.HasScopeRuntimeCheck = $State.Metadata.SupportedScopes.Count -gt 0
    $ScopeSelectionStart = if (-not [string]::IsNullOrWhiteSpace($Scope)) { $ScopeSelectionStarts[$Scope] } else { -1 }
    $HasTargetArchitectureResolver = $ArchitectureProbeStart -ge 0 -and -not [string]::IsNullOrWhiteSpace($Architecture)
    $HasTargetScopeResolver = $ScopeSelectionStart -ge 0 -and -not [string]::IsNullOrWhiteSpace($Scope)
    $UseDirectRegistryFallback = -not ($HasTargetArchitectureResolver -or $HasTargetScopeResolver)

    # Prefer direct uninstall registry writes when they already expose a single deterministic ARP identity.
    if ($UseDirectRegistryFallback) { Add-NSISDirectUninstallWrites -State $State }
    $Metadata = Complete-NSISMetadata -State $State -SkipLocalizedAppsAndFeaturesEntries
    if ($Mode -eq 'Fast' -and -not [string]::IsNullOrWhiteSpace($Metadata.DisplayName) -and -not [string]::IsNullOrWhiteSpace($Metadata.DisplayVersion) -and -not [string]::IsNullOrWhiteSpace($Metadata.ProductCode)) {
      # Fast mode is an explicit optimization: direct uninstall writes must
      # already provide complete deterministic identity before callbacks are skipped.
      return [pscustomobject]@{
        State       = $State
        Layout      = $Layout
        HeaderData  = $HeaderData
        Metadata    = Complete-NSISMetadata -State $State
        IsEarlyExit = $true
      }
    }

    $InitializationCompleted = $true
    if ($Layout.CodeOnInit -ge 0) {
      try {
        $null = Invoke-NSISCodeSegment -State $State -Position $Layout.CodeOnInit
      } catch {
        # Continue parsing when non-metadata callbacks loop or rely on unsupported runtime state.
        $InitializationCompleted = $false
      }
    }

    if (-not $InitializationCompleted -and -not [string]::IsNullOrWhiteSpace($Architecture)) {
      # Some legacy installers execute complex UI helpers before their x64.nsh
      # probe. If that prefix exceeds the watchdog, resume at the source-backed
      # architecture macro rather than losing architecture-selected ARP values.
      if ($ArchitectureProbeStart -ge 0) {
        try {
          $null = Invoke-NSISCodeSegment -State $State -Position $ArchitectureProbeStart
        } catch {
          # Later UI-only initialization remains optional after the architecture
          # branch has had an opportunity to populate deterministic variables.
        }
      }
    }

    if ($HasTargetScopeResolver) {
      # Enter the compiled scope setter directly after initialization. This
      # mirrors the deterministic MultiUser macro branch without emulating UAC,
      # account privilege checks, dialogs, or command-line parsing.
      Initialize-NSISTargetRegistryState -State $State
      Initialize-NSISScopeSelectionInput -State $State -Position $ScopeSelectionStart -Scope $Scope
      try {
        $null = Invoke-NSISCodeSegment -State $State -Position $ScopeSelectionStart
      } catch {
        $State.Warnings.Add("The compiled '$Scope' scope selector could not be simulated completely: $($_.Exception.Message)")
      }
    }

    # Initialization commonly establishes SHCTX before install sections begin.
    # Replay explicit writes so their scope reflects that context instead of the
    # conservative pre-simulation fallback used by the first literal scan.
    if ($State.ShellVarContext -and -not $HasTargetScopeResolver) { Add-NSISDirectUninstallWrites -State $State }

    # Very large NSISBI installers can contain one extraction command per
    # payload file. Walking all of those commands adds no identity evidence once
    # initialization and explicit uninstall writes are complete, and can take
    # minutes for Unity-sized archives. Keep Full as the normal behavior while
    # bounding this payload-only path after deterministic ARP metadata is known.
    $InitializedMetadata = Complete-NSISMetadata -State $State -SkipLocalizedAppsAndFeaturesEntries
    if ($HeaderData.IsNsisBi -and $State.Entries.Count -gt $Script:NSIS_MAX_FULL_SIMULATION_ENTRY_COUNT -and
      -not [string]::IsNullOrWhiteSpace($InitializedMetadata.DisplayName) -and
      -not [string]::IsNullOrWhiteSpace($InitializedMetadata.DisplayVersion) -and
      -not [string]::IsNullOrWhiteSpace($InitializedMetadata.ProductCode)) {
      $State.Warnings.Add("Full section simulation was skipped after deterministic uninstall metadata was recovered because the NSISBI command table contains $($State.Entries.Count) entries.")
      return [pscustomobject]@{
        State           = $State
        Layout          = $Layout
        HeaderData      = $HeaderData
        Metadata        = Complete-NSISMetadata -State $State
        IsEarlyExit     = $true
        EarlyExitReason = 'LargeNsisBiCommandTable'
      }
    }

    foreach ($Section in $State.Sections) {
      if ($Section.CodeOffset -lt 0) { continue }

      # Sections are independent entry points. Unsupported or looping sections
      # do not discard evidence already recovered from other sections.
      try {
        $Result = Invoke-NSISCodeSegment -State $State -Position $Section.CodeOffset
      } catch {
        continue
      }
      if ($Result -eq 'Quit') { break }
    }

    if ($Layout.CodeOnInstSuccess -ge 0) {
      try {
        $null = Invoke-NSISCodeSegment -State $State -Position $Layout.CodeOnInstSuccess
      } catch {
        # Continue parsing when the success callback contains unsupported UI-only behavior.
      }
    }

    if (($HasTargetArchitectureResolver -or $HasTargetScopeResolver) -and
      @($State.RegistryWrites | Where-Object IsUninstallKey).Count -eq 0) {
      # A selected architecture branch or an electron-builder custom scope hook
      # can stop the bounded simulator before explicit uninstall writes are
      # reached. Recover only one identity in the caller-requested hive;
      # architecture- or scope-dependent alternatives remain unresolved.
      $null = Add-NSISUnambiguousTargetUninstallWrites -State $State
    }

    if ($UseDirectRegistryFallback -and
      ([string]::IsNullOrWhiteSpace($State.Metadata.DisplayVersion) -or [string]::IsNullOrWhiteSpace($State.Metadata.ProductCode))) {
      # Re-scan literal EW_WRITEREG instructions only when dynamic control flow
      # did not reach enough explicit uninstall metadata.
      Add-NSISDirectUninstallWrites -State $State
    }

    return [pscustomobject]@{
      State       = $State
      Layout      = $Layout
      HeaderData  = $HeaderData
      Metadata    = Complete-NSISMetadata -State $State
      IsEarlyExit = $false
    }
  }
}

function Get-NSISPlainStrings {
  <#
  .SYNOPSIS
    Recover plain strings from the decoded NSIS strings block for static feature detection
  .PARAMETER State
    The mutable NSIS execution state
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State
  )

  $Strings = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $Encoding = if ($State.VersionInfo.Unicode) { [System.Text.Encoding]::Unicode } else { [System.Text.Encoding]::Default }
  $Step = if ($State.VersionInfo.Unicode) { 2 } else { 1 }
  $Start = 0
  $Index = 0

  while ($Index -lt $State.StringsBlock.Length) {
    $IsTerminator = if ($State.VersionInfo.Unicode) {
      $Index + 1 -lt $State.StringsBlock.Length -and $State.StringsBlock[$Index] -eq 0x00 -and $State.StringsBlock[$Index + 1] -eq 0x00
    } else {
      $State.StringsBlock[$Index] -eq 0x00
    }

    if ($IsTerminator) {
      if ($Index -gt $Start) {
        $Text = $Encoding.GetString($State.StringsBlock, $Start, $Index - $Start).Trim()
        if (-not [string]::IsNullOrWhiteSpace($Text)) { $null = $Strings.Add($Text) }
      }

      $Index += $Step
      $Start = $Index
    } else {
      $Index += $Step
    }
  }

  if ($State.LanguageTable) {
    foreach ($Offset in $State.LanguageTable.StringOffsets) {
      if ($Offset -eq 0) { continue }
      $Text = Get-NSISString -State $State -RelativeOffset $Offset
      if (-not [string]::IsNullOrWhiteSpace($Text)) { $null = $Strings.Add($Text) }
    }
  }

  return @($Strings)
}

function Get-NSISInstallerSwitchInfo {
  <#
  .SYNOPSIS
    Extract command-line switch evidence from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    # Reuse one full parse/simulation and inspect its decoded string table; do not
    # invoke individual metadata readers, which would parse the installer again.
    $Simulation = Invoke-NSISStaticSimulation -Path $Path
    $Strings = Get-NSISPlainStrings -State $Simulation.State
    $TauriInfo = Get-NSISTauriInstallerInfo -State $Simulation.State
    $Switches = [System.Collections.Generic.List[object]]::new()
    $RejectedSwitches = [System.Collections.Generic.List[object]]::new()
    $Seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $Pattern = '(?<![A-Za-z0-9_./\\-])(?:--[A-Za-z][A-Za-z0-9._-]+|/[A-Za-z](?:[A-Za-z0-9._-]+)?)(?::[^\s"''<>]+|=[^\s"''<>]+)?'
    $DefaultSwitches = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Switch in @('/S', '/NCRC', '/D', '/SD', '/LANG', '/LOG')) { $null = $DefaultSwitches.Add($Switch) }
    $ScopeSwitches = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Switch in @('/CURRENTUSER', '/currentuser', '/AllUsers', '/ALLUSERS', '/allusers', '--all-users', '--current-user')) { $null = $ScopeSwitches.Add($Switch) }
    $SilentSwitches = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Switch in @('/S', '/silent', '/verysilent', '--silent', '--updated')) { $null = $SilentSwitches.Add($Switch) }
    $TauriSwitchPurposes = [ordered]@{
      '/P'      = 'Passive installation with progress'
      '/NS'     = 'Suppress shortcut creation'
      '/UPDATE' = 'Internal updater mode'
      '/R'      = 'Run the application after silent or passive installation'
      '/ARGS'   = 'Arguments passed to the application launched by /R'
    }
    $ParsingMarkers = @($Strings | Where-Object {
        $_ -match '(?i)\b(TestParameter|GetParameters|GetOptions|IfSilent|StrStr|CommandLine|Parameters)\b'
      } | Select-Object -First 20)

    # A slash token is accepted only when known, adjacent to command-line parser
    # evidence, or a short standalone token. This filters nested process switches.
    foreach ($String in $Strings) {
      foreach ($Match in [regex]::Matches($String, $Pattern)) {
        $Value = $Match.Value
        $Name = if ($Value -match '^([^:=]+)') { $Matches[1] } else { $Value }
        if ($Name -match '\.(exe|dll|msi|zip|7z|ico|png|jpg|jpeg|json|yml|yaml|txt|html?)$') { continue }
        if ($Name -match '^/[A-Z]:$') { continue }

        $IsTauriSwitch = $TauriInfo.IsTauri -and $TauriSwitchPurposes.Contains($Name)
        $IsKnownSwitch = $DefaultSwitches.Contains($Name) -or $ScopeSwitches.Contains($Name) -or $SilentSwitches.Contains($Name) -or $IsTauriSwitch
        $HasParsingEvidence = $String -match '(?i)\b(TestParameter|GetParameters|GetOptions|IfSilent|StrStr|CommandLine|Parameters)\b'
        $EscapedValue = [regex]::Escape($Value)
        $TrimmedString = $String.Trim()
        $IsStandaloneEvidence = $TrimmedString -eq $Value -or ($TrimmedString.Length -le 160 -and $TrimmedString -match "(^|\s)$EscapedValue(\s|$)")
        $LooksLikeNestedCommand = $String -match '(?i)\b(taskkill|cmd(?:\.exe)?|powershell(?:\.exe)?|reg(?:\.exe)?|regsvr32(?:\.exe)?|msiexec(?:\.exe)?|rundll32(?:\.exe)?)\b'
        if (-not ($IsKnownSwitch -or $HasParsingEvidence -or ($IsStandaloneEvidence -and -not $LooksLikeNestedCommand))) {
          $RejectedSwitches.Add([pscustomobject]@{
              Switch   = $Value
              Reason   = 'Internal command-line or non-installer switch evidence'
              Evidence = $String
            })
          continue
        }
        if (-not $Seen.Add($Value)) { continue }
        $Evidence = @($Strings | Where-Object { $_ -like "*$Value*" } | Select-Object -First 5)
        $Switches.Add([pscustomobject]@{
            Switch              = $Value
            Name                = $Name
            IsDefaultNsisSwitch = $DefaultSwitches.Contains($Name)
            IsScopeSwitch       = $ScopeSwitches.Contains($Name)
            IsSilentSwitch      = $SilentSwitches.Contains($Name)
            IsTauriSwitch       = $IsTauriSwitch
            Purpose             = if ($IsTauriSwitch) { $TauriSwitchPurposes[$Name] } else { $null }
            IsCustomCandidate   = -not $DefaultSwitches.Contains($Name)
            Evidence            = $Evidence
          })
      }
    }

    $AdditionalSwitches = @($Switches | Where-Object { $_.IsCustomCandidate } | Select-Object -ExpandProperty Switch)

    $Warnings = [System.Collections.Generic.List[string]]::new()
    $Warnings.Add('Switch extraction is static string evidence. Confirm switch control-flow in the NSIS script or a VM before using custom switches in manifests.')
    if ($TauriInfo.IsTauri) {
      $Warnings.Add('Tauri /P is passive installation with progress; /R launches the application after installation, while /UPDATE and /ARGS are internal update/run arguments rather than general manifest switches.')
    }

    [pscustomobject]@{
      Path                       = (Get-Item -Path $Path -Force).FullName
      InstallerType              = 'Nullsoft'
      IsTauri                    = $TauriInfo.IsTauri
      TauriInstallerMode         = $TauriInfo.InstallerMode
      Switches                   = $Switches.ToArray()
      TauriSwitches              = @($Switches | Where-Object { $_.IsTauriSwitch })
      AdditionalSwitches         = $AdditionalSwitches
      ScopeSwitches              = @($Switches | Where-Object { $_.IsScopeSwitch } | Select-Object -ExpandProperty Switch)
      SilentSwitches             = @($Switches | Where-Object { $_.IsSilentSwitch } | Select-Object -ExpandProperty Switch)
      CommandLineParsingEvidence = $ParsingMarkers
      RejectedSwitchCandidates   = $RejectedSwitches.ToArray()
      Warnings                   = [string[]]$Warnings.ToArray()
    }
  }
}

function Read-AdditionalInstallerSwitchesFromNSIS {
  <#
  .SYNOPSIS
    Read non-default command-line switch candidates from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    (Get-NSISInstallerSwitchInfo -Path $Path).AdditionalSwitches
  }
}

function Get-ElectronBuilderNSISArchitecture {
  <#
  .SYNOPSIS
    Infer the preferred WinGet architecture from electron-builder app package files
  .PARAMETER Architectures
    The detected electron-builder app package architectures
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The detected electron-builder app package architectures')]
    [string[]]$Architectures
  )

  # electron-builder universal installers with x86 payloads are x86-compatible,
  if ($Architectures -contains 'x86') { return 'x86' }
  if ($Architectures -contains 'x64') { return 'x64' }
  if ($Architectures -contains 'arm64') { return 'arm64' }
  return $null
}

function Get-ElectronBuilderNSISDetection {
  <#
  .SYNOPSIS
    Detect electron-builder payload evidence from simulated NSIS state
  .PARAMETER State
    The mutable NSIS execution state
  .PARAMETER Strings
    Plain strings recovered from the NSIS strings block
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'Plain strings recovered from the NSIS strings block')]
    [string[]]$Strings
  )

  # electron-builder's architecture payload names are compiler-generated format
  # evidence; generic Electron strings or `--updated` alone are insufficient.
  $Architectures = [System.Collections.Generic.List[string]]::new()
  foreach ($Value in @($State.Files) + @($Strings)) {
    if ($Value -match '(?i)(^|[\\/])app-32\.(7z|zip)$|(^|[\\/])app-32$') {
      if (-not $Architectures.Contains('x86')) { $Architectures.Add('x86') }
    }
    if ($Value -match '(?i)(^|[\\/])app-64\.(7z|zip)$|(^|[\\/])app-64$') {
      if (-not $Architectures.Contains('x64')) { $Architectures.Add('x64') }
    }
    if ($Value -match '(?i)(^|[\\/])app-arm64\.(7z|zip)$|(^|[\\/])app-arm64$') {
      if (-not $Architectures.Contains('arm64')) { $Architectures.Add('arm64') }
    }
  }

  $AppPackageEvidence = @(
    foreach ($Value in @($State.Files) + @($Strings)) {
      if ($Value -match '(?i)(app-(?:32|64|arm64)(?:\.(?:7z|zip))?)') { $Matches[1].ToLowerInvariant() }
    }
  ) | Select-Object -Unique
  # Scope support is identified independently from architecture because some
  # electron-builder configurations are per-user or per-machine only.
  $HasDualScopeUi = @($Strings).Where({
      $_ -like '*make this software available to all users*' -or
      $_ -like '*Fresh install for all users*' -or
      $_ -like '*Fresh install for current user*'
    }, 'First').Count -gt 0

  $OrderedArchitectures = @('arm64', 'x64', 'x86').Where({ $Architectures.Contains($_) })
  $PortableInfo = Get-NSISPortableLauncherInfo -State $State

  return [pscustomobject]@{
    IsElectronBuilder = $Architectures.Count -gt 0
    IsPortable        = $PortableInfo.IsPortable
    PortableEvidence  = [string[]]$PortableInfo.Evidence
    Architectures     = $OrderedArchitectures
    AppPackageFiles   = $AppPackageEvidence
    HasUpdatedSwitch  = @($Strings).Where({ $_ -eq '--updated' }, 'First').Count -gt 0
    HasDualScopeUi    = $HasDualScopeUi
  }
}

function Test-ElectronBuilder {
  <#
  .SYNOPSIS
    Test whether a Nullsoft installer was built by electron-builder
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Simulation = Invoke-NSISStaticSimulation -Path $Path
    $Strings = Get-NSISPlainStrings -State $Simulation.State
    return (Get-ElectronBuilderNSISDetection -State $Simulation.State -Strings $Strings).IsElectronBuilder
  }
}

function Get-ElectronBuilderNSISInfo {
  <#
  .SYNOPSIS
    Get static electron-builder traits from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Simulation = Invoke-NSISStaticSimulation -Path $Path
    $State = $Simulation.State
    $Strings = Get-NSISPlainStrings -State $State
    $Detection = Get-ElectronBuilderNSISDetection -State $State -Strings $Strings
    $Architectures = @($Detection.Architectures)

    # Prefer explicit dual-scope UI evidence, otherwise retain the uninstall
    # registry hive observed by the shared NSIS simulation.
    $SupportedScopes = if ($Detection.HasDualScopeUi) {
      @('user', 'machine')
    } elseif ($State.Metadata.Scope -eq 'machine') {
      @('machine')
    } else {
      @('user')
    }

    [pscustomobject]@{
      Path                   = (Get-Item -Path $Path -Force).FullName
      InstallerType          = 'Nullsoft'
      Family                 = 'electron-builder'
      IsElectronBuilder      = $Detection.IsElectronBuilder
      IsPortable             = $Detection.IsPortable
      Architectures          = @($Architectures)
      Architecture           = if ($Architectures.Count -gt 0) { Get-ElectronBuilderNSISArchitecture -Architectures @($Architectures) } else { $null }
      SupportedScopes        = [string[]]$SupportedScopes
      SupportsUserScope      = $SupportedScopes -contains 'user'
      SupportsMachineScope   = $SupportedScopes -contains 'machine'
      SupportsDualScope      = $SupportedScopes.Count -gt 1
      ProductCode            = $State.Metadata.ProductCode
      DisplayName            = $State.Metadata.DisplayName
      DisplayVersion         = $State.Metadata.DisplayVersion
      Publisher              = $State.Metadata.Publisher
      DefaultInstallLocation = $State.Metadata.DefaultInstallLocation
      Evidence               = [pscustomobject]@{
        AppPackageFiles  = $Detection.AppPackageFiles
        HasUpdatedSwitch = $Detection.HasUpdatedSwitch
        HasDualScopeUi   = $Detection.HasDualScopeUi
        PortableEvidence = [string[]]$Detection.PortableEvidence
      }
    }
  }
}

# Simulation helpers remain callable by the public facade and extraction layer.
Export-ModuleMember -Function *
