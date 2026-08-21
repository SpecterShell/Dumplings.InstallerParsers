# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# NSIS command interpreter and virtual system-effect simulation.
# Instructor Registry plug-in stack and registry semantics are grounded in the
# published v4.2 source: https://nsis.sourceforge.io/Registry_plug-in

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# The original parser kept format constants and the simulator in one script scope. Import the
# format layer as a nested dependency and copy its documented NSIS constants into this module's
# script scope so existing `$Script:NSIS_*` lookups remain deterministic after the split.
$FormatModule = Import-Module (Join-Path $PSScriptRoot 'NSISFormat.psm1') -PassThru
foreach ($Entry in $FormatModule.ExportedVariables.GetEnumerator()) {
  Set-Variable -Scope Script -Name $Entry.Key -Value $Entry.Value.Value
}

$Script:NSIS_STRING_CODE_MAPS = @{
  NSIS2 = @{ 252 = 'Skip'; 253 = 'Var'; 254 = 'Shell'; 255 = 'Lang' }
  NSIS3 = @{ 1 = 'Lang'; 2 = 'Shell'; 3 = 'Var'; 4 = 'Skip' }
  Park  = @{ 0xE000 = 'Skip'; 0xE001 = 'Var'; 0xE002 = 'Shell'; 0xE003 = 'Lang' }
}

function Get-NSISAnsiEncoding {
  <#
  .SYNOPSIS
    Resolve the byte encoding used for ANSI NSIS literal text.
  .PARAMETER LanguageId
    Windows language identifier from the selected NSIS language table.
  .PARAMETER CodePage
    Explicit compiler/source code page supplied by the caller.
  #>
  [OutputType([System.Text.Encoding])]
  param (
    [int]$LanguageId,
    [int]$CodePage
  )

  [Text.Encoding]::RegisterProvider([Text.CodePagesEncodingProvider]::Instance)
  if ($CodePage -gt 0) { return [Text.Encoding]::GetEncoding($CodePage) }
  if ($LanguageId -gt 0) {
    try { return [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::GetCultureInfo($LanguageId).TextInfo.ANSICodePage) } catch { }
  }
  return [Text.Encoding]::GetEncoding(1252)
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

  $Route = if ($Type -like 'Park*') { 'Park' } elseif ($IsV3) { 'NSIS3' } else { 'NSIS2' }
  return $Script:NSIS_STRING_CODE_MAPS[$Route][[int]$Character]
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

function Get-NSISVariableLayout {
  <#
  .SYNOPSIS
    Resolve predefined-variable indexes for the selected catalog profile.
  .PARAMETER State
    Initialized NSIS state containing VersionInfo.VariableRoute.
  #>
  [OutputType([hashtable])]
  param ([Parameter(Mandatory)][pscustomobject]$State)

  $Route = Get-NSISVariableRoute -State $State
  $Layout = $Script:NSISFormatCatalog.VariableLayouts[$Route]
  if (-not $Layout) { throw "NSIS variable route '$Route' is not implemented." }
  return $Layout
}

function Get-NSISVariableRoute {
  <#
  .SYNOPSIS
    Resolve the predefined-variable route for a parser state.
  .PARAMETER State
    NSIS execution state. Catalog-aware states expose VersionInfo.VariableRoute;
    older synthetic states use the current NSIS layout for compatibility.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][pscustomobject]$State)

  if (-not $State.PSObject.Properties['VersionInfo'] -or $null -eq $State.VersionInfo) {
    return 'current'
  }
  $Property = $State.VersionInfo.PSObject.Properties['VariableRoute']
  if ($Property -and -not [string]::IsNullOrWhiteSpace([string]$Property.Value)) {
    return [string]$Property.Value
  }
  return 'current'
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

  if ($State.PSObject.Properties['UnknownVariables'] -and $State.UnknownVariables.Contains($Index)) {
    return "`$_NSIS_UNKNOWN_VAR_${Index}_"
  }
  if ($State.Variables.ContainsKey($Index)) { return [string]$State.Variables[$Index] }

  $VariableLayout = Get-NSISVariableLayout -State $State
  if ($null -ne $VariableLayout.ExePath -and $Index -eq $VariableLayout.ExePath) { return '$EXEPATH' }
  if ($null -ne $VariableLayout.ExeFile -and $Index -eq $VariableLayout.ExeFile) { return Split-Path -Path $State.Path -Leaf }
  if ($Index -eq $VariableLayout.Click) { return 'Click Next to continue.' }

  switch ($Index) {
    $Script:NSIS_PREDEFINED_VAR_CMDLINE { return $State.CommandLine }
    $Script:NSIS_PREDEFINED_VAR_EXEDIR { return '$EXEDIR' }
    $Script:NSIS_PREDEFINED_VAR_LANGUAGE { return [string]$State.LanguageTable.LanguageId }
    $Script:NSIS_PREDEFINED_VAR_TEMP { return '$TEMP' }
    $Script:NSIS_PREDEFINED_VAR_PLUGINSDIR { return '$PLUGINSDIR' }
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

  if ($State.PSObject.Properties['UnknownVariables']) { $null = $State.UnknownVariables.Remove($Index) }
  $State.Variables[$Index] = $Value

  $VariableLayout = Get-NSISVariableLayout -State $State
  $SavedOutDir = $VariableLayout.SavedOutDir

  switch ($Index) {
    $Script:NSIS_PREDEFINED_VAR_INSTDIR {
      $State.Variables[$Script:NSIS_PREDEFINED_VAR_OUTDIR] = $Value
      if ($null -ne $SavedOutDir) { $State.Variables[$SavedOutDir] = $Value }
      if (-not [string]::IsNullOrWhiteSpace($Value)) { $State.Metadata.DefaultInstallLocation = $Value }
    }
    $Script:NSIS_PREDEFINED_VAR_OUTDIR { if ($null -ne $SavedOutDir) { $State.Variables[$SavedOutDir] = $Value } }
    default { }
  }
  if ($null -ne $SavedOutDir -and $Index -eq $SavedOutDir) { $State.Variables[$Script:NSIS_PREDEFINED_VAR_OUTDIR] = $Value }
}

function Set-NSISVariableUnknown {
  <#
  .SYNOPSIS
    Mark a destination variable unresolved after divergent branch values merge.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Index
    Compiled variable index.
  #>
  [OutputType([void])]
  param ([Parameter(Mandatory)][pscustomobject]$State, [Parameter(Mandatory)][int]$Index)

  $null = $State.Variables.Remove($Index)
  $null = $State.UnknownVariables.Add($Index)
  if ($Index -eq $Script:NSIS_PREDEFINED_VAR_INSTDIR) { $State.Metadata.DefaultInstallLocation = $null }
}

function Test-NSISStringOperandUnknown {
  <#
  .SYNOPSIS
    Test whether one compiled string depends on an unresolved variable.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER RelativeOffset
    String-table operand offset.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][pscustomobject]$State, [Parameter(Mandatory)][int]$RelativeOffset)

  foreach ($Index in @(Get-NSISStringVariableIndex -State $State -RelativeOffset $RelativeOffset)) {
    if ($State.UnknownVariables.Contains([int]$Index)) { return $true }
  }
  return $false
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
        return $(if ($Is64BitFolder) { '%ProgramFiles%' } else { '%ProgramFiles(x86)%' })
      }
      'CommonFilesDir' {
        return $(if ($Is64BitFolder) { '%ProgramFiles%\Common Files' } else { '%ProgramFiles(x86)%\Common Files' })
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
  .PARAMETER VariableRoute
    Catalogued predefined-variable layout.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The compiled NSIS variable index')]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$Index,

    [ValidateSet('legacy-200', 'legacy-225', 'current')]
    [string]$VariableRoute = 'current'
  )

  # User variables occupy $0..$9 and $R0..$R9. Modern NSIS then exposes twelve
  # predefined variables; compiler-private variables use the $_N_ notation that
  # 7-Zip presents in its NSIS archive catalog.
  if ($Index -lt 10) { return '$' + $Index }
  if ($Index -lt 20) { return '$R' + ($Index - 10) }
  $Layout = $Script:NSISFormatCatalog.VariableLayouts[$VariableRoute]
  $Names = @('CMDLINE', 'INSTDIR', 'OUTDIR', 'EXEDIR', 'LANGUAGE', 'TEMP', 'PLUGINSDIR')
  $InternalIndex = $Index - 20
  if ($InternalIndex -lt $Names.Count) { return '$' + $Names[$InternalIndex] }
  if ($null -ne $Layout.ExePath -and $Index -eq $Layout.ExePath) { return '$EXEPATH' }
  if ($null -ne $Layout.ExeFile -and $Index -eq $Layout.ExeFile) { return '$EXEFILE' }
  if ($Index -eq $Layout.HwndParent) { return '$HWNDPARENT' }
  if ($Index -eq $Layout.Click) { return '$_CLICK' }
  if ($null -ne $Layout.SavedOutDir -and $Index -eq $Layout.SavedOutDir) { return '$_OUTDIR' }
  return '$_' + ($Index - $Layout.CustomVariableBase) + '_'
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

  $AnsiEncoding = if ($State.PSObject.Properties['AnsiEncoding'] -and $State.AnsiEncoding) { $State.AnsiEncoding } else { Get-NSISAnsiEncoding -LanguageId $Script:NSIS_DEFAULT_LANGUAGE }
  $Builder = [Text.StringBuilder]::new()
  $Index = 0
  while ($Index -lt $Characters.Count) {
    $Current = $Characters[$Index]
    $CodeKind = Get-NSISStringCodeKind -Character $Current -IsV3 $State.VersionInfo.IsV3 -Type $State.VersionInfo.Type

    if (-not $CodeKind -and -not $State.VersionInfo.Unicode) {
      # Decode the complete ANSI literal run at once. Decoding byte-by-byte
      # corrupts DBCS text such as Japanese product names before variables and
      # shell constants are rendered symbolically.
      $LiteralStart = $Index
      while ($Index -lt $Characters.Count -and -not (Get-NSISStringCodeKind -Character $Characters[$Index] -IsV3 $State.VersionInfo.IsV3 -Type $State.VersionInfo.Type)) { $Index++ }
      $LiteralBytes = [byte[]]::new($Index - $LiteralStart)
      for ($LiteralIndex = 0; $LiteralIndex -lt $LiteralBytes.Length; $LiteralIndex++) { $LiteralBytes[$LiteralIndex] = [byte]$Characters[$LiteralStart + $LiteralIndex] }
      $null = $Builder.Append($AnsiEncoding.GetString($LiteralBytes))
      continue
    }

    if (-not $CodeKind) {
      $null = $Builder.Append([char]$Current)
      $Index++
      continue
    }
    if ($Index + 1 -ge $Characters.Count) { break }

    if ($CodeKind -eq 'Skip') {
      $Index++
      $null = $Builder.Append([char]$Characters[$Index])
      $Index++
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
      'Var' { $null = $Builder.Append((ConvertTo-NSISSymbolicVariable -Index $Number -VariableRoute (Get-NSISVariableRoute -State $State))) }
      'Shell' { $null = $Builder.Append((Resolve-NSISSymbolicShellValue -State $State -Character $Payload -Depth $Depth)) }
      'Lang' { $null = $Builder.Append(('$(LSTR_' + $Number + ')')) }
    }
    $Index++
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
  $SavedOutDirIndex = (Get-NSISVariableLayout -State $State).SavedOutDir
  foreach ($Entry in $State.Entries) {
    if ($Entry.Opcode -eq $Script:NSIS_OPCODE_CREATE_DIR -and $Entry.Values[2] -ne 0) {
      # SetOutPath is encoded as EW_CREATEDIR with a nonzero second operand. A literal $OUTDIR
      # or compiler-private $_OUTDIR prefix extends the corresponding tracked path.
      $SetOutPath = Get-NSISSymbolicString -State $State -RelativeOffset $Entry.Values[1]
      $CurrentPrefix = Resolve-NSISArchiveOutputPrefix -Path $SetOutPath -CurrentPrefix $CurrentPrefix -SavedPrefix $SavedPrefix
      continue
    }

    if ($null -ne $SavedOutDirIndex -and $Entry.Opcode -eq $Script:NSIS_OPCODE_ASSIGN_VAR -and [int]$Entry.Raw[1] -eq $SavedOutDirIndex) {
      # NSIS macros use the private _OUTDIR variable to save and restore the active output path.
      $SavedPrefix = ''
      if ($Entry.Raw[3] -eq 0 -and $Entry.Raw[4] -eq 0) {
        $AssignedValue = Get-NSISSymbolicString -State $State -RelativeOffset $Entry.Values[2]
        if ($AssignedValue.Equals('$OUTDIR', [StringComparison]::OrdinalIgnoreCase)) { $SavedPrefix = $CurrentPrefix }
      }
      continue
    }

    if ($Entry.Opcode -notin @($Script:NSIS_OPCODE_EXTRACT_FILE, $Script:NSIS_OPCODE_EXTRACT_STUB_FILE)) { continue }

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
        DataSource   = if ($Entry.Opcode -eq $Script:NSIS_OPCODE_EXTRACT_STUB_FILE) { 'Embedded' } elseif ($HeaderData.HasExternalFile) { 'External' } else { 'Embedded' }
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
  .PARAMETER Depth
    Current recursion depth for language and shell indirections.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable NSIS execution state')]
    [pscustomobject]$State,

    [Parameter(Mandatory, HelpMessage = 'The compiled relative string offset')]
    [int]$RelativeOffset,

    [ValidateRange(0, 32)][int]$Depth = 0
  )

  if ($Depth -ge 16) {
    if ($State.PSObject.Properties['Diagnostics']) { $State.Diagnostics.Add('An NSIS string recursion or language-reference cycle exceeded the supported depth.') }
    return '$_ERROR_STRING_RECURSION_'
  }
  $AnsiEncoding = if ($State.PSObject.Properties['AnsiEncoding'] -and $State.AnsiEncoding) { $State.AnsiEncoding } else { Get-NSISAnsiEncoding -LanguageId $Script:NSIS_DEFAULT_LANGUAGE }

  if ($RelativeOffset -lt 0) {
    # Negative offsets encode language-table indices rather than byte positions.
    $LanguageIndex = [Math]::Abs($RelativeOffset + 1)
    if (-not $State.LanguageTable -or $LanguageIndex -ge $State.LanguageTable.StringOffsets.Count) { return '' }
    $ResolvedOffset = $State.LanguageTable.StringOffsets[$LanguageIndex]
    if ($ResolvedOffset -eq 0) { return '' }
    return Get-NSISString -State $State -RelativeOffset $ResolvedOffset -Depth ($Depth + 1)
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

    if (-not $CodeKind -and -not $State.VersionInfo.Unicode) {
      # Decode an uninterrupted ANSI literal as one byte sequence so DBCS
      # characters are not widened into unrelated Unicode code points.
      $LiteralStart = $Index
      while ($Index -lt $Characters.Count -and -not (Get-NSISStringCodeKind -Character $Characters[$Index] -IsV3 $State.VersionInfo.IsV3 -Type $State.VersionInfo.Type)) { $Index++ }
      $LiteralBytes = [byte[]]::new($Index - $LiteralStart)
      for ($LiteralIndex = 0; $LiteralIndex -lt $LiteralBytes.Length; $LiteralIndex++) { $LiteralBytes[$LiteralIndex] = [byte]$Characters[$LiteralStart + $LiteralIndex] }
      $null = $Builder.Append($AnsiEncoding.GetString($LiteralBytes))
      continue
    }

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
              if ($StringOffset -ne 0) { $null = $Builder.Append((Get-NSISString -State $State -RelativeOffset $StringOffset -Depth ($Depth + 1))) }
            }
          }
        }

        $Index++
        continue
      }
    }

    if ($State.VersionInfo.Unicode) { $null = $Builder.Append([char]$Current) }
    else { $null = $Builder.Append($AnsiEncoding.GetString([byte[]]@([byte]$Current))) }
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
      if ($VariableIndex -ge $Script:NSIS_PREDEFINED_VAR_CMDLINE -and
        $VariableIndex -lt (Get-NSISVariableLayout -State $State).CustomVariableBase) { continue }
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

function ConvertTo-NSISVirtualPath {
  <#
  .SYNOPSIS
    Normalize a Windows target path without resolving it on the parser host.
  .PARAMETER Path
    Literal or symbolic Windows path used by the compiled installer.
  #>
  [OutputType([string])]
  param ([AllowEmptyString()][Parameter(Mandatory)][string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
  $Normalized = $Path.Replace('/', '\')
  if ($Normalized.Length -gt 3) { $Normalized = $Normalized.TrimEnd('\') }
  return $Normalized
}

function Set-NSISVirtualFileRecord {
  <#
  .SYNOPSIS
    Store one explicit target filesystem fact in the virtual runtime.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Path
    Symbolic target path.
  .PARAMETER Exists
    Whether the target is known to exist.
  .PARAMETER IsDirectory
    Whether the target is a directory.
  .PARAMETER Content
    Optional bounded file bytes or text used by virtual FileRead operations.
  .PARAMETER FileVersion
    Optional dotted PE file version.
  .PARAMETER ProductVersion
    Optional dotted PE product version.
  .PARAMETER LastWriteTimeHigh
    High uint32 of the Windows FILETIME.
  .PARAMETER LastWriteTimeLow
    Low uint32 of the Windows FILETIME.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][string]$Path,
    [bool]$Exists = $true,
    [bool]$IsDirectory,
    [AllowNull()][object]$Content,
    [string]$FileVersion,
    [string]$ProductVersion,
    [uint32]$LastWriteTimeHigh,
    [uint32]$LastWriteTimeLow
  )

  $NormalizedPath = ConvertTo-NSISVirtualPath -Path $Path
  if ([string]::IsNullOrWhiteSpace($NormalizedPath)) { return $null }
  # Focused tests and consumers can provide a minimal simulation state. Create
  # the virtual containers lazily instead of requiring a full parsed installer.
  if (-not $State.PSObject.Properties['FileSystem']) { $State | Add-Member -NotePropertyName FileSystem -NotePropertyValue @{} }
  if (-not $State.PSObject.Properties['Directories']) { $State | Add-Member -NotePropertyName Directories -NotePropertyValue ([System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)) }
  if (-not $State.PSObject.Properties['Files']) { $State | Add-Member -NotePropertyName Files -NotePropertyValue ([System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)) }
  if ($Content -is [System.Collections.ICollection] -and $Content.Count -gt $Script:NSIS_MAX_VIRTUAL_FILE_BYTES) {
    throw "The virtual NSIS file '$NormalizedPath' exceeds the $Script:NSIS_MAX_VIRTUAL_FILE_BYTES-byte content limit."
  }
  $Record = [pscustomobject]@{
    Path              = $NormalizedPath
    Exists            = $Exists
    IsDirectory       = $IsDirectory
    Content           = $Content
    FileVersion       = $FileVersion
    ProductVersion    = $ProductVersion
    LastWriteTimeHigh = $LastWriteTimeHigh
    LastWriteTimeLow  = $LastWriteTimeLow
  }
  $State.FileSystem[$NormalizedPath] = $Record
  if ($Exists) {
    if ($IsDirectory) { $null = $State.Directories.Add($NormalizedPath) } else { $null = $State.Files.Add($NormalizedPath) }
  } else {
    $null = $State.Directories.Remove($NormalizedPath)
    $null = $State.Files.Remove($NormalizedPath)
  }
  return $Record
}

function Get-NSISVirtualFileRecord {
  <#
  .SYNOPSIS
    Read one exact target filesystem fact from the virtual runtime.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Path
    Symbolic target path.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [AllowEmptyString()][Parameter(Mandatory)][string]$Path
  )

  $NormalizedPath = ConvertTo-NSISVirtualPath -Path $Path
  if (-not $State.PSObject.Properties['FileSystem']) { return $null }
  if ($State.FileSystem.ContainsKey($NormalizedPath)) { return $State.FileSystem[$NormalizedPath] }
  return $null
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

  if (-not [string]::IsNullOrWhiteSpace($Path)) {
    $null = Set-NSISVirtualFileRecord -State $State -Path $Path -Exists $true -IsDirectory $true
  }
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
    [string]$Path,

    [AllowNull()][object]$Content,

    [string]$FileVersion,

    [string]$ProductVersion,

    [uint32]$LastWriteTimeHigh,

    [uint32]$LastWriteTimeLow
  )

  if (-not [string]::IsNullOrWhiteSpace($Path)) {
    $null = Set-NSISVirtualFileRecord -State $State -Path $Path -Exists $true -Content $Content -FileVersion $FileVersion -ProductVersion $ProductVersion -LastWriteTimeHigh $LastWriteTimeHigh -LastWriteTimeLow $LastWriteTimeLow
  }
}

function Get-NSISPathExistence {
  <#
  .SYNOPSIS
    Resolve a target path predicate as Present, Absent, or Unknown.
  .DESCRIPTION
    Files created by the simulated installer and explicit caller facts are
    authoritative. An unlisted path is unknown unless the caller declared its
    target filesystem snapshot complete.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Path
    Exact path or wildcard consumed by IfFileExists and FindFirst.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [AllowEmptyString()][Parameter(Mandatory)][string]$Path
  )

  $NormalizedPath = ConvertTo-NSISVirtualPath -Path $Path
  $HasWildcard = $NormalizedPath.IndexOfAny([char[]]'*?') -ge 0
  if (-not $State.PSObject.Properties['FileSystem']) {
    return $(if ($State.PSObject.Properties['FileSystemComplete'] -and $State.FileSystemComplete) { 'Absent' } else { 'Unknown' })
  }
  if ($HasWildcard) {
    $Pattern = [System.Management.Automation.WildcardPattern]::new($NormalizedPath, [System.Management.Automation.WildcardOptions]::IgnoreCase)
    foreach ($Record in $State.FileSystem.Values) {
      if ($Record.Exists -and $Pattern.IsMatch([string]$Record.Path)) { return 'Present' }
    }
  } else {
    $Record = Get-NSISVirtualFileRecord -State $State -Path $NormalizedPath
    if ($Record) { return $(if ($Record.Exists) { 'Present' } else { 'Absent' }) }
  }

  return $(if ($State.PSObject.Properties['FileSystemComplete'] -and $State.FileSystemComplete) { 'Absent' } else { 'Unknown' })
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

  return (Get-NSISPathExistence -State $State -Path $Path) -eq 'Present'
}

function Set-NSISExecutionError {
  <#
  .SYNOPSIS
    Increment or clear the virtual exec_error field consumed by IfErrors.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Clear
    Clear the accumulated error count instead of incrementing it.
  .PARAMETER Unknown
    Mark the flag unresolved because the operation depends on target state.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [switch]$Clear,
    [switch]$Unknown
  )

  if (-not $State.PSObject.Properties['ExecFlags']) { $State | Add-Member -NotePropertyName ExecFlags -NotePropertyValue @{} }
  if (-not $State.PSObject.Properties['UnknownExecFlags']) { $State | Add-Member -NotePropertyName UnknownExecFlags -NotePropertyValue ([System.Collections.Generic.HashSet[int]]::new()) }
  if ($Unknown) {
    $null = $State.UnknownExecFlags.Add($Script:NSIS_EXEC_FLAG_ERROR)
    return
  }
  $null = $State.UnknownExecFlags.Remove($Script:NSIS_EXEC_FLAG_ERROR)
  if ($Clear) {
    $State.ExecFlags[$Script:NSIS_EXEC_FLAG_ERROR] = 0
  } else {
    $Current = if ($State.ExecFlags.ContainsKey($Script:NSIS_EXEC_FLAG_ERROR)) { [int]$State.ExecFlags[$Script:NSIS_EXEC_FLAG_ERROR] } else { 0 }
    $State.ExecFlags[$Script:NSIS_EXEC_FLAG_ERROR] = $Current + 1
  }
}

function Set-NSISFileSystemExecutionError {
  <#
  .SYNOPSIS
    Record missing target-filesystem evidence and apply the fresh-install failure path.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Path
    Target path whose existence was not supplied by the caller.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [AllowEmptyString()][Parameter(Mandatory)][string]$Path
  )

  if ($State.PSObject.Properties['UnknownFileSystemPredicates']) {
    $null = $State.UnknownFileSystemPredicates.Add($Path)
  }
  # Static manifest analysis uses an empty target as its baseline. Model the
  # operation's ordinary missing-file error while retaining the unresolved path
  # so an existing-install scenario can be replayed with explicit FileSystem.
  Set-NSISExecutionError -State $State
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
      if ($State.Metadata.RequestedExecutionLevel -eq 'requireAdministrator') { return 'HKLM' }
      if ($State.TargetScope -eq 'machine') { return 'HKLM' }
      if ($State.TargetScope -eq 'user') { return 'HKCU' }

      $InstallLocation = [string]$State.Metadata.DefaultInstallLocation
      if ($InstallLocation -match '^(?i:\$PROGRAMFILES(?:32|64)?|%ProgramFiles(?:\(x86\))?%)') { return 'HKLM' }
      if ($InstallLocation -match '^(?i:\$(?:LOCALAPPDATA|APPDATA)|%(?:LocalAppData|AppData)%)') { return 'HKCU' }

      # Preserve SHCTX when neither the caller nor the compiled path establishes
      # a hive. Later scope-specific projection can resolve it without emitting
      # a warning for otherwise ordinary dual-scope installers.
      return 'SHCTX'
    }
    default { return 'HKCU' }
  }
}

function Set-NSISUnknownCondition {
  <#
  .SYNOPSIS
    Mark subsequent simulated effects conditional after an unresolved target-state operation.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Reason
    Source-backed description of the unresolved operation.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][string]$Reason
  )

  $State.HasUnknownControlFlow = $true
  $null = $State.ConditionalReasons.Add($Reason)
  $State.Diagnostics.Add($Reason)
}

function Copy-NSISBranchValue {
  <#
  .SYNOPSIS
    Deep-copy mutable NSIS runtime state while retaining immutable parser data.
  .DESCRIPTION
    Branch execution must not share dictionaries, sets, lists, or record objects.
    Byte arrays and framework services are immutable in the simulator and are
    therefore shared to avoid copying decoded installer blocks for every path.
  .PARAMETER Value
    Value from an NSIS execution state.
  #>
  param ([AllowNull()][object]$Value)

  if ($null -eq $Value -or $Value -is [string] -or $Value.GetType().IsValueType -or
    $Value -is [Text.Encoding] -or $Value -is [byte[]]) { return $Value }

  if ($Value -is [Collections.Specialized.OrderedDictionary]) {
    $Copy = [ordered]@{}
    foreach ($Key in $Value.Keys) { $Copy[$Key] = Copy-NSISBranchValue -Value $Value[$Key] }
    return $Copy
  }
  if ($Value -is [Collections.IDictionary]) {
    $Copy = @{}
    foreach ($Key in $Value.Keys) { $Copy[$Key] = Copy-NSISBranchValue -Value $Value[$Key] }
    return $Copy
  }
  if ($Value -is [Array]) {
    $ElementType = $Value.GetType().GetElementType()
    $Copy = [Array]::CreateInstance($ElementType, $Value.Length)
    for ($Index = 0; $Index -lt $Value.Length; $Index++) { $Copy.SetValue((Copy-NSISBranchValue -Value $Value.GetValue($Index)), $Index) }
    Write-Output -InputObject $Copy -NoEnumerate
    return
  }

  $ValueType = $Value.GetType()
  if ($ValueType.IsGenericType -and $ValueType.GetGenericTypeDefinition() -eq [Collections.Generic.HashSet``1]) {
    $ElementType = $ValueType.GetGenericArguments()[0]
    if ($ElementType -eq [string]) {
      $Copy = [Collections.Generic.HashSet[string]]::new($Value.Comparer)
    } else {
      $Copy = [Activator]::CreateInstance($ValueType)
    }
    foreach ($Item in $Value) { $null = $Copy.Add((Copy-NSISBranchValue -Value $Item)) }
    Write-Output -InputObject $Copy -NoEnumerate
    return
  }
  if ($Value -is [Collections.IList]) {
    $Copy = [Activator]::CreateInstance($ValueType)
    foreach ($Item in $Value) { $null = $Copy.Add((Copy-NSISBranchValue -Value $Item)) }
    Write-Output -InputObject $Copy -NoEnumerate
    return
  }
  if ($Value -is [pscustomobject]) {
    $Copy = [ordered]@{}
    foreach ($Property in $Value.PSObject.Properties) { $Copy[$Property.Name] = Copy-NSISBranchValue -Value $Property.Value }
    return [pscustomobject]$Copy
  }

  return $Value
}

function Copy-NSISExecutionState {
  <#
  .SYNOPSIS
    Create one isolated execution state for an alternative control-flow path.
  .PARAMETER State
    Source execution state at the unresolved branch.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][pscustomobject]$State)

  $ImmutableProperties = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($Name in 'Path', 'Entries', 'StringsBlock', 'LanguageTables', 'VersionInfo', 'AnsiEncoding') { $null = $ImmutableProperties.Add($Name) }
  $Copy = [ordered]@{}
  foreach ($Property in $State.PSObject.Properties) {
    if ($ImmutableProperties.Contains($Property.Name)) {
      $Copy[$Property.Name] = $Property.Value
    } else {
      $Copy[$Property.Name] = Copy-NSISBranchValue -Value $Property.Value
    }
  }
  return [pscustomobject]$Copy
}

function Test-NSISBranchValueEqual {
  <#
  .SYNOPSIS
    Compare two bounded branch-state values structurally.
  .PARAMETER Left
    First value.
  .PARAMETER Right
    Second value.
  #>
  [OutputType([bool])]
  param ([AllowNull()][object]$Left, [AllowNull()][object]$Right)

  if ([object]::ReferenceEquals($Left, $Right)) { return $true }
  if ($null -eq $Left -or $null -eq $Right) { return $false }
  if ($Left -is [byte[]] -and $Right -is [byte[]]) {
    return [Collections.StructuralComparisons]::StructuralEqualityComparer.Equals($Left, $Right)
  }
  if ($Left -is [Collections.IDictionary] -and $Right -is [Collections.IDictionary]) {
    if ($Left.Count -ne $Right.Count) { return $false }
    foreach ($Key in $Left.Keys) {
      if (-not $Right.Contains($Key) -or -not (Test-NSISBranchValueEqual -Left $Left[$Key] -Right $Right[$Key])) { return $false }
    }
    return $true
  }
  if ($Left -is [Collections.IEnumerable] -and $Right -is [Collections.IEnumerable] -and
    $Left -isnot [string] -and $Right -isnot [string]) {
    $LeftItems = [Collections.Generic.List[object]]::new()
    foreach ($Item in $Left) { $LeftItems.Add($Item) }
    $RightItems = [Collections.Generic.List[object]]::new()
    foreach ($Item in $Right) { $RightItems.Add($Item) }
    if ($LeftItems.Count -ne $RightItems.Count) { return $false }
    for ($Index = 0; $Index -lt $LeftItems.Count; $Index++) {
      if (-not (Test-NSISBranchValueEqual -Left $LeftItems[$Index] -Right $RightItems[$Index])) { return $false }
    }
    return $true
  }
  if ($Left -is [pscustomobject] -and $Right -is [pscustomobject]) {
    $LeftProperties = @($Left.PSObject.Properties)
    $RightProperties = @($Right.PSObject.Properties)
    if ($LeftProperties.Count -ne $RightProperties.Count) { return $false }
    foreach ($Property in $LeftProperties) {
      $Other = $Right.PSObject.Properties[$Property.Name]
      if (-not $Other -or -not (Test-NSISBranchValueEqual -Left $Property.Value -Right $Other.Value)) { return $false }
    }
    return $true
  }
  return $Left -ceq $Right
}

function Get-NSISCommonBranchDictionary {
  <#
  .SYNOPSIS
    Retain dictionary entries whose values agree across every terminal path.
  .PARAMETER Dictionary
    One dictionary from each terminal state.
  #>
  [OutputType([hashtable])]
  param ([Parameter(Mandatory)][Collections.IDictionary[]]$Dictionary)

  $Result = @{}
  if ($Dictionary.Count -eq 0) { return $Result }
  foreach ($Key in $Dictionary[0].Keys) {
    $Values = [Collections.Generic.List[object]]::new()
    $Missing = $false
    foreach ($Item in $Dictionary) {
      if (-not $Item.Contains($Key)) { $Missing = $true; break }
      $Values.Add($Item[$Key])
    }
    if ($Missing) { continue }
    if (@($Values | Where-Object { $_ -isnot [Collections.IDictionary] }).Count -eq 0) {
      $Nested = Get-NSISCommonBranchDictionary -Dictionary ([Collections.IDictionary[]]$Values.ToArray())
      if ($Nested.Count -gt 0) { $Result[$Key] = $Nested }
    } elseif (@($Values | Where-Object { -not (Test-NSISBranchValueEqual -Left $Values[0] -Right $_) }).Count -eq 0) {
      $Result[$Key] = Copy-NSISBranchValue -Value $Values[0]
    }
  }
  return $Result
}

function Get-NSISBranchEffectFingerprint {
  <#
  .SYNOPSIS
    Create a stable identity for one effect without path-conditional metadata.
  .PARAMETER Effect
    Registry, INI, shortcut, or executed-payload evidence object.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][pscustomobject]$Effect)

  $Projection = [ordered]@{}
  foreach ($Property in $Effect.PSObject.Properties) {
    if ($Property.Name -in @('Conditional', 'Provenance')) { continue }
    $Projection[$Property.Name] = $Property.Value
  }
  return ConvertTo-Json $Projection -Depth 8 -Compress
}

function Merge-NSISBranchEffects {
  <#
  .SYNOPSIS
    Union path effects and promote an effect only when every path performs it.
  .PARAMETER State
    Terminal execution states.
  .PARAMETER Property
    Effect-list property to merge.
  .PARAMETER InitialConditionalReasons
    Reasons that already made execution conditional before the first new fork.
  #>
  [OutputType([object[]])]
  param (
    [Parameter(Mandatory)][pscustomobject[]]$State,
    [Parameter(Mandatory)][string]$Property,
    [string[]]$InitialConditionalReasons = @()
  )

  $Effects = [ordered]@{}
  for ($PathIndex = 0; $PathIndex -lt $State.Count; $PathIndex++) {
    $SeenOnPath = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($Effect in $State[$PathIndex].$Property) {
      $Fingerprint = Get-NSISBranchEffectFingerprint -Effect $Effect
      if (-not $SeenOnPath.Add($Fingerprint)) { continue }
      if (-not $Effects.Contains($Fingerprint)) {
        $Effects[$Fingerprint] = [pscustomobject]@{
          Effect     = Copy-NSISBranchValue -Value $Effect
          Paths      = [Collections.Generic.HashSet[int]]::new()
          Provenance = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        }
      }
      $Record = $Effects[$Fingerprint]
      $null = $Record.Paths.Add($PathIndex)
      foreach ($Reason in @($Effect.Provenance)) { $null = $Record.Provenance.Add([string]$Reason) }
    }
  }

  $Result = [Collections.Generic.List[object]]::new()
  foreach ($Record in $Effects.Values) {
    $IsCommon = $Record.Paths.Count -eq $State.Count
    $Conditional = -not $IsCommon -or $InitialConditionalReasons.Count -gt 0
    $Provenance = if ($IsCommon) { [string[]]$InitialConditionalReasons } else { [string[]]$Record.Provenance }
    if ($Record.Effect.PSObject.Properties['Conditional']) { $Record.Effect.Conditional = $Conditional }
    if ($Record.Effect.PSObject.Properties['Provenance']) { $Record.Effect.Provenance = $Provenance }
    $Result.Add($Record.Effect)
  }
  return $Result.ToArray()
}

function Merge-NSISExecutionStates {
  <#
  .SYNOPSIS
    Reconcile terminal NSIS paths into one conservative execution state.
  .DESCRIPTION
    Values shared by every path remain deterministic. Divergent variables,
    flags, registry state, INI state, and section selections become unresolved.
    Effects are retained with branch provenance so metadata projection can
    distinguish guaranteed writes from path-specific alternatives.
  .PARAMETER Target
    Original execution state to update in place.
  .PARAMETER State
    Terminal branch states.
  .PARAMETER InitialConditionalReasons
    Conditions already unresolved before the first fork.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)][pscustomobject]$Target,
    [Parameter(Mandatory)][ValidateCount(1, 16)][pscustomobject[]]$State,
    [string[]]$InitialConditionalReasons = @()
  )

  $HasDivergence = $false
  $Target.Variables = Get-NSISCommonBranchDictionary -Dictionary ([Collections.IDictionary[]]@($State.Variables))
  $Target.UnknownVariables.Clear()
  foreach ($BranchState in $State) { foreach ($Index in $BranchState.UnknownVariables) { $null = $Target.UnknownVariables.Add($Index) } }
  $VariableKeys = [Collections.Generic.HashSet[int]]::new()
  foreach ($BranchState in $State) { foreach ($Index in $BranchState.Variables.Keys) { $null = $VariableKeys.Add([int]$Index) } }
  foreach ($Index in $VariableKeys) {
    if (-not $Target.Variables.ContainsKey($Index)) { $null = $Target.UnknownVariables.Add($Index); $HasDivergence = $true }
  }

  $Target.Registry = Get-NSISCommonBranchDictionary -Dictionary ([Collections.IDictionary[]]@($State.Registry))
  $Target.IniFiles = Get-NSISCommonBranchDictionary -Dictionary ([Collections.IDictionary[]]@($State.IniFiles))
  $Target.FileSystem = Get-NSISCommonBranchDictionary -Dictionary ([Collections.IDictionary[]]@($State.FileSystem))
  foreach ($Property in 'Registry', 'IniFiles', 'FileSystem') {
    if (-not (Test-NSISBranchValueEqual -Left $State[0].$Property -Right $Target.$Property)) { $HasDivergence = $true }
  }

  $Target.ExecFlags = Get-NSISCommonBranchDictionary -Dictionary ([Collections.IDictionary[]]@($State.ExecFlags))
  $Target.UnknownExecFlags.Clear()
  foreach ($BranchState in $State) { foreach ($Flag in $BranchState.UnknownExecFlags) { $null = $Target.UnknownExecFlags.Add($Flag) } }
  $FlagKeys = [Collections.Generic.HashSet[int]]::new()
  foreach ($BranchState in $State) { foreach ($Flag in $BranchState.ExecFlags.Keys) { $null = $FlagKeys.Add([int]$Flag) } }
  foreach ($Flag in $FlagKeys) {
    if (-not $Target.ExecFlags.ContainsKey($Flag)) { $null = $Target.UnknownExecFlags.Add($Flag); $HasDivergence = $true }
  }

  foreach ($SetProperty in 'Directories', 'Files') {
    $Target.$SetProperty.Clear()
    foreach ($Value in $State[0].$SetProperty) {
      if (@($State | Where-Object { -not $_.$SetProperty.Contains($Value) }).Count -eq 0) { $null = $Target.$SetProperty.Add($Value) }
    }
  }
  $ConditionalFiles = [ordered]@{}
  foreach ($BranchState in $State) {
    foreach ($Evidence in $BranchState.ConditionalExtractedFiles) { $ConditionalFiles[[string]$Evidence.Path] = $Evidence }
    foreach ($Path in $BranchState.Files) {
      if ($Target.Files.Contains($Path) -or $ConditionalFiles.Contains($Path)) { continue }
      $ConditionalFiles[$Path] = [pscustomobject][ordered]@{
        Path        = [string]$Path
        Conditional = $true
        Provenance  = [string[]]@($BranchState.ConditionalReasons)
      }
    }
  }
  $Target.ConditionalExtractedFiles = [Collections.Generic.List[object]]::new()
  foreach ($Evidence in $ConditionalFiles.Values) { $Target.ConditionalExtractedFiles.Add($Evidence) }

  foreach ($SetProperty in 'UnknownFileSystemPredicates', 'UnknownProcessPredicates', 'UnknownEnvironment', 'UnsupportedOpcodes', 'BranchPredicates') {
    $Target.$SetProperty.Clear()
    foreach ($BranchState in $State) { foreach ($Value in $BranchState.$SetProperty) { $null = $Target.$SetProperty.Add($Value) } }
  }
  foreach ($Path in @($State.FileSystem.Keys | Select-Object -Unique)) {
    if (-not $Target.FileSystem.ContainsKey($Path)) { $null = $Target.UnknownFileSystemPredicates.Add([string]$Path) }
  }
  $Target.ExploredBranchCount = $Target.BranchPredicates.Count
  $Target.TruncatedBranchCount = [int](($State.TruncatedBranchCount | Measure-Object -Maximum).Maximum)

  $Target.RegistryWrites = [Collections.Generic.List[object]]::new()
  foreach ($Effect in @(Merge-NSISBranchEffects -State $State -Property RegistryWrites -InitialConditionalReasons $InitialConditionalReasons)) { $Target.RegistryWrites.Add($Effect) }
  $Target.IniWrites = [Collections.Generic.List[object]]::new()
  foreach ($Effect in @(Merge-NSISBranchEffects -State $State -Property IniWrites -InitialConditionalReasons $InitialConditionalReasons)) { $Target.IniWrites.Add($Effect) }
  $Target.CreatedShortcuts = [Collections.Generic.List[object]]::new()
  foreach ($Effect in @(Merge-NSISBranchEffects -State $State -Property CreatedShortcuts -InitialConditionalReasons $InitialConditionalReasons)) { $Target.CreatedShortcuts.Add($Effect) }
  $Target.ExecutedPayloads = [Collections.Generic.List[object]]::new()
  foreach ($Effect in @(Merge-NSISBranchEffects -State $State -Property ExecutedPayloads -InitialConditionalReasons $InitialConditionalReasons)) { $Target.ExecutedPayloads.Add($Effect) }

  # Stack, open handles, and ambient scalar state are usable after a join only
  # when every terminal path agrees exactly.
  foreach ($Property in 'Stack', 'SystemVariableStack', 'FileHandles', 'FindHandles', 'LastExecFlags', 'InstallTypeNames') {
    $FirstValue = $State[0].$Property
    $Agrees = @($State | Where-Object { -not (Test-NSISBranchValueEqual -Left $FirstValue -Right $_.$Property) }).Count -eq 0
    if ($Agrees) { $Target.$Property = Copy-NSISBranchValue -Value $FirstValue } else { $HasDivergence = $true }
  }
  foreach ($Property in 'NextFileHandle', 'NextTempFile', 'NextFindHandle') { $Target.$Property = [int](($State.$Property | Measure-Object -Maximum).Maximum) }
  foreach ($Property in 'CurrentInstallType', 'StatusUpdateFlag', 'ShellVarContext') {
    $FirstValue = $State[0].$Property
    if (@($State | Where-Object { -not (Test-NSISBranchValueEqual -Left $FirstValue -Right $_.$Property) }).Count -eq 0) {
      $Target.$Property = Copy-NSISBranchValue -Value $FirstValue
    } else {
      $Target.$Property = $null
      $HasDivergence = $true
    }
  }

  for ($Index = 0; $Index -lt $Target.Sections.Count; $Index++) {
    $Flags = @($State | ForEach-Object { $_.Sections[$Index].Flags } | Select-Object -Unique)
    if ($Flags.Count -gt 1) {
      $MergedFlags = 0
      foreach ($Flag in $Flags) { $MergedFlags = $MergedFlags -bor [int]$Flag }
      $Target.Sections[$Index].Flags = $MergedFlags
      $HasDivergence = $true
    } else {
      $Target.Sections[$Index].Flags = $Flags[0]
    }
  }

  $Target.Diagnostics.Clear()
  foreach ($BranchState in $State) { foreach ($Warning in $BranchState.Diagnostics) { if (-not $Target.Diagnostics.Contains($Warning)) { $Target.Diagnostics.Add($Warning) } } }
  $Target.InformationalDiagnosticMessages.Clear()
  foreach ($BranchState in $State) { foreach ($Message in $BranchState.InformationalDiagnosticMessages) { if (-not $Target.InformationalDiagnosticMessages.Contains($Message)) { $Target.InformationalDiagnosticMessages.Add($Message) } } }
  $Target.ConditionalReasons.Clear()
  foreach ($Reason in $InitialConditionalReasons) { $null = $Target.ConditionalReasons.Add($Reason) }
  $Target.HasUnknownControlFlow = $Target.ConditionalReasons.Count -gt 0

  # Preserve model fields that agree across all paths and leave divergent
  # package evidence unresolved for the final structured projection.
  foreach ($Key in @($Target.Metadata.Keys)) {
    if ($Key -in @('UnresolvedFields', 'Diagnostics', 'RegistryWrites', 'IniWrites', 'CreatedShortcuts', 'ExecutedPayloads')) { continue }
    $Values = [Collections.Generic.List[object]]::new()
    foreach ($BranchState in $State) { $Values.Add($BranchState.Metadata[$Key]) }
    if (@($Values | Where-Object { -not (Test-NSISBranchValueEqual -Left $Values[0] -Right $_) }).Count -eq 0) {
      $Target.Metadata[$Key] = Copy-NSISBranchValue -Value $Values[0]
    } elseif ($Values[0] -is [bool]) {
      $Target.Metadata[$Key] = $false
      $HasDivergence = $true
    } elseif ($Values[0] -is [Collections.IDictionary]) {
      $Target.Metadata[$Key] = Get-NSISCommonBranchDictionary -Dictionary ([Collections.IDictionary[]]$Values)
      $HasDivergence = $true
    } elseif ($Values[0] -is [Array]) {
      $Target.Metadata[$Key] = @()
      $HasDivergence = $true
    } else {
      $Target.Metadata[$Key] = $null
      $HasDivergence = $true
    }
  }
  $UnresolvedFields = @($State.Metadata.UnresolvedFields | Where-Object { $_ } | Select-Object -Unique)
  if ($HasDivergence) { $UnresolvedFields += 'ControlFlowBranches' }
  $Target.Metadata.UnresolvedFields = [string[]]@($UnresolvedFields | Select-Object -Unique)
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
    Conditional    = [bool]$State.HasUnknownControlFlow
    Provenance     = [string[]]@($State.ConditionalReasons)
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
  if ($Write.Conditional) {
    $State.Metadata.UnresolvedFields = [string[]]@($State.Metadata.UnresolvedFields + @('RegistryWrites', 'AppsAndFeaturesEntries') | Select-Object -Unique)
  }
  # A branch state is isolated from all sibling paths. Apply the write inside
  # that state so later ReadReg commands observe correct path-local behavior;
  # Merge-NSISExecutionStates decides whether the effect is common or conditional.
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
      Kind        = $Kind
      Command     = $Command
      Parameters  = $Parameters
      Conditional = [bool]$State.HasUnknownControlFlow
      Provenance  = [string[]]@($State.ConditionalReasons)
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

function Get-NSISRegistryEnumerationValue {
  <#
  .SYNOPSIS
    Enumerate a value name or immediate child key from the virtual NSIS registry.
  .DESCRIPTION
    The emulator never reads the host registry. This function exposes only
    values and keys created by earlier simulated registry commands, preserving
    their in-memory enumeration order for deterministic follow-on branches.
  .PARAMETER State
    Mutable NSIS simulation state containing the virtual registry.
  .PARAMETER Root
    Resolved logical registry hive.
  .PARAMETER Key
    Registry key whose values or child keys should be enumerated.
  .PARAMETER Index
    Zero-based enumeration index from the compiled command.
  .PARAMETER EnumerateKeys
    Enumerate immediate child key names instead of value names.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$Key,
    [Parameter(Mandatory)][int]$Index,
    [Parameter(Mandatory)][bool]$EnumerateKeys
  )

  if ($Index -lt 0 -or -not $State.Registry.ContainsKey($Root)) { return '' }
  if (-not $EnumerateKeys) {
    if (-not $State.Registry[$Root].ContainsKey($Key)) { return '' }
    $Names = [string[]]@($State.Registry[$Root][$Key].Keys)
    return $(if ($Index -lt $Names.Count) { $Names[$Index] } else { '' })
  }

  $Prefix = $Key.TrimEnd('\') + '\'
  $Seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $Names = [System.Collections.Generic.List[string]]::new()
  foreach ($CandidateKey in @($State.Registry[$Root].Keys)) {
    if (-not ([string]$CandidateKey).StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
    $Remainder = ([string]$CandidateKey).Substring($Prefix.Length)
    $Separator = $Remainder.IndexOf('\')
    $Name = if ($Separator -ge 0) { $Remainder.Substring(0, $Separator) } else { $Remainder }
    if (-not [string]::IsNullOrEmpty($Name) -and $Seen.Add($Name)) { $Names.Add($Name) }
  }
  return $(if ($Index -lt $Names.Count) { $Names[$Index] } else { '' })
}

function Add-NSISIniWrite {
  <#
  .SYNOPSIS
    Apply one source-accurate EW_WRITEINI command to the virtual INI store.
  .DESCRIPTION
    Offsets zero through four encode section, key, value, file, and the
    write-value flag. Null section/key/value combinations represent FlushINI,
    DeleteINISection, and DeleteINIStr exactly as the NSIS runtime does.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Entry
    Canonical EW_WRITEINI command record.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][pscustomobject]$Entry
  )

  $Section = if ($Entry.Raw[1] -ne 0) { Get-NSISString -State $State -RelativeOffset $Entry.Values[1] } else { $null }
  $Key = if ($Entry.Raw[2] -ne 0) { Get-NSISString -State $State -RelativeOffset $Entry.Values[2] } else { $null }
  $Value = if ($Entry.Raw[5] -ne 0) { Get-NSISString -State $State -RelativeOffset $Entry.Values[3] } else { $null }
  $File = Get-NSISString -State $State -RelativeOffset $Entry.Values[4]
  $Action = if ($null -eq $Section) { 'Flush' } elseif ($null -eq $Key) { 'DeleteSection' } elseif ($null -eq $Value) { 'DeleteValue' } else { 'Write' }
  $Write = [pscustomobject][ordered]@{
    Action      = $Action
    File        = $File
    Section     = $Section
    Key         = $Key
    Value       = $Value
    Conditional = [bool]$State.HasUnknownControlFlow
    Provenance  = [string[]]@($State.ConditionalReasons)
    Opcode      = $Entry.Opcode
    RawOpcode   = $Entry.RawOpcode
  }
  $State.IniWrites.Add($Write)
  if ($Write.Conditional) {
    $State.Metadata.UnresolvedFields = [string[]]@($State.Metadata.UnresolvedFields + 'IniWrites' | Select-Object -Unique)
  }
  # Keep the path-local INI store accurate for a later ReadINIStr. The final
  # merge retains only values shared by every terminal path.
  if ($Action -eq 'Flush') { return }

  if (-not $State.IniFiles.ContainsKey($File)) { $State.IniFiles[$File] = @{} }
  if ($Action -eq 'DeleteSection') {
    $null = $State.IniFiles[$File].Remove($Section)
    return
  }
  if (-not $State.IniFiles[$File].ContainsKey($Section)) { $State.IniFiles[$File][$Section] = @{} }
  if ($Action -eq 'DeleteValue') {
    $null = $State.IniFiles[$File][$Section].Remove($Key)
  } else {
    $State.IniFiles[$File][$Section][$Key] = $Value
  }
}

function Get-NSISIniValue {
  <#
  .SYNOPSIS
    Read one value previously written to the virtual NSIS INI store.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER File
    Resolved INI file path.
  .PARAMETER Section
    INI section name.
  .PARAMETER Key
    INI key name.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [AllowEmptyString()][Parameter(Mandatory)][string]$File,
    [AllowEmptyString()][Parameter(Mandatory)][string]$Section,
    [AllowEmptyString()][Parameter(Mandatory)][string]$Key
  )

  if ($State.IniFiles.ContainsKey($File) -and $State.IniFiles[$File].ContainsKey($Section) -and $State.IniFiles[$File][$Section].ContainsKey($Key)) {
    return [string]$State.IniFiles[$File][$Section][$Key]
  }
  return ''
}

function Add-NSISShortcutEvidence {
  <#
  .SYNOPSIS
    Decode one EW_CREATESHORTCUT record into static shortcut evidence.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Entry
    Canonical shortcut command containing six source-defined operands.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][pscustomobject]$Entry
  )

  # NSIS packs icon index, show command, no-working-directory, and hotkey into
  # offsets[4]. Keep that packed source evidence alongside decoded fields.
  $Flags = [uint32]$Entry.Raw[5]
  $State.CreatedShortcuts.Add([pscustomobject][ordered]@{
      Path               = Get-NSISString -State $State -RelativeOffset $Entry.Values[1]
      Target             = Get-NSISString -State $State -RelativeOffset $Entry.Values[2]
      Arguments          = Get-NSISString -State $State -RelativeOffset $Entry.Values[3]
      IconPath           = Get-NSISString -State $State -RelativeOffset $Entry.Values[4]
      IconIndex          = [int]($Flags -band 0x00000FFF)
      ShowCommand        = [int](($Flags -band 0x00007000) -shr 12)
      HotKey             = [int](($Flags -band 0xFFFF0000) -shr 16)
      NoWorkingDirectory = [bool](($Flags -band 0x00008000) -ne 0)
      WorkingDirectory   = $(if (($Flags -band 0x00008000) -eq 0) { Get-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_OUTDIR } else { $null })
      Comment            = Get-NSISString -State $State -RelativeOffset $Entry.Values[6]
      Conditional        = [bool]$State.HasUnknownControlFlow
      Provenance         = [string[]]@($State.ConditionalReasons)
      PackedFlags        = $Flags
      Opcode             = $Entry.Opcode
      RawOpcode          = $Entry.RawOpcode
    })
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
        Index        = $SectionIndex
        NameOffset   = [System.BitConverter]::ToInt32($SectionBlock, $Offset + $Script:NSIS_SECTION_OFFSET_NAME)
        InstallTypes = [System.BitConverter]::ToInt32($SectionBlock, $Offset + $Script:NSIS_SECTION_OFFSET_INSTALL_TYPES)
        Flags        = [System.BitConverter]::ToInt32($SectionBlock, $Offset + $Script:NSIS_SECTION_OFFSET_FLAGS)
        CodeOffset   = [System.BitConverter]::ToInt32($SectionBlock, $Offset + $Script:NSIS_SECTION_OFFSET_CODE)
        CodeSize     = [System.BitConverter]::ToInt32($SectionBlock, $Offset + $Script:NSIS_SECTION_OFFSET_CODE_SIZE)
        SizeKb       = [System.BitConverter]::ToInt32($SectionBlock, $Offset + $Script:NSIS_SECTION_OFFSET_SIZE_KB)
      })
  }

  return $Sections.ToArray()
}

function Test-NSISHasComponentPage {
  <#
  .SYNOPSIS
    Determine whether the compiled NSIS stub contains a components page.
  .DESCRIPTION
    The runtime guards section-selection checks with NSIS_CONFIG_COMPONENTPAGE.
    A serialized page starts with dlg_id, and the stock components dialog uses
    resource ID 104 even when a custom UI replaces the dialog resource.
  .PARAMETER HeaderBytes
    Decompressed logical NSIS header.
  .PARAMETER BlockHeaders
    Validated logical block descriptors.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][byte[]]$HeaderBytes,
    [Parameter(Mandatory)][pscustomobject[]]$BlockHeaders
  )

  if ($BlockHeaders.Count -eq 0 -or $BlockHeaders[0].Count -le 0) { return $false }
  $PageBlock = Get-NSISBlockBytes -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Index 0
  $RecordSize = [int]($PageBlock.Length / $BlockHeaders[0].Count)
  if ($RecordSize -lt 8 -or $PageBlock.Length % $BlockHeaders[0].Count -ne 0) { return $false }
  for ($Index = 0; $Index -lt $BlockHeaders[0].Count; $Index++) {
    if ([BitConverter]::ToInt32($PageBlock, $Index * $RecordSize) -eq 104) { return $true }
  }
  return $false
}

function Initialize-NSISState {
  <#
  .SYNOPSIS
    Build the mutable execution state used for deterministic NSIS metadata parsing
  .PARAMETER HeaderData
    The decompressed NSIS header data. Used when FormatContext is not supplied.
  .PARAMETER FormatContext
    A catalog-selected context shared by the facade, simulator, and extractor.
  .PARAMETER Architecture
    The target Windows architecture used to resolve source-backed runtime architecture checks
  .PARAMETER Scope
    The target installation scope used to resolve compiled MultiUser scope setters
  .PARAMETER FileSystem
    Explicit virtual target filesystem facts keyed by Windows path.
  .PARAMETER FileSystemComplete
    Treat paths absent from FileSystem as absent rather than unknown.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ParameterSetName = 'HeaderData', HelpMessage = 'The decompressed NSIS header data')]
    [pscustomobject]$HeaderData,

    [Parameter(Mandatory, ParameterSetName = 'FormatContext', HelpMessage = 'The catalog-selected NSIS format context')]
    [pscustomobject]$FormatContext,

    [Parameter(HelpMessage = 'The target Windows architecture used to resolve runtime architecture checks')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [Parameter(HelpMessage = 'The target installation scope used to resolve runtime scope checks')]
    [ValidateSet('user', 'machine')]
    [string]$Scope,

    [ValidateRange(1, 65535)][int]$AnsiCodePage,

    [hashtable]$FileSystem = @{},

    [switch]$FileSystemComplete
  )

  # Format parsing owns profile selection and opcode normalization. Simulation
  # receives one immutable context instead of repeating block and entry reads.
  if ($PSCmdlet.ParameterSetName -eq 'HeaderData') { $FormatContext = Get-NSISFormatContext -HeaderData $HeaderData }
  $HeaderData = $FormatContext.HeaderData
  $FormatInfo = ConvertTo-NSISFormatInfo -Context $FormatContext
  if (-not $FormatInfo.IsSupported) {
    throw "The NSIS command layout '$($FormatInfo.CatalogProfileId)' is structurally unsupported: $([string]::Join(' ', $FormatInfo.Diagnostics))"
  }
  $HeaderBytes = $FormatContext.HeaderBytes
  $BlockHeaders = $FormatContext.BlockHeaders
  $Layout = $FormatContext.HeaderLayout
  $StringsBlock = $FormatContext.StringsBlock
  $LanguageTables = @(Get-NSISLanguageTable -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders -Layout $Layout)
  $LanguageTable = @($LanguageTables.Where({ $_.LanguageId -eq $Script:NSIS_DEFAULT_LANGUAGE }, 'First'))[0]
  if (-not $LanguageTable) { $LanguageTable = $LanguageTables | Select-Object -First 1 }
  $Entries = $FormatContext.Entries
  $VersionInfo = $FormatContext.VersionInfo
  # Account-sensitive NSIS plug-ins observe the installer's process token. Read
  # the PE manifest once so requireAdministrator installers can take the same
  # deterministic elevated branch without consulting the parser host's token.
  $RequestedExecutionLevel = try { Get-PERequestedExecutionLevel -Path $HeaderData.Path } catch { $null }
  $VersionInfo | Add-Member -NotePropertyName FirstHeaderFlags -NotePropertyValue $HeaderData.FirstHeaderFlags -Force
  $VersionInfo | Add-Member -NotePropertyName HasLongDataBlockOffsets -NotePropertyValue $HeaderData.HasLongDataBlockOffsets -Force
  $VersionInfo | Add-Member -NotePropertyName HasLargeFileSource -NotePropertyValue $HeaderData.HasLargeFileSource -Force
  $VersionInfo | Add-Member -NotePropertyName SupportsExternalFiles -NotePropertyValue $HeaderData.SupportsExternalFiles -Force
  $VersionInfo | Add-Member -NotePropertyName HasExternalFile -NotePropertyValue $HeaderData.HasExternalFile -Force
  $VersionInfo | Add-Member -NotePropertyName IsStubInstaller -NotePropertyValue $HeaderData.IsStubInstaller -Force
  $VersionInfo | Add-Member -NotePropertyName ExternalFileCount -NotePropertyValue $HeaderData.ExternalFileCount -Force
  $VersionInfo | Add-Member -NotePropertyName ExternalSegmentSize -NotePropertyValue $HeaderData.ExternalSegmentSize -Force
  $VersionInfo | Add-Member -NotePropertyName ArchiveCrcStatus -NotePropertyValue $HeaderData.ArchiveCrcInfo.Status -Force
  $VersionInfo | Add-Member -NotePropertyName ArchiveCrcVerified -NotePropertyValue $HeaderData.ArchiveCrcInfo.IsVerified -Force
  $HasComponentPage = Test-NSISHasComponentPage -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders
  $VersionInfo | Add-Member -NotePropertyName HasComponentPage -NotePropertyValue $HasComponentPage -Force
  $State = [pscustomobject]@{
    Path                            = $HeaderData.Path
    Entries                         = $Entries
    Sections                        = Get-NSISSections -HeaderBytes $HeaderBytes -BlockHeaders $BlockHeaders
    HasComponentPage                = $HasComponentPage
    StringsBlock                    = $StringsBlock
    LanguageTable                   = $LanguageTable
    LanguageTables                  = $LanguageTables
    VersionInfo                     = $VersionInfo
    AnsiEncoding                    = Get-NSISAnsiEncoding -LanguageId $(if ($LanguageTable) { $LanguageTable.LanguageId } else { $Script:NSIS_DEFAULT_LANGUAGE }) -CodePage $AnsiCodePage
    Variables                       = @{}
    Registry                        = @{}
    RegistryWrites                  = [System.Collections.Generic.List[object]]::new()
    IniFiles                        = @{}
    IniWrites                       = [System.Collections.Generic.List[object]]::new()
    CreatedShortcuts                = [System.Collections.Generic.List[object]]::new()
    ExecutedPayloads                = [System.Collections.Generic.List[object]]::new()
    ConditionalExtractedFiles       = [System.Collections.Generic.List[object]]::new()
    Diagnostics                     = [System.Collections.Generic.List[object]]::new()
    InformationalDiagnosticMessages = [System.Collections.Generic.List[string]]::new()
    Stack                           = [System.Collections.Generic.List[string]]::new()
    SystemVariableStack             = [System.Collections.Generic.List[object]]::new()
    Directories                     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Files                           = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    FileSystem                      = @{}
    FileSystemComplete              = [bool]$FileSystemComplete
    UnknownFileSystemPredicates     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    UnknownProcessPredicates        = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    FileHandles                     = @{}
    NextFileHandle                  = 1
    NextTempFile                    = 1
    FindHandles                     = @{}
    NextFindHandle                  = 1
    ExecFlags                       = @{}
    LastExecFlags                   = @{}
    UnknownExecFlags                = [System.Collections.Generic.HashSet[int]]::new()
    UnknownVariables                = [System.Collections.Generic.HashSet[int]]::new()
    CurrentInstallType              = 0
    InstallTypeNames                = @{}
    StatusUpdateFlag                = 0
    ShellVarContext                 = $null
    HasUnknownControlFlow           = $false
    ConditionalReasons              = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    UnsupportedOpcodes              = [System.Collections.Generic.HashSet[int]]::new()
    UnknownEnvironment              = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    BranchPredicates                = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    ExploredBranchCount             = 0
    TruncatedBranchCount            = 0
    TargetArchitecture              = $Architecture
    TargetScope                     = $Scope
    RegistryPluginScopeVariables    = [int[]]@()
    Environment                     = @{}
    CommandLine                     = ''
    Metadata                        = [ordered]@{
      Path                               = $HeaderData.Path
      InstallerType                      = 'nullsoft'
      TargetArchitecture                 = $Architecture
      HasArchitectureRuntimeCheck        = $false
      TargetScope                        = $Scope
      HasScopeRuntimeCheck               = $false
      SupportedScopes                    = [string[]]@()
      UserScopeSwitch                    = $null
      MachineScopeSwitch                 = $null
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
      Diagnostics                        = @(Merge-InstallerDiagnostics -Diagnostic @(@(ConvertTo-InstallerDiagnostic -InputObject @([object[]]@()) -Source 'NSISSimulation' -Kind Incomplete -Areas Metadata), @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]@()) -Source 'NSISSimulation' -Kind Information -Areas Metadata)))
      UnresolvedFields                   = [string[]]@()
      Family                             = 'NSIS/Nullsoft'
      UninstallString                    = $null
      QuietUninstallString               = $null
      DisplayIcon                        = $null
      SystemComponent                    = $null
      RegistryValues                     = @{}
      RegistryWrites                     = @()
      IniWrites                          = @()
      CreatedShortcuts                   = @()
      AppsAndFeaturesEntries             = @()
      AppsAndFeaturesEntryEvidence       = @()
      HasLocalizedAppsAndFeaturesEntries = $false

      ExtractedFiles                     = @()
      ConditionalExtractedFiles          = @()
      ExecutedPayloads                   = @()
      ParserVersionInfo                  = $null
      EditionId                          = $VersionInfo.EditionId
      Edition                            = $VersionInfo.Edition
      CharacterMode                      = $VersionInfo.CharacterMode
    }
  }

  $State.ExecFlags[$Script:NSIS_EXEC_FLAG_ERROR] = 0
  foreach ($FilePath in $FileSystem.Keys) {
    $Value = $FileSystem[$FilePath]
    $Arguments = @{ State = $State; Path = [string]$FilePath }
    if ($Value -is [bool]) {
      $Arguments.Exists = [bool]$Value
    } elseif ($Value -is [byte[]] -or $Value -is [string]) {
      $Arguments.Content = $Value
    } elseif ($null -ne $Value) {
      foreach ($Property in 'Exists', 'IsDirectory', 'Content', 'FileVersion', 'ProductVersion', 'LastWriteTimeHigh', 'LastWriteTimeLow') {
        if ($Value -is [System.Collections.IDictionary] -and $Value.Contains($Property)) {
          $Arguments[$Property] = $Value[$Property]
        } elseif ($Value.PSObject.Properties[$Property]) {
          $Arguments[$Property] = $Value.$Property
        }
      }
    }
    $null = Set-NSISVirtualFileRecord @Arguments
  }

  foreach ($Diagnostic in @($FormatInfo.Diagnostics)) { $State.Diagnostics.Add($Diagnostic) }

  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_EXEDIR -Value '$EXEDIR'
  $VariableLayout = Get-NSISVariableLayout -State $State
  if ($null -ne $VariableLayout.ExePath) { Set-NSISVariableValue -State $State -Index $VariableLayout.ExePath -Value '$EXEPATH' }
  if ($null -ne $VariableLayout.ExeFile) { Set-NSISVariableValue -State $State -Index $VariableLayout.ExeFile -Value (Split-Path -Path $HeaderData.Path -Leaf) }
  $LanguageId = if ($LanguageTable) { $LanguageTable.LanguageId } else { $Script:NSIS_DEFAULT_LANGUAGE }
  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_LANGUAGE -Value ([string]$LanguageId)
  Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_TEMP -Value '$TEMP'

  if ($HeaderData.IsNsisBi) {
    $State.InformationalDiagnosticMessages.Add('The installer uses the NSISBI large-installer format; metadata was parsed from its expanded first-header and command layouts.')
  }
  if ($HeaderData.HasExternalFile) {
    $State.Diagnostics.Add('The NSISBI installer references an external payload file; embedded script metadata is available, but payload evidence may be incomplete without the sidecar file.')
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

  # Resolve to stable target tokens. Neither the parser process environment nor
  # SHGetKnownFolderPath describes the endpoint where the installer will run.
  $WindowsDirectory = $Script:NSIS_WINDOWS_DIRECTORY
  $SystemDirectory = $Script:NSIS_SYSTEM_DIRECTORY
  $SystemX86Directory = '%SystemRoot%\SysWOW64'
  $ProgramFiles64 = '%ProgramFiles%'
  $ProgramFilesX86 = '%ProgramFiles(x86)%'
  $CommonProgramFiles64 = '%ProgramFiles%\Common Files'
  $CommonProgramFilesX86 = '%ProgramFiles(x86)%\Common Files'
  $UserStartMenu = '%AppData%\Microsoft\Windows\Start Menu'
  $CommonStartMenu = '%ProgramData%\Microsoft\Windows\Start Menu'

  switch ($CanonicalFolderId) {
    # Application-data and machine-data roots.
    '{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}' { return '%LocalAppData%' } # FOLDERID_LocalAppData
    '{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}' { return '%AppData%' } # FOLDERID_RoamingAppData
    '{A520A1A4-1780-4FF6-BD18-167343C5AF16}' { return '%UserProfile%\AppData\LocalLow' } # FOLDERID_LocalAppDataLow
    '{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}' { return '%ProgramData%' } # FOLDERID_ProgramData
    '{5E6C858F-0E22-4760-9AFE-EA3317B67173}' { return '%UserProfile%' } # FOLDERID_Profile

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
    $Script:NSIS_FOLDER_ID_USER_PROGRAM_FILES { return '%LocalAppData%\Programs' }
    '{BCBD3057-CA5C-4622-B42D-BC56DB0AE516}' { return '%LocalAppData%\Programs\Common' } # FOLDERID_UserProgramFilesCommon

    # Per-user Start Menu folders.
    '{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}' { return [string]$UserStartMenu } # FOLDERID_StartMenu
    '{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}' { return "$UserStartMenu\Programs" } # FOLDERID_Programs
    '{B97D20BB-F46A-4C97-BA10-5E3608430854}' { return "$UserStartMenu\Programs\Startup" } # FOLDERID_Startup
    '{724EF170-A42D-4FEF-9F26-B60E846FBA4F}' { return "$UserStartMenu\Programs\Administrative Tools" } # FOLDERID_AdminTools

    # All-users Start Menu folders.
    '{A4115719-D62E-491D-AA7C-E74B8BE3B067}' { return [string]$CommonStartMenu } # FOLDERID_CommonStartMenu
    '{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}' { return "$CommonStartMenu\Programs" } # FOLDERID_CommonPrograms
    '{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}' { return "$CommonStartMenu\Programs\Startup" } # FOLDERID_CommonStartup
    '{D0384E7D-BAC3-4797-8F14-CBA229B392B5}' { return "$CommonStartMenu\Programs\Administrative Tools" } # FOLDERID_CommonAdminTools
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

function Resolve-NSISRegistryPluginPath {
  <#
  .SYNOPSIS
    Split an Instructor Registry plug-in path into a canonical hive and key.
  .DESCRIPTION
    The plug-in accepts long and abbreviated Windows hive names followed by a
    backslash and key. Invalid or dynamically unresolved roots return null so
    static simulation never invents a target hive.
  .PARAMETER Path
    Full registry path popped from the NSIS plug-in stack.
  #>
  [OutputType([pscustomobject])]
  param ([AllowEmptyString()][string]$Path)

  $Value = $Path.Trim().TrimEnd('\')
  if ($Value -notmatch '^(?<Root>HK(?:CR|CU|LM|U|PD|CC|DD)|HKEY_(?:CLASSES_ROOT|CURRENT_USER|LOCAL_MACHINE|USERS|PERFORMANCE_DATA|CURRENT_CONFIG|DYN_DATA))\\(?<Key>.*)$') { return $null }
  # Capture both fields before the following regex switch replaces PowerShell's
  # automatic $Matches dictionary with the hive-alias match.
  $RootText = $Matches.Root
  $Key = $Matches.Key
  $Root = switch -Regex ($RootText) {
    '^(?:HKCR|HKEY_CLASSES_ROOT)$' { 'HKCR'; break }
    '^(?:HKCU|HKEY_CURRENT_USER)$' { 'HKCU'; break }
    '^(?:HKLM|HKEY_LOCAL_MACHINE)$' { 'HKLM'; break }
    '^(?:HKU|HKEY_USERS)$' { 'HKU'; break }
    '^(?:HKPD|HKEY_PERFORMANCE_DATA)$' { 'HKPD'; break }
    '^(?:HKCC|HKEY_CURRENT_CONFIG)$' { 'HKCC'; break }
    '^(?:HKDD|HKEY_DYN_DATA)$' { 'HKDD'; break }
  }
  if (-not $Root) { return $null }
  return [pscustomobject]@{ Root = $Root; Key = $Key.TrimStart('\') }
}

function Add-NSISRegistryPluginWrite {
  <#
  .SYNOPSIS
    Project one source-backed Registry::_Write call into virtual registry evidence.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Path
    Full registry path containing the hive and key.
  .PARAMETER Name
    Registry value name.
  .PARAMETER Value
    Registry value data.
  .PARAMETER Type
    Registry plug-in type name such as REG_SZ or REG_DWORD.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [AllowEmptyString()][string]$Path,
    [AllowEmptyString()][string]$Name,
    [AllowEmptyString()][string]$Value,
    [AllowEmptyString()][string]$Type
  )

  $Target = Resolve-NSISRegistryPluginPath -Path $Path
  $RegistryType = $Type.Trim().ToUpperInvariant()
  if (-not $Target -or $RegistryType -notmatch '^REG_(?:BINARY|DWORD|DWORD_BIG_ENDIAN|EXPAND_SZ|MULTI_SZ|NONE|SZ|LINK|RESOURCE_LIST|FULL_RESOURCE_DESCRIPTOR|RESOURCE_REQUIREMENTS_LIST|QWORD)$') { return $false }

  $Write = [pscustomobject]@{
    Root           = $Target.Root
    Key            = $Target.Key
    Name           = $Name
    Value          = $Value
    Type           = $RegistryType
    RawType        = $RegistryType
    RegistryType   = $RegistryType
    IsUninstallKey = $Target.Key -match $Script:NSIS_UNINSTALL_KEY_PATTERN
    Opcode         = $Script:NSIS_OPCODE_REGISTER_DLL
    RawOpcode      = $Script:NSIS_OPCODE_REGISTER_DLL
    Conditional    = [bool]$State.HasUnknownControlFlow
    Provenance     = [string[]]@($State.ConditionalReasons)
    Source         = 'RegistryPlugin'
  }
  $State.RegistryWrites.Add($Write)
  if ($Write.Conditional) {
    $State.Metadata.UnresolvedFields = [string[]]@($State.Metadata.UnresolvedFields + @('RegistryWrites', 'AppsAndFeaturesEntries') | Select-Object -Unique)
  }
  Set-NSISRegistryValue -State $State -Root $Target.Root -Key $Target.Key -Name $Name -Value $Value
  return $true
}

function Invoke-NSISRegistryPluginCall {
  <#
  .SYNOPSIS
    Simulate deterministic Instructor Registry plug-in stack operations.
  .DESCRIPTION
    Implements the published v4.2 plug-in contracts used for ARP registration
    without loading the extracted DLL or consulting the parser host registry.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER FunctionName
    Export invoked by the compiled EW_REGISTERDLL command.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][string]$FunctionName
  )

  switch ($FunctionName.ToLowerInvariant()) {
    '_write' {
      $Path = Pop-NSISStackValue -State $State
      $Name = Pop-NSISStackValue -State $State
      $Value = Pop-NSISStackValue -State $State
      $Type = Pop-NSISStackValue -State $State
      $Succeeded = Add-NSISRegistryPluginWrite -State $State -Path $Path -Name $Name -Value $Value -Type $Type
      $State.Stack.Add($Succeeded ? '0' : '-1')
      return $true
    }
    '_read' {
      $Path = Pop-NSISStackValue -State $State
      $Name = Pop-NSISStackValue -State $State
      $Target = Resolve-NSISRegistryPluginPath -Path $Path
      $Exists = $Target -and $State.Registry.ContainsKey($Target.Root) -and $State.Registry[$Target.Root].ContainsKey($Target.Key) -and $State.Registry[$Target.Root][$Target.Key].ContainsKey($Name)
      $Type = ''
      $Value = ''
      if ($Exists) {
        $Value = Get-NSISRegistryValue -State $State -Root $Target.Root -Key $Target.Key -Name $Name
        for ($Index = $State.RegistryWrites.Count - 1; $Index -ge 0; $Index--) {
          $Write = $State.RegistryWrites[$Index]
          if ($Write.Root -ieq $Target.Root -and $Write.Key -ieq $Target.Key -and $Write.Name -ieq $Name) { $Type = [string]$Write.Type; break }
        }
        if (-not $Type) { $Type = 'REG_SZ' }
      }
      # registry.c pushes type first and value second, making value the first
      # result consumed by the macro's following Pop instruction.
      $State.Stack.Add($Type)
      $State.Stack.Add($Value)
      return $true
    }
    '_keyexists' {
      $Target = Resolve-NSISRegistryPluginPath -Path (Pop-NSISStackValue -State $State)
      $Exists = $Target -and $State.Registry.ContainsKey($Target.Root) -and $State.Registry[$Target.Root].ContainsKey($Target.Key)
      $State.Stack.Add($Exists ? '0' : '-1')
      return $true
    }
    '_createkey' {
      $Target = Resolve-NSISRegistryPluginPath -Path (Pop-NSISStackValue -State $State)
      if (-not $Target) { $State.Stack.Add('-1'); return $true }
      if (-not $State.Registry.ContainsKey($Target.Root)) { $State.Registry[$Target.Root] = @{} }
      $Existed = $State.Registry[$Target.Root].ContainsKey($Target.Key)
      if (-not $Existed) { $State.Registry[$Target.Root][$Target.Key] = @{} }
      $State.Stack.Add($Existed ? '1' : '0')
      return $true
    }
    '_deletevalue' {
      $Path = Pop-NSISStackValue -State $State
      $Name = Pop-NSISStackValue -State $State
      $Target = Resolve-NSISRegistryPluginPath -Path $Path
      if ($Target) { Remove-NSISRegistryValue -State $State -Root $Target.Root -Key $Target.Key -Name $Name }
      $State.Stack.Add($Target ? '0' : '-1')
      return $true
    }
    { $_ -in @('_deletekey', '_deletekeyempty') } {
      $Target = Resolve-NSISRegistryPluginPath -Path (Pop-NSISStackValue -State $State)
      if ($Target) { Remove-NSISRegistryValue -State $State -Root $Target.Root -Key $Target.Key -Name '' }
      $State.Stack.Add($Target ? '0' : '-1')
      return $true
    }
    '_unload' { return $true }
    default { return $false }
  }
}

function Get-NSISRegistryPluginScopeVariable {
  <#
  .SYNOPSIS
    Locate variables that select HKCU or HKLM for Registry plug-in ARP writes.
  .DESCRIPTION
    Some dual-scope installers build the complete uninstall path on the stack
    and call Registry::_Write instead of using SetShellVarContext and
    EW_WRITEREG. A variable is accepted only when it is referenced by the path
    immediately pushed before a validated _Write call and has explicit HKCU and
    HKLM assignments in the compiled command table.
  .PARAMETER State
    Mutable NSIS simulation state containing normalized commands and strings.
  #>
  [OutputType([int[]])]
  param ([Parameter(Mandatory)][pscustomobject]$State)

  $Candidates = [Collections.Generic.HashSet[int]]::new()
  $AssignedRootsByVariable = @{}
  foreach ($Entry in $State.Entries) {
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_ASSIGN_VAR) { continue }
    $AssignedValue = Get-NSISString -State $State -RelativeOffset $Entry.Values[2]
    if ($AssignedValue -notin @('HKCU', 'HKLM')) { continue }
    $VariableIndex = [Math]::Abs($Entry.Values[1])
    if (-not $AssignedRootsByVariable.ContainsKey($VariableIndex)) {
      $AssignedRootsByVariable[$VariableIndex] = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    }
    $null = $AssignedRootsByVariable[$VariableIndex].Add($AssignedValue)
  }

  for ($EntryIndex = 1; $EntryIndex -lt $State.Entries.Count; $EntryIndex++) {
    $Entry = $State.Entries[$EntryIndex]
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_REGISTER_DLL) { continue }
    $Library = [IO.Path]::GetFileName((Get-NSISString -State $State -RelativeOffset $Entry.Values[1]))
    $Function = Get-NSISString -State $State -RelativeOffset $Entry.Values[2]
    if ($Library -ine 'registry.dll' -or $Function -ine '_Write') { continue }

    # Registry::_Write pops the full path first, so the immediately preceding
    # Push record must contain the path expression used by this call.
    $PathPush = $State.Entries[$EntryIndex - 1]
    if ($PathPush.Opcode -ne $Script:NSIS_OPCODE_PUSH_POP -or $PathPush.Values[2] -ne 0 -or $PathPush.Values[3] -ne 0) { continue }
    $Path = Get-NSISString -State $State -RelativeOffset $PathPush.Values[1]
    if ($Path.TrimStart('\') -notmatch $Script:NSIS_UNINSTALL_KEY_PATTERN) { continue }

    foreach ($VariableIndex in @(Get-NSISStringVariableIndex -State $State -RelativeOffset $PathPush.Values[1])) {
      $AssignedRoots = $AssignedRootsByVariable[$VariableIndex]
      if (-not $AssignedRoots) { continue }
      if ($AssignedRoots.Contains('HKCU') -and $AssignedRoots.Contains('HKLM')) { $null = $Candidates.Add([int]$VariableIndex) }
    }
  }
  return [int[]]@($Candidates)
}

function Set-NSISRegistryPluginScope {
  <#
  .SYNOPSIS
    Select the explicit Registry plug-in root for a caller-requested scope.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER VariableIndex
    Variables proven by Get-NSISRegistryPluginScopeVariable to select both
    supported uninstall hives.
  .PARAMETER Scope
    Requested user or machine installation route.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][int[]]$VariableIndex,
    [Parameter(Mandatory)][ValidateSet('user', 'machine')][string]$Scope
  )

  $Root = if ($Scope -eq 'machine') { 'HKLM' } else { 'HKCU' }
  foreach ($Index in $VariableIndex) { Set-NSISVariableValue -State $State -Index $Index -Value $Root }
  $ContextValue = if ($Scope -eq 'machine') { 1 } else { 0 }
  $State.ExecFlags[$Script:NSIS_EXEC_FLAG_SHELL_VAR_CONTEXT] = $ContextValue
  $State.ShellVarContext = $Root
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

  if ($FunctionName -in @('Alloc', 'StrAlloc')) {
    # Buffers.c pops a size and pushes a zero-filled GlobalAlloc pointer. The
    # simulator represents the pointer with a stable nonzero scalar; APIs that
    # receive it below project their written text back into the referenced NSIS
    # register instead of exposing parser-host memory.
    $Size = 0L
    $null = [long]::TryParse((Pop-NSISStackValue -State $State), [ref]$Size)
    $State.Stack.Add($(if ($Size -gt 0) { '65536' } else { '0' }))
    return $true
  }

  if ($FunctionName -ieq 'Free') {
    # System::Free consumes one pointer and has no script-visible output.
    $null = Pop-NSISStackValue -State $State
    return $true
  }

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

  if ($Command -match '(?i)kernel32::GetLogicalDriveStrings(?:W|A)?\([^)]*\)\s*i\([^,]+,\s*r(?<BufferRegister>\d+)\)') {
    # Drive enumeration depends on the target machine. Project an empty,
    # correctly terminated MULTI_SZ into the caller's buffer so metadata
    # simulation follows the no-drive-effects path instead of repeatedly
    # walking an opaque allocation that can never acquire a NUL terminator.
    Set-NSISVariableValue -State $State -Index ([int]$Matches.BufferRegister) -Value ''
    if ($Command -match '(?i)\)\s*i\.r(?<ResultRegister>\d+)') {
      Set-NSISVariableValue -State $State -Index ([int]$Matches.ResultRegister) -Value '0'
    }
    return $true
  }

  if ($Command -match '(?i)kernel32::lstrlen(?:W|A)?\([^)]*\)\s*i\(i\s+r(?<InputRegister>\d+)\)\s*\.r(?<ResultRegister>\d+)') {
    $Value = Get-NSISVariableValue -State $State -Index ([int]$Matches.InputRegister)
    Set-NSISVariableValue -State $State -Index ([int]$Matches.ResultRegister) -Value ([string]$Value.Length)
    return $true
  }

  if ($Command -match '(?i)kernel32::GetDriveType(?:W|A)?\([^)]*\)\s*i\([^)]*\)\s*\.r(?<ResultRegister>\d+)') {
    # DRIVE_UNKNOWN is the conservative result when no caller-provided target
    # filesystem can establish the drive kind.
    Set-NSISVariableValue -State $State -Index ([int]$Matches.ResultRegister) -Value '0'
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

function Invoke-NSISUacPluginCall {
  <#
  .SYNOPSIS
    Simulate deterministic stack results from the NSIS UAC plug-in.
  .DESCRIPTION
    Static metadata analysis follows a successful installation route. A
    requested machine scope therefore has an elevated token. A requested user
    scope remains non-admin unless the installer has an independently selected
    Registry plug-in hive, in which case elevation and ARP scope are separate.
    No parser-host token or UAC prompt is consulted.
  .PARAMETER State
    Mutable NSIS simulation state whose stack receives plug-in results.
  .PARAMETER FunctionName
    Export invoked by the compiled plug-in call.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][string]$FunctionName
  )

  if ($FunctionName -ieq '_Unload') { return $true }
  if ($FunctionName -ieq 'GetOuterHwnd') {
    # This plug-in generation returns scalar helpers through $0 rather than
    # leaving a value on the NSIS stack.
    Set-NSISVariableValue -State $State -Index 0 -Value '0'
    return $true
  }
  if ($FunctionName -ine 'IsAdmin') { return $false }

  $HasIndependentScopeSelector = @($State.RegistryPluginScopeVariables).Count -gt 0
  $IsAdmin = $State.Metadata.RequestedExecutionLevel -eq 'requireAdministrator' -or
  $State.TargetScope -eq 'machine' -or
  ($State.TargetScope -eq 'user' -and $HasIndependentScopeSelector)
  Set-NSISVariableValue -State $State -Index 0 -Value $(if ($IsAdmin) { '1' } else { '0' })
  return $true
}

function Invoke-NSISProcessPluginCall {
  <#
  .SYNOPSIS
    Simulate the stack contract of the standard nsProcess plug-in.
  .DESCRIPTION
    nsProcess pops a process name and pushes 0 when it finds a match or 603
    when no process matches. Static fresh-install analysis uses the latter path
    and records the process predicate so runtime validation can revisit it.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER FunctionName
    Exported nsProcess function.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][string]$FunctionName
  )

  if ($FunctionName -ieq '_Unload') { return $true }
  if ($FunctionName -notin @('_FindProcess', '_KillProcess', '_CloseProcess')) { return $false }
  $ProcessName = if ($State.Stack.Count -gt 0) { [string]$State.Stack[$State.Stack.Count - 1] } else { '' }
  if ($State.Stack.Count -gt 0) { $State.Stack.RemoveAt($State.Stack.Count - 1) }
  if ($State.PSObject.Properties['UnknownProcessPredicates'] -and -not [string]::IsNullOrWhiteSpace($ProcessName)) {
    $null = $State.UnknownProcessPredicates.Add($ProcessName)
  }
  $State.Stack.Add('603')
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
    when writes resolved for the requested architecture and, when supplied, the
    requested scope resolve to one key. Writes compiled for another scope are
    ignored because templates can retain both HKCU and HKLM command paths even
    when only one is reachable.
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

  if ([string]::IsNullOrWhiteSpace([string]$State.TargetScope) -and
    [string]::IsNullOrWhiteSpace([string]$State.TargetArchitecture)) { return $false }
  $Candidates = @(Get-NSISDirectUninstallWrites -State $State)
  if (-not [string]::IsNullOrWhiteSpace([string]$State.TargetScope)) {
    $ExpectedRoot = $State.TargetScope -eq 'machine' ? 'HKLM' : 'HKCU'
    $Candidates = @($Candidates | Where-Object Root -CEQ $ExpectedRoot)
  }
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
    # Do not let the lexical fallback replace architecture- or scope-specific
    # identity already selected by simulation. One stable write is sufficient
    # to establish ProductCode when the simulator reached no ARP key at all.
    if (-not [string]::IsNullOrWhiteSpace([string]$State.Metadata.ProductCode) -and
      -not [string]::IsNullOrWhiteSpace([string]$State.Metadata[$Write.Name])) { continue }
    $AlreadyRecorded = @($State.RegistryWrites | Where-Object {
        $_.Root -ceq $Write.Root -and $_.Key -ceq $Write.Key -and $_.Name -ceq $Write.Name -and
        $_.Type -ceq $Write.Type -and $_.Value -ceq $Write.Value
      }).Count -gt 0
    if (-not $AlreadyRecorded) { $State.RegistryWrites.Add($Write) }
    Set-NSISRegistryValue -State $State -Root $Write.Root -Key $Write.Key -Name $Write.Name -Value $Write.Value
  }

  # The standard electron-builder registry macro composes these values from
  # scope-dependent registers. Preserve that limitation explicitly instead of
  # reporting a lexically nearest but potentially wrong switch or path.
  $DynamicNames = @('UninstallString', 'QuietUninstallString', 'DisplayIcon') | Where-Object {
    $_ -cin $Names -and [string]::IsNullOrWhiteSpace([string]$State.Metadata[$_])
  }
  $State.Metadata.UnresolvedFields = [string[]]@($State.Metadata.UnresolvedFields + $DynamicNames | Select-Object -Unique)
  return [bool]$State.Metadata.WritesAppsAndFeaturesEntry
}

function Invoke-NSISCodeSegment {
  <#
  .SYNOPSIS
    Simulate a compiled NSIS code segment across bounded alternative paths.
  .DESCRIPTION
    Resolvable commands execute in one state. A handler can return a Fork action
    with source-backed alternative addresses for an unresolved predicate. Each
    path receives an isolated state and is executed under path, depth, and step
    limits. Terminal states are merged conservatively into the caller's state.
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

  $WatchdogLimit = [Math]::Max($State.Entries.Count * $Script:NSIS_MAX_WATCHDOG_MULTIPLIER, 1)
  $TotalWatchdogLimit = $WatchdogLimit * $Script:NSIS_MAX_BRANCH_PATHS
  $SegmentStart = $Position
  $Queue = [Collections.Generic.Queue[object]]::new()
  $Queue.Enqueue([pscustomobject]@{ State = $State; Position = $Position; Steps = 0; Depth = 0 })
  $TerminalPaths = [Collections.Generic.List[object]]::new()
  $CreatedPathCount = 1
  $TotalSteps = 0
  $HadFork = $false
  [string[]]$InitialConditionalReasons = @()

  while ($Queue.Count -gt 0) {
    $WorkItem = $Queue.Dequeue()
    $PathState = $WorkItem.State
    $PathPosition = [int]$WorkItem.Position
    $PathSteps = [int]$WorkItem.Steps
    $PathDepth = [int]$WorkItem.Depth
    $PathCompleted = $false

    # Every path has an independent watchdog, while the aggregate budget limits
    # work multiplied by branching. Recursive CALL segments receive the same
    # limits through their own bounded invocation.
    while ($PathPosition -ge 0 -and $PathPosition -lt $PathState.Entries.Count) {
      $Result = Invoke-NSISEntry -State $PathState -Entry $PathState.Entries[$PathPosition]
      $PathSteps++
      $TotalSteps++
      if ($PathSteps -gt $WatchdogLimit -or $TotalSteps -gt $TotalWatchdogLimit) {
        if (-not $HadFork -and $PathDepth -eq 0) {
          throw "The NSIS code segment starting at entry $SegmentStart exceeded its bounded static execution budget near entry $PathPosition"
        }
        $PathState.TruncatedBranchCount++
        $LimitReason = "The NSIS branch path near entry $PathPosition exceeded its bounded execution budget."
        $PathState.HasUnknownControlFlow = $true
        $null = $PathState.ConditionalReasons.Add($LimitReason)
        $PathState.Metadata.UnresolvedFields = [string[]]@($PathState.Metadata.UnresolvedFields + 'ControlFlowBranches' | Select-Object -Unique)
        $TerminalPaths.Add([pscustomobject]@{ State = $PathState; Outcome = 'Return' })
        if ($TotalSteps -gt $TotalWatchdogLimit) {
          while ($Queue.Count -gt 0) {
            $Pending = $Queue.Dequeue()
            $Pending.State.TruncatedBranchCount++
            $Pending.State.HasUnknownControlFlow = $true
            $null = $Pending.State.ConditionalReasons.Add('The aggregate NSIS branch execution budget was exhausted.')
            $Pending.State.Metadata.UnresolvedFields = [string[]]@($Pending.State.Metadata.UnresolvedFields + 'ControlFlowBranches' | Select-Object -Unique)
            $TerminalPaths.Add([pscustomobject]@{ State = $Pending.State; Outcome = 'Return' })
          }
        }
        $PathCompleted = $true
        break
      }

      if ($Result.Action -in @('Return', 'Quit', 'Abort')) {
        $TerminalPaths.Add([pscustomobject]@{ State = $PathState; Outcome = $Result.Action })
        $PathCompleted = $true
        break
      }

      if ($Result.Action -eq 'Fork') {
        $Addresses = [int[]]@($Result.Addresses | Select-Object -Unique)
        if ($Addresses.Count -gt 1 -and $PathDepth -lt $Script:NSIS_MAX_BRANCH_DEPTH -and
          $CreatedPathCount + $Addresses.Count - 1 -le $Script:NSIS_MAX_BRANCH_PATHS) {
          if (-not $HadFork) { $InitialConditionalReasons = [string[]]@($PathState.ConditionalReasons) }
          $HadFork = $true
          $CreatedPathCount += $Addresses.Count - 1
          for ($AlternativeIndex = 0; $AlternativeIndex -lt $Addresses.Count; $AlternativeIndex++) {
            $Address = $Addresses[$AlternativeIndex]
            $BranchState = Copy-NSISExecutionState -State $PathState
            $null = $BranchState.BranchPredicates.Add([string]$Result.Reason)
            $BranchState.ExploredBranchCount++
            # Path-local effects need provenance, but a successfully explored
            # predicate is normal structured evidence rather than a warning.
            $BranchState.HasUnknownControlFlow = $true
            $null = $BranchState.ConditionalReasons.Add([string]$Result.Reason)
            if ($Result.PSObject.Properties['Path'] -and $Result.PSObject.Properties['PathExistence']) {
              $Exists = [string]$Result.PathExistence[$AlternativeIndex] -ceq 'Present'
              $AssumptionPath = [string]$Result.Path
              $WasCreatedFile = $BranchState.Files.Contains($AssumptionPath)
              $WasCreatedDirectory = $BranchState.Directories.Contains($AssumptionPath)
              $null = Set-NSISVirtualFileRecord -State $BranchState -Path $AssumptionPath -Exists $Exists
              # The premise represents pre-existing target state, not a file
              # extracted by this installer path.
              if (-not $WasCreatedFile) { $null = $BranchState.Files.Remove($AssumptionPath) }
              if (-not $WasCreatedDirectory) { $null = $BranchState.Directories.Remove($AssumptionPath) }
              $null = $BranchState.UnknownFileSystemPredicates.Remove([string]$Result.Path)
            }
            if ($Result.PSObject.Properties['Flag'] -and $Result.PSObject.Properties['FlagValues']) {
              $Flag = [int]$Result.Flag
              $null = $BranchState.UnknownExecFlags.Remove($Flag)
              $BranchState.ExecFlags[$Flag] = [int]$Result.FlagValues[$AlternativeIndex]
            }
            $ResolvedAddress = Resolve-NSISAddress -State $BranchState -Address $Address
            $NextPosition = if ($ResolvedAddress -eq 0) { $PathPosition + 1 } else { $ResolvedAddress - 1 }
            $Queue.Enqueue([pscustomobject]@{ State = $BranchState; Position = $NextPosition; Steps = $PathSteps; Depth = $PathDepth + 1 })
          }
          $PathCompleted = $true
          break
        }

        # Preserve the previous conservative behavior when a malformed or
        # branch-heavy installer reaches the configured bounds.
        $PathState.TruncatedBranchCount++
        $null = $PathState.BranchPredicates.Add([string]$Result.Reason)
        $LimitReason = 'NSIS branch exploration reached the configured path or depth limit; the preferred fresh-install edge was retained.'
        $PathState.HasUnknownControlFlow = $true
        $null = $PathState.ConditionalReasons.Add($LimitReason)
        $FallbackAddress = if ($Result.PSObject.Properties['PreferredAddress']) { [int]$Result.PreferredAddress } else { $Addresses[-1] }
        $ResolvedAddress = Resolve-NSISAddress -State $PathState -Address $FallbackAddress
        $PathPosition = if ($ResolvedAddress -eq 0) { $PathPosition + 1 } else { $ResolvedAddress - 1 }
        continue
      }

      $ResolvedAddress = Resolve-NSISAddress -State $PathState -Address $Result.Address
      $PathPosition = if ($ResolvedAddress -eq 0) { $PathPosition + 1 } else { $ResolvedAddress - 1 }
    }

    if (-not $PathCompleted) { $TerminalPaths.Add([pscustomobject]@{ State = $PathState; Outcome = 'Return' }) }
  }

  if ($HadFork) {
    Merge-NSISExecutionStates -Target $State -State ([pscustomobject[]]@($TerminalPaths.State)) -InitialConditionalReasons $InitialConditionalReasons
  }
  $Outcomes = [string[]]@($TerminalPaths.Outcome | Select-Object -Unique)
  if ($Outcomes.Count -eq 1) { return $Outcomes[0] }
  $State.Metadata.UnresolvedFields = [string[]]@($State.Metadata.UnresolvedFields + 'ControlFlowOutcome' | Select-Object -Unique)
  return 'Return'
}

function Resolve-NSISVirtualFullPath {
  <#
  .SYNOPSIS
    Resolve a Windows path lexically against the virtual NSIS output directory.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Path
    Relative, rooted, or symbolic Windows path.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [AllowEmptyString()][Parameter(Mandatory)][string]$Path
  )

  $Candidate = ConvertTo-NSISVirtualPath -Path $Path
  if ($Candidate -notmatch '^(?:[A-Za-z]:\\|\\\\|%[^%]+%\\|\$[A-Za-z_][A-Za-z0-9_]*\\)') {
    $Base = Get-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_OUTDIR
    if ([string]::IsNullOrWhiteSpace($Base)) { $Base = Get-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_EXEDIR }
    if (-not [string]::IsNullOrWhiteSpace($Base)) { $Candidate = (ConvertTo-NSISVirtualPath -Path $Base) + '\' + $Candidate }
  }

  $RootLength = 0
  if ($Candidate -match '^[A-Za-z]:\\') { $RootLength = 3 }
  elseif ($Candidate -match '^%[^%]+%\\') { $RootLength = $Candidate.IndexOf('\') + 1 }
  elseif ($Candidate -match '^\$[A-Za-z_][A-Za-z0-9_]*\\') { $RootLength = $Candidate.IndexOf('\') + 1 }
  elseif ($Candidate.StartsWith('\\')) {
    $Parts = $Candidate.Substring(2).Split('\')
    if ($Parts.Count -ge 2) { $RootLength = 2 + $Parts[0].Length + 1 + $Parts[1].Length + 1 }
  }

  $Root = if ($RootLength -gt 0) { $Candidate.Substring(0, [Math]::Min($RootLength, $Candidate.Length)) } else { '' }
  $Tail = if ($RootLength -lt $Candidate.Length) { $Candidate.Substring($RootLength) } else { '' }
  $Segments = [System.Collections.Generic.List[string]]::new()
  foreach ($Segment in $Tail.Split('\', [StringSplitOptions]::RemoveEmptyEntries)) {
    if ($Segment -eq '.') { continue }
    if ($Segment -eq '..') {
      if ($Segments.Count -gt 0) { $Segments.RemoveAt($Segments.Count - 1) }
      continue
    }
    $Segments.Add($Segment)
  }
  return ($Root + [string]::Join('\', $Segments)).TrimEnd('\')
}

function Get-NSISCommandLineParameters {
  <#
  .SYNOPSIS
    Reproduce the bounded FileFunc.nsh GetParameters split.
  .PARAMETER CommandLine
    Full Windows command line exposed through NSIS $CMDLINE.
  #>
  [OutputType([string])]
  param ([AllowEmptyString()][Parameter(Mandatory)][string]$CommandLine)

  if ([string]::IsNullOrWhiteSpace($CommandLine)) { return '' }
  $Separator = if ($CommandLine[0] -eq '"') { '"' } else { ' ' }
  $Start = if ($Separator -eq '"') { 1 } else { 0 }
  $End = $CommandLine.IndexOf($Separator, $Start + 1)
  if ($End -lt 0) { return '' }
  return $CommandLine.Substring($End + 1).Trim()
}

function Get-NSISCommandLineOption {
  <#
  .SYNOPSIS
    Extract a quote-aware option value using FileFunc.nsh GetOptions semantics.
  .PARAMETER Parameters
    Parameter text, normally returned by Get-NSISCommandLineParameters.
  .PARAMETER Option
    Option prefix such as /D= or --scope=.
  .PARAMETER CaseSensitive
    Match the option using ordinal case-sensitive comparison.
  #>
  [OutputType([string])]
  param (
    [AllowEmptyString()][Parameter(Mandatory)][string]$Parameters,
    [Parameter(Mandatory)][string]$Option,
    [switch]$CaseSensitive
  )

  if ([string]::IsNullOrEmpty($Option)) { return $null }
  $Comparison = if ($CaseSensitive) { [StringComparison]::Ordinal } else { [StringComparison]::OrdinalIgnoreCase }
  $Quote = [char]0
  for ($Index = 0; $Index -le $Parameters.Length - $Option.Length; $Index++) {
    $Character = $Parameters[$Index]
    if ($Character -in @('"', "'", '`')) {
      if ($Quote -eq [char]0) { $Quote = $Character } elseif ($Quote -eq $Character) { $Quote = [char]0 }
      continue
    }
    if ($Quote -ne [char]0 -or [string]::Compare($Parameters, $Index, $Option, 0, $Option.Length, $Comparison) -ne 0) { continue }

    $ValueStart = $Index + $Option.Length
    while ($ValueStart -lt $Parameters.Length -and $Parameters[$ValueStart] -eq ' ') { $ValueStart++ }
    if ($ValueStart -ge $Parameters.Length) { return '' }
    $Delimiter = if ($Parameters[$ValueStart] -in @('"', "'", '`')) { $Parameters[$ValueStart] } else { [char]0 }
    if ($Delimiter -ne [char]0) { $ValueStart++ }
    $ValueEnd = $ValueStart
    while ($ValueEnd -lt $Parameters.Length) {
      if ($Delimiter -ne [char]0) {
        if ($Parameters[$ValueEnd] -eq $Delimiter) { break }
      } elseif ($Parameters[$ValueEnd] -eq ' ') { break }
      $ValueEnd++
    }
    return $Parameters.Substring($ValueStart, $ValueEnd - $ValueStart)
  }
  return $null
}

function ConvertTo-NSISVersionWords {
  <#
  .SYNOPSIS
    Convert a dotted Windows version into NSIS high and low DWORD strings.
  .PARAMETER Version
    Two-to-four-component numeric version string.
  #>
  [OutputType([pscustomobject])]
  param ([AllowEmptyString()][Parameter(Mandatory)][string]$Version)

  $Parts = @($Version.Split('.') | ForEach-Object { [uint16]$Value = 0; if ([uint16]::TryParse($_, [ref]$Value)) { $Value } else { 0 } })
  if ($Parts.Count -lt 2) { return $null }
  while ($Parts.Count -lt 4) { $Parts += 0 }
  return [pscustomobject]@{
    High = [string](([uint32]$Parts[0] -shl 16) -bor [uint32]$Parts[1])
    Low  = [string](([uint32]$Parts[2] -shl 16) -bor [uint32]$Parts[3])
  }
}

function Set-NSISFileVersionResult {
  <#
  .SYNOPSIS
    Apply source-defined GetDLLVersion output to two NSIS variables.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Entry
    Canonical EW_GETDLLVERSION instruction.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][pscustomobject]$Entry
  )

  # GetDLLVersion stores the two output variables in offsets[0..1], the path in
  # offsets[2], and a 0/2 selector for file/product version in offsets[3].
  $Path = Resolve-NSISVirtualFullPath -State $State -Path (Get-NSISString -State $State -RelativeOffset $Entry.Values[3])
  $Record = Get-NSISVirtualFileRecord -State $State -Path $Path
  $Version = if ($Record -and $Entry.Values[4] -ne 0) { [string]$Record.ProductVersion } elseif ($Record) { [string]$Record.FileVersion } else { '' }
  $Words = if (-not [string]::IsNullOrWhiteSpace($Version)) { ConvertTo-NSISVersionWords -Version $Version } else { $null }
  if ($Words) {
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[1])) -Value $Words.High
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[2])) -Value $Words.Low
    return
  }

  Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[1])) -Value '0'
  Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[2])) -Value '0'
  $Existence = Get-NSISPathExistence -State $State -Path $Path
  if ($Existence -eq 'Absent') { Set-NSISExecutionError -State $State } else { Set-NSISFileSystemExecutionError -State $State -Path $Path }
}

function Invoke-NSISSectionOperation {
  <#
  .SYNOPSIS
    Apply EW_SECTIONSET and EW_INSTTYPESET against the virtual section table.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Entry
    Canonical section or install-type instruction.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][pscustomobject]$Entry
  )

  if ($Entry.Opcode -eq $Script:NSIS_OPCODE_INSTALL_TYPE_SET) {
    $Index = Get-NSISInt -State $State -RelativeOffset $Entry.Values[1]
    if ($Entry.Values[4] -ne 0) {
      if ($Entry.Values[3] -ne 0) {
        # SetInstType selects every ordinary section whose install-type mask
        # contains the requested bit. Section groups retain their own flags.
        $State.CurrentInstallType = $Index
        foreach ($Section in $State.Sections) {
          if (($Section.Flags -band 6) -ne 0) { continue }
          if (($Section.InstallTypes -band (1 -shl $Index)) -ne 0) {
            $Section.Flags = $Section.Flags -bor $Script:NSIS_SECTION_FLAG_SELECTED
          } else {
            $Section.Flags = $Section.Flags -band (-bnot $Script:NSIS_SECTION_FLAG_SELECTED)
          }
        }
      } else {
        Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[2])) -Value ([string]$State.CurrentInstallType)
      }
    } elseif ($Entry.Values[3] -ne 0) {
      $State.InstallTypeNames[$Index] = Get-NSISString -State $State -RelativeOffset $Entry.Values[2]
    } else {
      $Value = if ($State.InstallTypeNames.ContainsKey($Index)) { [string]$State.InstallTypeNames[$Index] } else { '' }
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[2])) -Value $Value
    }
    return
  }

  $Index = Get-NSISInt -State $State -RelativeOffset $Entry.Values[1]
  if ($Index -lt 0 -or $Index -ge $State.Sections.Count) { Set-NSISExecutionError -State $State; return }
  $Section = $State.Sections[$Index]
  $Selector = [int]$Entry.Values[3]
  $IsSet = $Selector -lt 0
  $Field = if ($IsSet) { - $Selector - 1 } else { $Selector }
  $Property = switch ($Field) { 0 { 'NameOffset' }; 1 { 'InstallTypes' }; 2 { 'Flags' }; 5 { 'SizeKb' }; default { $null } }
  if (-not $Property) { Set-NSISExecutionError -State $State; return }

  if ($IsSet) {
    $Section.$Property = if ($Field -eq 0) { [int]$Entry.Values[5] } else { Get-NSISInt -State $State -RelativeOffset $Entry.Values[2] }
  } else {
    $Value = if ($Field -eq 0) { Get-NSISString -State $State -RelativeOffset $Section.NameOffset } else { [string]$Section.$Property }
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[2])) -Value $Value
  }
}

function Get-NSISMatchingVirtualFileRecord {
  <#
  .SYNOPSIS
    Return bounded, deterministic virtual filesystem matches for an NSIS path.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Path
    Exact path or Windows wildcard pattern.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [AllowEmptyString()][Parameter(Mandatory)][string]$Path
  )

  if (-not $State.PSObject.Properties['FileSystem']) { return @() }
  $NormalizedPath = ConvertTo-NSISVirtualPath -Path $Path
  $Pattern = [System.Management.Automation.WildcardPattern]::new($NormalizedPath, [System.Management.Automation.WildcardOptions]::IgnoreCase)
  return [pscustomobject[]]@(
    $State.FileSystem.Values |
      Where-Object { $_.Exists -and $Pattern.IsMatch([string]$_.Path) } |
      Sort-Object -Property Path
  )
}

function ConvertTo-NSISVirtualFileBytes {
  <#
  .SYNOPSIS
    Convert caller-supplied virtual file content into a bounded byte array.
  .PARAMETER State
    NSIS state providing the installer ANSI encoding.
  .PARAMETER Content
    Byte, integer-array, or textual file content.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [AllowNull()][object]$Content
  )

  if ($null -eq $Content) { return , ([byte[]]::new(0)) }
  if ($Content -is [byte[]]) { return , ([byte[]]$Content.Clone()) }
  if ($Content -is [string]) { return , ([byte[]]$State.AnsiEncoding.GetBytes([string]$Content)) }
  if ($Content -is [System.Collections.IEnumerable]) {
    $Bytes = [System.Collections.Generic.List[byte]]::new()
    foreach ($Value in $Content) {
      if ($Bytes.Count -ge $Script:NSIS_MAX_VIRTUAL_FILE_BYTES) { throw 'The virtual NSIS file content exceeds the parser limit.' }
      $Bytes.Add([byte]$Value)
    }
    return , ([byte[]]$Bytes.ToArray())
  }
  return , ([byte[]]$State.AnsiEncoding.GetBytes([string]$Content))
}

function Save-NSISVirtualFileHandle {
  <#
  .SYNOPSIS
    Persist a writable virtual handle back into the simulated filesystem.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Handle
    Virtual handle record containing path, mode, position, and bytes.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][pscustomobject]$Handle
  )

  if (-not $Handle.Writable) { return }
  $null = Set-NSISVirtualFileRecord -State $State -Path $Handle.Path -Exists $true -Content ([byte[]]$Handle.Bytes.ToArray())
}

function Invoke-NSISFileOperation {
  <#
  .SYNOPSIS
    Emulate bounded NSIS file-handle commands against virtual file content.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Entry
    Canonical file open, close, read, write, or seek instruction.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][pscustomobject]$Entry
  )

  $Values = $Entry.Values
  $HandleVariable = [Math]::Abs($Values[1])
  if ($Entry.Opcode -eq $Script:NSIS_OPCODE_FILE_OPEN) {
    $Path = Resolve-NSISVirtualFullPath -State $State -Path (Get-NSISString -State $State -RelativeOffset $Values[4])
    $Record = Get-NSISVirtualFileRecord -State $State -Path $Path
    $CreationDisposition = [int]$Values[3]
    if ($CreationDisposition -eq 3 -and (-not $Record -or -not $Record.Exists)) {
      Set-NSISVariableValue -State $State -Index $HandleVariable -Value '0'
      if ((Get-NSISPathExistence -State $State -Path $Path) -eq 'Unknown') { Set-NSISFileSystemExecutionError -State $State -Path $Path } else { Set-NSISExecutionError -State $State }
      return
    }

    [byte[]]$Bytes = if ($CreationDisposition -eq 2) { , ([byte[]]::new(0)) } elseif ($Record) { ConvertTo-NSISVirtualFileBytes -State $State -Content $Record.Content } else { , ([byte[]]::new(0)) }
    $HandleId = $State.NextFileHandle++
    $Writable = ([int64]$Values[2] -band 0x40000000L) -ne 0
    $ByteList = [System.Collections.Generic.List[byte]]::new()
    if ($Bytes.Length -gt 0) { $ByteList.AddRange($Bytes) }
    $State.FileHandles[$HandleId] = [pscustomobject]@{
      Id       = $HandleId
      Path     = $Path
      Position = $(if ($CreationDisposition -eq 4) { [long]$Bytes.Length } else { [long]0 })
      Readable = ([int64]$Values[2] -band 0x80000000L) -ne 0
      Writable = $Writable
      Bytes    = $ByteList
    }
    Set-NSISVariableValue -State $State -Index $HandleVariable -Value ([string]$HandleId)
    if ($Writable) { Save-NSISVirtualFileHandle -State $State -Handle $State.FileHandles[$HandleId] }
    return
  }

  $HandleIdText = Get-NSISVariableValue -State $State -Index $HandleVariable
  [int]$HandleId = 0
  if (-not [int]::TryParse($HandleIdText, [ref]$HandleId) -or -not $State.FileHandles.ContainsKey($HandleId)) {
    if ($Entry.Opcode -in @($Script:NSIS_OPCODE_FILE_READ, $Script:NSIS_OPCODE_FILE_READ_UTF16) -and $Values[2] -ge 0) {
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[2])) -Value ''
    }
    Set-NSISExecutionError -State $State
    return
  }

  $Handle = $State.FileHandles[$HandleId]
  if ($Entry.Opcode -eq $Script:NSIS_OPCODE_FILE_CLOSE) {
    Save-NSISVirtualFileHandle -State $State -Handle $Handle
    $State.FileHandles.Remove($HandleId)
    return
  }

  if ($Entry.Opcode -eq $Script:NSIS_OPCODE_FILE_SEEK) {
    $Offset = [long](Get-NSISInt -State $State -RelativeOffset $Values[3])
    $Origin = [int]$Values[4]
    $Base = if ($Origin -eq 1) { $Handle.Position } elseif ($Origin -eq 2) { $Handle.Bytes.Count } else { 0 }
    $Handle.Position = [Math]::Max(0, [Math]::Min([long]$Handle.Bytes.Count, $Base + $Offset))
    if ($Values[2] -ge 0) { Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[2])) -Value ([string]$Handle.Position) }
    return
  }

  if ($Entry.Opcode -in @($Script:NSIS_OPCODE_FILE_WRITE, $Script:NSIS_OPCODE_FILE_WRITE_UTF16)) {
    if (-not $Handle.Writable) { Set-NSISExecutionError -State $State; return }
    if ($Values[3] -ne 0) {
      $Number = Get-NSISInt -State $State -RelativeOffset $Values[2]
      $WriteBytes = if ($Entry.Opcode -eq $Script:NSIS_OPCODE_FILE_WRITE_UTF16) { [BitConverter]::GetBytes([uint16]$Number) } else { [byte[]]@([byte]$Number) }
    } else {
      $Text = Get-NSISString -State $State -RelativeOffset $Values[2]
      $WriteBytes = if ($Entry.Opcode -eq $Script:NSIS_OPCODE_FILE_WRITE_UTF16) { [Text.Encoding]::Unicode.GetBytes($Text) } else { $State.AnsiEncoding.GetBytes($Text) }
      if ($Entry.Opcode -eq $Script:NSIS_OPCODE_FILE_WRITE_UTF16 -and $Values[4] -ne 0 -and $Handle.Position -eq 0) {
        $WriteBytes = [byte[]]@([byte]0xFF, [byte]0xFE) + $WriteBytes
      }
    }
    if ($Handle.Position + $WriteBytes.Length -gt $Script:NSIS_MAX_VIRTUAL_FILE_BYTES) { throw 'The virtual NSIS file write exceeds the parser limit.' }
    while ($Handle.Bytes.Count -lt $Handle.Position) { $Handle.Bytes.Add(0) }
    foreach ($Byte in $WriteBytes) {
      if ($Handle.Position -lt $Handle.Bytes.Count) { $Handle.Bytes[[int]$Handle.Position] = $Byte } else { $Handle.Bytes.Add($Byte) }
      $Handle.Position++
    }
    Save-NSISVirtualFileHandle -State $State -Handle $Handle
    return
  }

  if (-not $Handle.Readable -or $Handle.Position -ge $Handle.Bytes.Count) {
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[2])) -Value ''
    Set-NSISExecutionError -State $State
    return
  }

  $MaximumCharacters = [Math]::Max(1, [Math]::Min((Get-NSISInt -State $State -RelativeOffset $Values[3]), 8191))
  if ($Values[4] -ne 0) {
    $Width = if ($Entry.Opcode -eq $Script:NSIS_OPCODE_FILE_READ_UTF16) { 2 } else { 1 }
    $Available = [Math]::Min($Width, $Handle.Bytes.Count - [int]$Handle.Position)
    $NumberBytes = $Handle.Bytes.GetRange([int]$Handle.Position, $Available).ToArray()
    $Handle.Position += $Available
    $Number = if ($Width -eq 2 -and $NumberBytes.Length -eq 2) { [BitConverter]::ToUInt16($NumberBytes, 0) } else { $NumberBytes[0] }
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[2])) -Value ([string]$Number)
    return
  }

  $Remaining = $Handle.Bytes.GetRange([int]$Handle.Position, $Handle.Bytes.Count - [int]$Handle.Position).ToArray()
  $Encoding = if ($Entry.Opcode -eq $Script:NSIS_OPCODE_FILE_READ_UTF16) { [Text.Encoding]::Unicode } else { $State.AnsiEncoding }
  $Text = $Encoding.GetString($Remaining)
  if ($Text.Length -gt 0 -and $Text[0] -eq [char]0xFEFF) { $Text = $Text.Substring(1) }
  $Length = [Math]::Min($MaximumCharacters, $Text.Length)
  for ($Index = 0; $Index -lt $Length; $Index++) {
    if ($Text[$Index] -in @("`r", "`n")) {
      $Length = $Index + 1
      if ($Index + 1 -lt $Text.Length -and $Text[$Index + 1] -in @("`r", "`n") -and $Text[$Index + 1] -ne $Text[$Index]) { $Length++ }
      break
    }
  }
  $Result = $Text.Substring(0, $Length)
  $Handle.Position += $Encoding.GetByteCount($Result)
  Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[2])) -Value $Result
}

function Invoke-NSISFindOperation {
  <#
  .SYNOPSIS
    Emulate FindFirst, FindNext, and FindClose over the virtual filesystem.
  .PARAMETER State
    Mutable NSIS simulation state.
  .PARAMETER Entry
    Canonical find instruction.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][pscustomobject]$Entry
  )

  $Values = $Entry.Values
  if ($Entry.Opcode -eq $Script:NSIS_OPCODE_FIND_CLOSE) {
    [int]$HandleId = 0
    if ([int]::TryParse((Get-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1]))), [ref]$HandleId)) { $State.FindHandles.Remove($HandleId) }
    return
  }

  if ($Entry.Opcode -eq $Script:NSIS_OPCODE_FIND_FIRST) {
    $Pattern = Resolve-NSISVirtualFullPath -State $State -Path (Get-NSISString -State $State -RelativeOffset $Values[3])
    $MatchingRecords = @(Get-NSISMatchingVirtualFileRecord -State $State -Path $Pattern)
    if ($MatchingRecords.Count -eq 0) {
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ''
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[2])) -Value '0'
      if ((Get-NSISPathExistence -State $State -Path $Pattern) -eq 'Unknown') { Set-NSISFileSystemExecutionError -State $State -Path $Pattern } else { Set-NSISExecutionError -State $State }
      return
    }
    $HandleId = $State.NextFindHandle++
    $State.FindHandles[$HandleId] = [pscustomobject]@{ Matches = $MatchingRecords; Index = 1 }
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ([IO.Path]::GetFileName($MatchingRecords[0].Path))
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[2])) -Value ([string]$HandleId)
    return
  }

  [int]$HandleId = 0
  if (-not [int]::TryParse((Get-NSISVariableValue -State $State -Index ([Math]::Abs($Values[2]))), [ref]$HandleId) -or -not $State.FindHandles.ContainsKey($HandleId)) {
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ''
    Set-NSISExecutionError -State $State
    return
  }
  $Handle = $State.FindHandles[$HandleId]
  if ($Handle.Index -ge $Handle.Matches.Count) {
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ''
    Set-NSISExecutionError -State $State
    return
  }
  Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ([IO.Path]::GetFileName($Handle.Matches[$Handle.Index].Path))
  $Handle.Index++
}

function Initialize-NSISOpcodeHandlers {
  <#
  .SYNOPSIS
    Build the canonical NSIS opcode-handler registry used by the emulator.
  .DESCRIPTION
    Format profiles normalize edition-specific command numbers before this
    layer. Handlers therefore implement one canonical NSIS runtime ABI and
    produce only abstract state and system-effect evidence.
  #>
  [OutputType([hashtable])]
  param ()

  $Handlers = @{}

  # These commands affect installer presentation or non-ARP filesystem state,
  # but do not produce values consumed by the metadata model. Treating them as
  # bounded observational no-ops avoids tainting all later registry writes while
  # keeping output-producing and control-flow commands explicit below.
  $MetadataNeutralOpcodes = @(
    6, 7, 8, 9, 10, # UI text, sleep, window activation, details, attributes
    22,             # MessageBox; silent-mode response handling is separate
    32, 33, 34, 35, 36, 37, 38, 39, # window/control/font operations
    47,             # reboot request
    67, 70, 71, 72, 73 # section/UI locking/log and optional probes
  )
  foreach ($Opcode in $MetadataNeutralOpcodes) {
    $Handlers[$Opcode] = { param($State, $Entry) $null = $State, $Entry; $Script:NSIS_CONTINUE_RESULT }
  }
  $Handlers[$Script:NSIS_OPCODE_INVALID] = { param($State, $Entry) $null = $State, $Entry; $Script:NSIS_RETURN_RESULT }
  $Handlers[$Script:NSIS_OPCODE_RETURN] = { param($State, $Entry) $null = $State, $Entry; $Script:NSIS_RETURN_RESULT }
  $Handlers[$Script:NSIS_OPCODE_ABORT] = { param($State, $Entry) $null = $State, $Entry; $Script:NSIS_ABORT_RESULT }
  $Handlers[$Script:NSIS_OPCODE_QUIT] = { param($State, $Entry) $null = $State, $Entry; $Script:NSIS_QUIT_RESULT }
  $Handlers[$Script:NSIS_OPCODE_JUMP] = { param($State, $Entry) $null = $State; [pscustomobject]@{ Action = 'Continue'; Address = $Entry.Values[1] } }
  $Handlers[$Script:NSIS_OPCODE_CALL] = {
    param($State, $Entry)
    $Result = Invoke-NSISCodeSegment -State $State -Position ((Resolve-NSISAddress -State $State -Address $Entry.Values[1]) - 1)
    if ($Result -in @('Quit', 'Abort')) { return [pscustomobject]@{ Action = $Result; Address = 0 } }
    return $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_CREATE_DIR] = {
    param($State, $Entry)
    $Values = $Entry.Values
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
  $Handlers[$Script:NSIS_OPCODE_IF_FILE_EXISTS] = {
    param($State, $Entry)
    $Values = $Entry.Values
    $FileName = Resolve-NSISVirtualFullPath -State $State -Path (Get-NSISString -State $State -RelativeOffset $Values[1])
    $Existence = Get-NSISPathExistence -State $State -Path $FileName
    if ($Existence -eq 'Unknown') {
      $null = $State.UnknownFileSystemPredicates.Add($FileName)
      return [pscustomobject]@{
        Action           = 'Fork'
        Addresses        = [int[]]@($Values[2], $Values[3])
        PreferredAddress = $Values[3]
        Reason           = "IfFileExists depends on unresolved target path '$FileName'."
        Path             = $FileName
        PathExistence    = [string[]]@('Present', 'Absent')
      }
    }
    [pscustomobject]@{ Action = 'Continue'; Address = if ($Existence -eq 'Present') { $Values[2] } else { $Values[3] } }
  }
  $Handlers[$Script:NSIS_OPCODE_RENAME] = {
    param($State, $Entry)
    $Source = Resolve-NSISVirtualFullPath -State $State -Path (Get-NSISString -State $State -RelativeOffset $Entry.Values[1])
    $Destination = Resolve-NSISVirtualFullPath -State $State -Path (Get-NSISString -State $State -RelativeOffset $Entry.Values[2])
    $Record = Get-NSISVirtualFileRecord -State $State -Path $Source
    if ($Record -and $Record.Exists) {
      $null = Set-NSISVirtualFileRecord -State $State -Path $Destination -Exists $true -IsDirectory $Record.IsDirectory -Content $Record.Content -FileVersion $Record.FileVersion -ProductVersion $Record.ProductVersion -LastWriteTimeHigh $Record.LastWriteTimeHigh -LastWriteTimeLow $Record.LastWriteTimeLow
      $null = Set-NSISVirtualFileRecord -State $State -Path $Source -Exists $false -IsDirectory $Record.IsDirectory
    } elseif ((Get-NSISPathExistence -State $State -Path $Source) -eq 'Unknown') {
      Set-NSISFileSystemExecutionError -State $State -Path $Source
    } else {
      Set-NSISExecutionError -State $State
    }
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_GET_FULL_PATH_NAME] = {
    param($State, $Entry)
    $Path = Resolve-NSISVirtualFullPath -State $State -Path (Get-NSISString -State $State -RelativeOffset $Entry.Values[1])
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[2])) -Value $Path
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_SEARCH_PATH] = {
    param($State, $Entry)
    $Name = Get-NSISString -State $State -RelativeOffset $Entry.Values[2]
    $Match = @(Get-NSISMatchingVirtualFileRecord -State $State -Path "*\$Name" | Select-Object -First 1)
    if ($Match.Count -gt 0) {
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[1])) -Value ([string]$Match[0].Path)
    } else {
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[1])) -Value ''
      if ($State.FileSystemComplete) { Set-NSISExecutionError -State $State } else { Set-NSISFileSystemExecutionError -State $State -Path $Name }
    }
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_GET_TEMP_FILE_NAME] = {
    param($State, $Entry)
    $Directory = Resolve-NSISVirtualFullPath -State $State -Path (Get-NSISString -State $State -RelativeOffset $Entry.Values[2])
    $Path = "$Directory\nsis$('{0:X4}' -f $State.NextTempFile++).tmp"
    Add-NSISFile -State $State -Path $Path
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[1])) -Value $Path
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_DELETE_FILE] = {
    param($State, $Entry)
    $Path = Resolve-NSISVirtualFullPath -State $State -Path (Get-NSISString -State $State -RelativeOffset $Entry.Values[1])
    $Records = @(Get-NSISMatchingVirtualFileRecord -State $State -Path $Path)
    foreach ($Record in $Records) { $null = Set-NSISVirtualFileRecord -State $State -Path $Record.Path -Exists $false -IsDirectory $Record.IsDirectory }
    if ($Records.Count -eq 0 -and (Get-NSISPathExistence -State $State -Path $Path) -eq 'Unknown') { Set-NSISFileSystemExecutionError -State $State -Path $Path }
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_MESSAGE_BOX] = {
    param($State, $Entry)
    # my_MessageBox returns the compiled /SD response without displaying UI in
    # silent mode. Interactive responses remain intentionally unresolved.
    $IsSilent = $State.ExecFlags.ContainsKey($Script:NSIS_EXEC_FLAG_SILENT) -and $State.ExecFlags[$Script:NSIS_EXEC_FLAG_SILENT] -ne 0
    $DefaultResponse = ([uint32]$Entry.Values[1]) -shr 21
    if (-not $IsSilent -or $DefaultResponse -eq 0) { return $Script:NSIS_CONTINUE_RESULT }
    $Address = if ($DefaultResponse -eq $Entry.Values[3]) { $Entry.Values[4] } elseif ($DefaultResponse -eq $Entry.Values[5]) { $Entry.Values[6] } else { 0 }
    [pscustomobject]@{ Action = 'Continue'; Address = $Address }
  }
  $Handlers[$Script:NSIS_OPCODE_REMOVE_DIRECTORY] = {
    param($State, $Entry)
    $Path = Resolve-NSISVirtualFullPath -State $State -Path (Get-NSISString -State $State -RelativeOffset $Entry.Values[1])
    $Recursive = ($Entry.Values[2] -band 2) -ne 0
    $Pattern = if ($Recursive) { $Path.TrimEnd('\') + '\*' } else { $Path }
    foreach ($Record in @(Get-NSISMatchingVirtualFileRecord -State $State -Path $Pattern)) {
      $null = Set-NSISVirtualFileRecord -State $State -Path $Record.Path -Exists $false -IsDirectory $Record.IsDirectory
    }
    $Directory = Get-NSISVirtualFileRecord -State $State -Path $Path
    if ($Directory -and $Directory.IsDirectory) { $null = Set-NSISVirtualFileRecord -State $State -Path $Path -Exists $false -IsDirectory $true }
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_EXTRACT_FILE] = {
    param($State, $Entry)
    $LastWriteTimeLow = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$Entry.Values[4]), 0)
    $LastWriteTimeHigh = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$Entry.Values[5]), 0)
    Add-NSISFile -State $State -Path (Resolve-NSISVirtualFullPath -State $State -Path (Get-NSISString -State $State -RelativeOffset $Entry.Values[2])) -LastWriteTimeLow $LastWriteTimeLow -LastWriteTimeHigh $LastWriteTimeHigh
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_SET_FLAG] = {
    param($State, $Entry)
    $Values = $Entry.Values
    $FlagType = $Values[1]
    $Value = Get-NSISInt -State $State -RelativeOffset $Values[2]
    if ($Values[3] -le 0) {
      if ($Values[3] -lt 0) { $State.StatusUpdateFlag = if ($State.ExecFlags.ContainsKey($FlagType)) { $State.ExecFlags[$FlagType] } else { 0 } }
      else { $State.LastExecFlags[$FlagType] = if ($State.ExecFlags.ContainsKey($FlagType)) { $State.ExecFlags[$FlagType] } else { 0 } }
      $State.ExecFlags[$FlagType] = $Value
    } else {
      $State.ExecFlags[$FlagType] = if ($State.LastExecFlags.ContainsKey($FlagType)) { $State.LastExecFlags[$FlagType] } else { 0 }
      if ($Values[4] -lt 0) { $State.ExecFlags[$FlagType] = $State.StatusUpdateFlag }
    }
    $null = $State.UnknownExecFlags.Remove($FlagType)
    if ($FlagType -eq $Script:NSIS_EXEC_FLAG_SHELL_VAR_CONTEXT) {
      $ShellValue = if ($State.ExecFlags.ContainsKey($FlagType)) { $State.ExecFlags[$FlagType] } else { 0 }
      $State.ShellVarContext = if ($ShellValue -eq 0) { 'HKCU' } else { 'HKLM' }
    }
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_IF_FLAG] = {
    param($State, $Entry)
    $Values = $Entry.Values
    if ($State.UnknownExecFlags.Contains($Values[3])) {
      # IfFlag clears bits after evaluating the condition. A zero mask makes
      # the post-branch value deterministic even though both edges remain live.
      if ($Values[4] -eq 0) {
        $null = $State.UnknownExecFlags.Remove($Values[3])
        $State.ExecFlags[$Values[3]] = 0
      }
      return [pscustomobject]@{
        Action           = 'Fork'
        Addresses        = [int[]]@($Values[1], $Values[2])
        PreferredAddress = $Values[2]
        Reason           = "IfFlag depends on unresolved NSIS execution flag $($Values[3])."
        Flag             = $Values[3]
        FlagValues       = [int[]]@($(if ($Values[4] -eq 0) { 0 } else { $Values[4] -band (-$Values[4]) }), 0)
      }
    }
    $FlagValue = if ($State.ExecFlags.ContainsKey($Values[3])) { $State.ExecFlags[$Values[3]] } else { 0 }
    $Address = if ($FlagValue -ne 0) { $Values[1] } else { $Values[2] }
    $State.ExecFlags[$Values[3]] = $FlagValue -band $Values[4]
    [pscustomobject]@{ Action = 'Continue'; Address = $Address }
  }
  $Handlers[$Script:NSIS_OPCODE_GET_FLAG] = {
    param($State, $Entry)
    $Values = $Entry.Values
    $FlagValue = if ($State.UnknownExecFlags.Contains($Values[2])) { '$_NSIS_UNKNOWN_FLAG_' + $Values[2] } elseif ($State.ExecFlags.ContainsKey($Values[2])) { $State.ExecFlags[$Values[2]] } else { 0 }
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ([string]$FlagValue)
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_STR_LEN] = {
    param($State, $Entry)
    $Values = $Entry.Values
    if (Test-NSISStringOperandUnknown -State $State -RelativeOffset $Values[2]) {
      Set-NSISVariableUnknown -State $State -Index ([Math]::Abs($Values[1]))
      return $Script:NSIS_CONTINUE_RESULT
    }
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ([string](Get-NSISString -State $State -RelativeOffset $Values[2]).Length)
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_ASSIGN_VAR] = {
    param($State, $Entry)
    $Values = $Entry.Values
    if (@($Values[2..4] | Where-Object { Test-NSISStringOperandUnknown -State $State -RelativeOffset $_ }).Count -gt 0) {
      Set-NSISVariableUnknown -State $State -Index ([Math]::Abs($Values[1]))
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Result = Get-NSISString -State $State -RelativeOffset $Values[2]
    $MaximumLengthText = Get-NSISString -State $State -RelativeOffset $Values[3]
    $NewLength = if ([string]::IsNullOrEmpty($MaximumLengthText)) { $Result.Length } else { Get-NSISInt -State $State -RelativeOffset $Values[3] }
    $Start = Get-NSISInt -State $State -RelativeOffset $Values[4]
    if ($Start -lt 0) { $Start += $Result.Length }
    if ($Start -lt 0) { $Result = '' } else {
      if ($Start -gt $Result.Length) { $Start = $Result.Length }
      $Result = $Result.Substring($Start)
    }
    if ($NewLength -lt 0) { $NewLength += $Result.Length }
    if ($NewLength -lt 0) { $NewLength = 0 }
    if ($Result.Length -gt $NewLength) { $Result = $Result.Substring(0, $NewLength) }
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $Result
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_STR_CMP] = {
    param($State, $Entry)
    $Values = $Entry.Values
    $Left = Get-NSISString -State $State -RelativeOffset $Values[1]
    $Right = Get-NSISString -State $State -RelativeOffset $Values[2]
    $UnknownIndexes = @(
      Get-NSISStringVariableIndex -State $State -RelativeOffset $Values[1]
      Get-NSISStringVariableIndex -State $State -RelativeOffset $Values[2]
    ) | Where-Object { $State.UnknownVariables.Contains([int]$_) }
    if ($UnknownIndexes.Count -gt 0) {
      return [pscustomobject]@{
        Action           = 'Fork'
        Addresses        = [int[]]@($Values[3], $Values[4])
        PreferredAddress = $Values[4]
        Reason           = "StrCmp depends on unresolved NSIS variable(s): $($UnknownIndexes -join ', ')."
      }
    }
    $Equal = if ($Values[5] -eq 0) { $Left.Equals($Right, [StringComparison]::OrdinalIgnoreCase) } else { $Left -ceq $Right }
    [pscustomobject]@{ Action = 'Continue'; Address = if ($Equal) { $Values[3] } else { $Values[4] } }
  }
  $Handlers[$Script:NSIS_OPCODE_READ_ENV] = {
    param($State, $Entry)
    $Values = $Entry.Values
    $InputValue = Get-NSISString -State $State -RelativeOffset $Values[2]

    # Both ReadEnvStr and ExpandEnvStrings compile to EW_READENVSTR. The former
    # wraps its name in percent signs and sets operand two, while the latter can
    # expand several tokens inside arbitrary text. ExpandEnvironmentStrings
    # preserves unknown tokens; ReadEnvStr then turns an unchanged result into
    # an empty string and increments exec_error.
    $ExpandedValue = [regex]::Replace($InputValue, '%(?<Name>[^%]+)%', {
        param($Match)
        $Name = [string]$Match.Groups['Name'].Value
        if ($State.Environment.ContainsKey($Name)) { return [string]$State.Environment[$Name] }
        $null = $State.UnknownEnvironment.Add($Name)
        return [string]$Match.Value
      })
    if ($Values[3] -ne 0 -and $ExpandedValue -ceq $InputValue) {
      $ExpandedValue = ''
      Set-NSISExecutionError -State $State
    }
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $ExpandedValue
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_GET_OS_INFO] = {
    param($State, $Entry)
    $Values = $Entry.Values
    if ($Values[4] -eq $Script:NSIS_GET_OS_INFO_KNOWN_FOLDER) {
      $FolderId = Get-NSISString -State $State -RelativeOffset $Values[3]
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[2])) -Value (Resolve-NSISKnownFolderPath -FolderId $FolderId)
    } elseif ($Values[4] -eq $Script:NSIS_GET_OS_INFO_READ_MEMORY) {
      $Address = Get-NSISInt -State $State -RelativeOffset $Values[3]
      $Specification = [uint32](Get-NSISInt -State $State -RelativeOffset $Values[5])
      $Value = Get-NSISOsInfoMemoryValue -Address $Address -Specification $Specification
      if ($null -ne $Value) { Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[2])) -Value $Value }
    }
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_INT_CMP] = {
    param($State, $Entry)
    $Values = $Entry.Values
    $UnknownIndexes = @(
      Get-NSISStringVariableIndex -State $State -RelativeOffset $Values[1]
      Get-NSISStringVariableIndex -State $State -RelativeOffset $Values[2]
    ) | Where-Object { $State.UnknownVariables.Contains([int]$_) }
    if ($UnknownIndexes.Count -gt 0) {
      return [pscustomobject]@{
        Action           = 'Fork'
        Addresses        = [int[]]@($Values[3], $Values[4], $Values[5])
        PreferredAddress = $Values[3]
        Reason           = "IntCmp depends on unresolved NSIS variable(s): $($UnknownIndexes -join ', ')."
      }
    }
    $Left = Get-NSISInt -State $State -RelativeOffset $Values[1]
    $Right = Get-NSISInt -State $State -RelativeOffset $Values[2]
    [pscustomobject]@{ Action = 'Continue'; Address = if ($Left -eq $Right) { $Values[3] } elseif ($Left -lt $Right) { $Values[4] } else { $Values[5] } }
  }
  $Handlers[$Script:NSIS_OPCODE_INT_OP] = {
    param($State, $Entry)
    $Values = $Entry.Values
    if (@($Values[2..3] | Where-Object { Test-NSISStringOperandUnknown -State $State -RelativeOffset $_ }).Count -gt 0) {
      Set-NSISVariableUnknown -State $State -Index ([Math]::Abs($Values[1]))
      return $Script:NSIS_CONTINUE_RESULT
    }
    $Left = Get-NSISInt -State $State -RelativeOffset $Values[2]
    $Right = Get-NSISInt -State $State -RelativeOffset $Values[3]
    if ($Values[4] -in @(3, 10) -and $Right -eq 0) {
      # NSIS returns zero and increments exec_error for division or remainder
      # by zero. IfErrors can consume this flag immediately afterward.
      Set-NSISExecutionError -State $State
    }
    $Result = switch ($Values[4]) {
      0 { $Left + $Right }; 1 { $Left - $Right }; 2 { $Left * $Right }
      3 { if ($Right -eq 0) { 0 } else { [int]($Left / $Right) } }
      4 { $Left -bor $Right }; 5 { $Left -band $Right }; 6 { $Left -bxor $Right }; 7 { [int]($Left -eq 0) }
      8 { [int]($Left -ne 0 -or $Right -ne 0) }; 9 { [int]($Left -ne 0 -and $Right -ne 0) }
      10 { if ($Right -eq 0) { 0 } else { $Left % $Right } }
      11 { $Left -shl $Right }; 12 { $Left -shr $Right }; 13 { [int](([uint32]$Left) -shr $Right) }
      default { $Left }
    }
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value ([string]$Result)
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_INT_FMT] = {
    param($State, $Entry)
    $Values = $Entry.Values
    $Format = Get-NSISString -State $State -RelativeOffset $Values[2]
    $Result = if ($Format.StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) { '0x{0:X8}' -f [uint32]$Values[3] } else { [string]$Values[3] }
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $Result
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_PUSH_POP] = {
    param($State, $Entry)
    $Values = $Entry.Values
    if ($Values[3] -ne 0) {
      $ExchangeIndex = $Values[3]
      if ($ExchangeIndex -lt $State.Stack.Count) {
        $TopIndex = $State.Stack.Count - 1; $TargetIndex = $TopIndex - $ExchangeIndex
        $Temporary = $State.Stack[$TopIndex]; $State.Stack[$TopIndex] = $State.Stack[$TargetIndex]; $State.Stack[$TargetIndex] = $Temporary
      } else {
        Set-NSISExecutionError -State $State
      }
    } elseif ($Values[2] -eq $Script:NSIS_POP_OPERATION) {
      $Value = if ($State.Stack.Count -gt 0) { $State.Stack[$State.Stack.Count - 1] } else { '' }
      if ($State.Stack.Count -gt 0) { $State.Stack.RemoveAt($State.Stack.Count - 1) }
      else { Set-NSISExecutionError -State $State }
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $Value
    } else { $State.Stack.Add((Get-NSISString -State $State -RelativeOffset $Values[1])) }
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_REGISTER_DLL] = {
    param($State, $Entry)
    $Values = $Entry.Values
    $Library = [IO.Path]::GetFileName((Get-NSISString -State $State -RelativeOffset $Values[1]))
    $Function = Get-NSISString -State $State -RelativeOffset $Values[2]
    if ($Library -ieq 'System.dll') { $null = Invoke-NSISSystemPluginCall -State $State -FunctionName $Function }
    elseif ($Library -ieq 'UserInfo.dll') { $null = Invoke-NSISUserInfoPluginCall -State $State -FunctionName $Function }
    elseif ($Library -ieq 'UAC.dll') { $null = Invoke-NSISUacPluginCall -State $State -FunctionName $Function }
    elseif ($Library -ieq 'nsProcess.dll') { $null = Invoke-NSISProcessPluginCall -State $State -FunctionName $Function }
    elseif ($Library -ieq 'registry.dll') { $null = Invoke-NSISRegistryPluginCall -State $State -FunctionName $Function }
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_CREATE_SHORTCUT] = {
    param($State, $Entry)
    Add-NSISShortcutEvidence -State $State -Entry $Entry
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_SHELL_EXEC] = {
    param($State, $Entry)
    $Values = $Entry.Values
    $Verb = Get-NSISString -State $State -RelativeOffset $Values[1]
    $Kind = if ([string]::IsNullOrWhiteSpace($Verb)) { 'ShellExec' } else { "ShellExec:$Verb" }
    Add-NSISExecutedPayload -State $State -Command (Get-NSISString -State $State -RelativeOffset $Values[2]) -Parameters (Get-NSISString -State $State -RelativeOffset $Values[3]) -Kind $Kind
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_EXECUTE] = {
    param($State, $Entry)
    $Values = $Entry.Values
    Add-NSISExecutedPayload -State $State -Command (Get-NSISString -State $State -RelativeOffset $Values[1]) -Kind $(if ($Values[3] -ne 0) { 'ExecWait' } else { 'Exec' })
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_COPY_FILES] = {
    param($State, $Entry)
    $Source = Resolve-NSISVirtualFullPath -State $State -Path (Get-NSISString -State $State -RelativeOffset $Entry.Values[1])
    $Destination = Resolve-NSISVirtualFullPath -State $State -Path (Get-NSISString -State $State -RelativeOffset $Entry.Values[2])
    $Records = @(Get-NSISMatchingVirtualFileRecord -State $State -Path $Source)
    foreach ($Record in $Records) {
      $TargetPath = if ($Records.Count -gt 1 -or $Destination.EndsWith('\')) { $Destination.TrimEnd('\') + '\' + [IO.Path]::GetFileName($Record.Path) } else { $Destination }
      $null = Set-NSISVirtualFileRecord -State $State -Path $TargetPath -Exists $true -IsDirectory $Record.IsDirectory -Content $Record.Content -FileVersion $Record.FileVersion -ProductVersion $Record.ProductVersion -LastWriteTimeHigh $Record.LastWriteTimeHigh -LastWriteTimeLow $Record.LastWriteTimeLow
    }
    if ($Records.Count -eq 0) {
      if ((Get-NSISPathExistence -State $State -Path $Source) -eq 'Unknown') { Set-NSISFileSystemExecutionError -State $State -Path $Source } else { Set-NSISExecutionError -State $State }
    }
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_GET_FILE_TIME] = {
    param($State, $Entry)
    $Path = Resolve-NSISVirtualFullPath -State $State -Path (Get-NSISString -State $State -RelativeOffset $Entry.Values[3])
    $Record = @(Get-NSISMatchingVirtualFileRecord -State $State -Path $Path | Select-Object -First 1)
    if ($Record.Count -gt 0) {
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[1])) -Value ([string][uint32]$Record[0].LastWriteTimeHigh)
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[2])) -Value ([string][uint32]$Record[0].LastWriteTimeLow)
    } else {
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[1])) -Value ''
      Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[2])) -Value ''
      if ((Get-NSISPathExistence -State $State -Path $Path) -eq 'Unknown') { Set-NSISFileSystemExecutionError -State $State -Path $Path } else { Set-NSISExecutionError -State $State }
    }
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_GET_DLL_VERSION] = {
    param($State, $Entry)
    Set-NSISFileVersionResult -State $State -Entry $Entry
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_DELETE_REG] = {
    param($State, $Entry)
    $Values = $Entry.Values
    Remove-NSISRegistryValue -State $State -Root (Resolve-NSISRegistryRoot -State $State -Root $Entry.Raw[2]) -Key (Get-NSISString -State $State -RelativeOffset $Values[3]) -Name (Get-NSISString -State $State -RelativeOffset $Values[4])
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_WRITE_REG] = { param($State, $Entry) Add-NSISRegistryWrite -State $State -Entry $Entry; $Script:NSIS_CONTINUE_RESULT }
  $Handlers[$Script:NSIS_OPCODE_READ_REG] = {
    param($State, $Entry)
    $Values = $Entry.Values
    $Root = Resolve-NSISRegistryRoot -State $State -Root $Entry.Raw[2]
    $Key = Get-NSISString -State $State -RelativeOffset $Values[3]
    $Name = Get-NSISString -State $State -RelativeOffset $Values[4]
    $Exists = $State.Registry.ContainsKey($Root) -and $State.Registry[$Root].ContainsKey($Key) -and $State.Registry[$Root][$Key].ContainsKey($Name)
    $Value = Get-NSISRegistryValue -State $State -Root $Root -Key $Key -Name $Name
    if (-not $Exists) { Set-NSISExecutionError -State $State }
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Values[1])) -Value $Value
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_EXTRACT_STUB_FILE] = $Handlers[$Script:NSIS_OPCODE_EXTRACT_FILE]
  $Handlers[$Script:NSIS_OPCODE_VERIFY_EXTERNAL_FILE] = {
    param($State, $Entry)
    $null = $State, $Entry
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_ENUM_REG] = {
    param($State, $Entry)
    $Root = Resolve-NSISRegistryRoot -State $State -Root $Entry.Raw[2]
    $Key = Get-NSISString -State $State -RelativeOffset $Entry.Values[3]
    $Index = Get-NSISInt -State $State -RelativeOffset $Entry.Values[4]
    $Value = Get-NSISRegistryEnumerationValue -State $State -Root $Root -Key $Key -Index $Index -EnumerateKeys ($Entry.Values[5] -ne 0)
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[1])) -Value $Value
    $Script:NSIS_CONTINUE_RESULT
  }
  foreach ($Opcode in @(
      $Script:NSIS_OPCODE_FILE_CLOSE,
      $Script:NSIS_OPCODE_FILE_OPEN,
      $Script:NSIS_OPCODE_FILE_WRITE,
      $Script:NSIS_OPCODE_FILE_READ,
      $Script:NSIS_OPCODE_FILE_SEEK,
      $Script:NSIS_OPCODE_FILE_WRITE_UTF16,
      $Script:NSIS_OPCODE_FILE_READ_UTF16
    )) {
    $Handlers[$Opcode] = { param($State, $Entry) Invoke-NSISFileOperation -State $State -Entry $Entry; $Script:NSIS_CONTINUE_RESULT }
  }
  foreach ($Opcode in @($Script:NSIS_OPCODE_FIND_CLOSE, $Script:NSIS_OPCODE_FIND_NEXT, $Script:NSIS_OPCODE_FIND_FIRST)) {
    $Handlers[$Opcode] = { param($State, $Entry) Invoke-NSISFindOperation -State $State -Entry $Entry; $Script:NSIS_CONTINUE_RESULT }
  }
  $Handlers[$Script:NSIS_OPCODE_SECTION_SET] = { param($State, $Entry) Invoke-NSISSectionOperation -State $State -Entry $Entry; $Script:NSIS_CONTINUE_RESULT }
  $Handlers[$Script:NSIS_OPCODE_INSTALL_TYPE_SET] = { param($State, $Entry) Invoke-NSISSectionOperation -State $State -Entry $Entry; $Script:NSIS_CONTINUE_RESULT }
  $Handlers[$Script:NSIS_OPCODE_WRITE_INI] = {
    param($State, $Entry)
    Add-NSISIniWrite -State $State -Entry $Entry
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_READ_INI] = {
    param($State, $Entry)
    $Section = Get-NSISString -State $State -RelativeOffset $Entry.Values[2]
    $Key = Get-NSISString -State $State -RelativeOffset $Entry.Values[3]
    $File = Get-NSISString -State $State -RelativeOffset $Entry.Values[4]
    $Exists = $State.IniFiles.ContainsKey($File) -and $State.IniFiles[$File].ContainsKey($Section) -and $State.IniFiles[$File][$Section].ContainsKey($Key)
    Set-NSISVariableValue -State $State -Index ([Math]::Abs($Entry.Values[1])) -Value (Get-NSISIniValue -State $State -File $File -Section $Section -Key $Key)
    if (-not $Exists) { Set-NSISExecutionError -State $State }
    $Script:NSIS_CONTINUE_RESULT
  }
  $Handlers[$Script:NSIS_OPCODE_WRITE_UNINSTALLER] = {
    param($State, $Entry)
    Add-NSISFile -State $State -Path (Get-NSISString -State $State -RelativeOffset $Entry.Values[1])
    $Script:NSIS_CONTINUE_RESULT
  }
  return $Handlers
}

$Script:NSIS_OPCODE_HANDLERS = Initialize-NSISOpcodeHandlers

function Invoke-NSISEntry {
  <#
  .SYNOPSIS
    Dispatch one canonical NSIS instruction to the abstract system emulator.
  .PARAMETER State
    Mutable abstract variables, stack, registry, filesystem, and effect logs.
  .PARAMETER Entry
    Canonical instruction retaining raw and format-layout operands.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][pscustomobject]$State,
    [Parameter(Mandatory)][pscustomobject]$Entry
  )

  $Handler = $Script:NSIS_OPCODE_HANDLERS[[int]$Entry.Opcode]
  if (-not $Handler) {
    $Opcode = [int]$Entry.Opcode
    if ($State.UnsupportedOpcodes.Add($Opcode)) {
      Set-NSISUnknownCondition -State $State -Reason "NSIS opcode $Opcode (raw $($Entry.RawOpcode)) has no bounded emulator handler; subsequent effects on this path are conditional."
      $State.Metadata.UnresolvedFields = [string[]]@($State.Metadata.UnresolvedFields + "Opcode:$Opcode" | Select-Object -Unique)
    }
    return $Script:NSIS_CONTINUE_RESULT
  }
  return & $Handler $State $Entry
}

function ConvertTo-NSISManifestPath {
  <#
  .SYNOPSIS
    Convert a symbolic NSIS target path to the WinGet environment-variable form
  .DESCRIPTION
    NSIS simulation uses target tokens rather than directories from the parser
    host. This function normalizes equivalent NSIS spellings to WinGet tokens.
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

  # Longest aliases go first so Common Files wins over Program Files.
  $Mappings = @(
    @('$COMMONFILES32', '%ProgramFiles(x86)%\Common Files'),
    @('$COMMONFILES64', '%ProgramFiles%\Common Files'),
    @('$PROGRAMFILES32', '%ProgramFiles(x86)%'),
    @('$PROGRAMFILES64', '%ProgramFiles%'),
    @('$PROGRAMFILES', '%ProgramFiles%'),
    @('$LOCALAPPDATA', '%LocalAppData%'),
    @('$APPDATA', '%AppData%'),
    @('$PROGRAMDATA', '%ProgramData%'),
    @('$PROFILE', '%UserProfile%'),
    @('$WINDIR', '%SystemRoot%'),
    @('$SYSDIR', '%SystemRoot%\System32')
  ) | Sort-Object -Property { - $_[0].Length } -Stable

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

  $InformationMessages = [System.Collections.Generic.List[string]]::new()
  if ($LocalizedRegistryKeys.Count -gt 0) {
    $Locales = @($Evidence | Where-Object IsVisible | ForEach-Object { $_.Locale ?? "LANGID-$($_.LanguageId)" } | Select-Object -Unique)
    $InformationMessages.Add("NSIS uninstall DisplayName or Publisher varies by installer language ($($Locales -join ', ')); AppsAndFeaturesEntries contains $($ManifestEntries.Count) distinct visible ARP identities. Preserve the applicable localized identities and validate installed-language behavior in a VM when authoring the manifest.")
  }

  return [pscustomobject][ordered]@{
    AppsAndFeaturesEntries       = $ManifestEntries.ToArray()
    AppsAndFeaturesEntryEvidence = $Evidence.ToArray()
    Diagnostics                  = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$InformationMessages.ToArray()) -Source 'NSISSimulation' -Kind Information -Areas Metadata)
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
  $IsTemporaryMachineRoot = $EffectiveScope -eq 'machine' -and $ObservedInstallRoot -match '^(?i:\$TEMP|%TEMP%)(?:\\|$)'
  if (-not $IsRootRelative -and -not $IsTemporaryMachineRoot) { return }

  $InstallSuffix = if ($IsRootRelative) {
    $ObservedInstallRoot.TrimStart('\', '/')
  } else {
    Split-Path -Path $ObservedInstallRoot -Leaf
  }
  if ([string]::IsNullOrWhiteSpace($InstallSuffix)) { return }
  $SuffixPath = '\' + $InstallSuffix

  $KnownRoots = if ($EffectiveScope -eq 'machine') {
    @('$PROGRAMFILES', '$PROGRAMFILES32', '$PROGRAMFILES64', '%ProgramFiles%', '%ProgramFiles(x86)%')
  } elseif ($EffectiveScope -eq 'user') {
    @('$LOCALAPPDATA', '$APPDATA', '%LocalAppData%', '%AppData%')
  } else {
    @('$PROGRAMFILES', '$PROGRAMFILES32', '$PROGRAMFILES64', '$LOCALAPPDATA', '$APPDATA', '%ProgramFiles%', '%ProgramFiles(x86)%', '%LocalAppData%', '%AppData%')
  }
  $KnownRoots = @($KnownRoots) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique
  $DirectInstallDirectoryCandidates = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $SuffixCandidates = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

  foreach ($Entry in $State.Entries) {
    if ($Entry.Opcode -ne $Script:NSIS_OPCODE_ASSIGN_VAR) { continue }
    $Candidate = Get-NSISString -State $State -RelativeOffset $Entry.Values[2]
    if ([string]::IsNullOrWhiteSpace($Candidate)) { continue }
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
      '$TEMP'
      '%TEMP%'
      '$PLUGINSDIR'
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
    if ($State.Metadata.DefaultInstallLocation -match '^(?i:\$(?:PROGRAMFILES|PROGRAMFILES32|PROGRAMFILES64)|%ProgramFiles(?:\(x86\))?%)(?:\\|$)') {
      $State.Metadata.Scope = 'machine'
    } else {
      $State.Metadata.Scope = 'user'
    }
  }

  # Control-flow joins can represent an unresolved empty array element as an
  # empty string. Normalize parser-owned scope evidence before Tauri mode
  # inference so that absence is not mistaken for an unsupported scope.
  $State.Metadata.SupportedScopes = [string[]]@(
    @($State.Metadata.SupportedScopes) |
      ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } |
      Where-Object { $_ -in @('user', 'machine') } |
      Select-Object -Unique
  )
  if ($State.Metadata.HasScopeRuntimeCheck -and $State.Metadata.SupportedScopes -contains 'user' -and $State.Metadata.SupportedScopes -contains 'machine') {
    $State.Metadata.UserScopeSwitch = '/CurrentUser'
    $State.Metadata.MachineScopeSwitch = '/AllUsers'
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
    if ($TauriInfo.InstallerMode -eq 'currentUser' -and $State.Metadata.SupportedScopes.Count -eq 0) {
      $State.Metadata.SupportedScopes = [string[]]@('user')
    } elseif ($TauriInfo.InstallerMode -eq 'perMachine' -and $State.Metadata.SupportedScopes.Count -eq 0) {
      $State.Metadata.SupportedScopes = [string[]]@('machine')
    } elseif (-not $TauriInfo.InstallerMode) {
      $State.Diagnostics.Add((New-InstallerDiagnostic -Id 'NSIS.Tauri.InstallModeUnresolved' -Source 'NSIS' -Message 'The standard Tauri NSIS template was detected, but its compiled installer mode could not be resolved from scope and PE execution-level evidence.' -Kind Ambiguous -Areas Metadata, Installability -AffectedFields Scope -Evidence ([ordered]@{
              RequestedExecutionLevel = $TauriInfo.RequestedExecutionLevel
              ObservedScope           = $State.Metadata.Scope
              SupportedScopes         = [string[]]$State.Metadata.SupportedScopes
            })))
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$State.TargetScope) -and
      $State.Metadata.SupportedScopes.Count -gt 0 -and
      $State.Metadata.SupportedScopes -notcontains $State.TargetScope) {
      $State.Diagnostics.Add((New-InstallerDiagnostic -Id 'NSIS.Tauri.ScopeMismatch' -Source 'NSIS' -Message "The Tauri installer supports '$($State.Metadata.SupportedScopes -join ', ')' scope, not the requested '$($State.TargetScope)' scope." -Kind Mismatch -Areas Metadata, Installability -AffectedFields Scope -Evidence ([ordered]@{
              RequestedScope  = $State.TargetScope
              SupportedScopes = [string[]]$State.Metadata.SupportedScopes
            })))
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
      $State.Diagnostics.Add('The NSIS executable is an electron-builder portable launcher: it sets the PORTABLE_EXECUTABLE_* environment variables, executes the unpacked application from a temporary directory, and writes no visible Apps & Features entry. Treat the outer EXE as portable payload evidence rather than an installed NSIS package.')
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
  $ConcreteRegistryWrites = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($Write in @($State.RegistryWrites | Where-Object Root -CNE 'SHCTX')) {
    $null = $ConcreteRegistryWrites.Add("$($Write.Key)`0$($Write.Name)`0$($Write.Type)")
  }

  # Deduplicate exact registry evidence while preserving first-observed order.
  $RegistryWrites = @(
    foreach ($Write in @($State.RegistryWrites)) {
      # A literal pre-simulation scan can observe SHCTX before initialization,
      # then normal execution resolves the same write to HKCU or HKLM. Keep the
      # concrete evidence and discard only that exact unresolved duplicate.
      $RootlessKey = "$($Write.Key)`0$($Write.Name)`0$($Write.Type)"
      if ($Write.Root -ceq 'SHCTX' -and $ConcreteRegistryWrites.Contains($RootlessKey)) { continue }
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
    $State.Diagnostics.Add('The NSIS installer has nested installer evidence but no visible uninstall registry write was found; inspect the nested payload or validate ARP in a VM.')
  }
  if (-not $SkipLocalizedAppsAndFeaturesEntries -and
    -not $State.Metadata.IsPortable -and
    $State.Metadata.HasArchitectureRuntimeCheck -and
    [string]::IsNullOrWhiteSpace([string]$State.TargetArchitecture) -and
    [string]::IsNullOrWhiteSpace([string]$State.Metadata.ProductCode)) {
    $State.Diagnostics.Add('The installer contains a runtime architecture branch; pass -Architecture x86, x64, or arm64 to resolve architecture-specific ARP metadata deterministically.')
  }
  if (-not $SkipLocalizedAppsAndFeaturesEntries -and
    $State.Metadata.HasScopeRuntimeCheck -and
    [string]::IsNullOrWhiteSpace([string]$State.TargetScope) -and
    @($State.Metadata.SupportedScopes).Count -gt 1) {
    $State.Diagnostics.Add('The installer contains runtime user and machine scope branches; pass -Scope user or machine to resolve scope-specific ARP metadata deterministically.')
  }
  if (-not $SkipLocalizedAppsAndFeaturesEntries -and
    $State.Metadata.HasScopeRuntimeCheck -and
    -not [string]::IsNullOrWhiteSpace([string]$State.TargetScope) -and
    -not [string]::IsNullOrWhiteSpace([string]$State.Metadata.Scope) -and
    $State.TargetScope -ne $State.Metadata.Scope) {
    $State.Diagnostics.Add("The requested '$($State.TargetScope)' scope did not resolve to matching uninstall registry evidence; the parser observed '$($State.Metadata.Scope)' scope instead.")
  }

  $State.Metadata.RegistryWrites = @($RegistryWrites)
  $State.Metadata.IniWrites = @($State.IniWrites)
  $State.Metadata.CreatedShortcuts = @($State.CreatedShortcuts)
  if (-not $SkipLocalizedAppsAndFeaturesEntries) {
    # The all-language projection scans explicit registry commands once per
    # language. Defer it until a result is returned rather than repeating it for
    # the simulator's intermediate completeness checks.
    $AppsAndFeaturesInfo = Get-NSISAppsAndFeaturesEntryInfo -State $State
    $State.Metadata.AppsAndFeaturesEntries = @($AppsAndFeaturesInfo.AppsAndFeaturesEntries)
    $State.Metadata.AppsAndFeaturesEntryEvidence = @($AppsAndFeaturesInfo.AppsAndFeaturesEntryEvidence)
    $State.Metadata.Diagnostics = @(
      Merge-InstallerDiagnostics -Diagnostic @(
        $State.Metadata.Diagnostics
        $AppsAndFeaturesInfo.Diagnostics
        @(ConvertTo-InstallerDiagnostic -InputObject @($State.InformationalDiagnosticMessages) -Source 'NSISSimulation' -Kind Information -Areas Metadata)
      )
    )
    $State.Metadata.HasLocalizedAppsAndFeaturesEntries = $AppsAndFeaturesInfo.HasLocalizedEntries

    # Architecture-targeted simulation can intentionally skip a direct scan.
    # Recover a missing scalar only when every explicit visible ARP projection
    # agrees, preserving localized or architecture-specific differences.
    foreach ($PropertyName in @('ProductCode', 'DisplayName', 'DisplayVersion', 'Publisher')) {
      if (-not [string]::IsNullOrWhiteSpace([string]$State.Metadata[$PropertyName])) { continue }
      $Values = @($AppsAndFeaturesInfo.AppsAndFeaturesEntryEvidence | Where-Object IsVisible | ForEach-Object { $_.$PropertyName } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
      if ($Values.Count -eq 1) { $State.Metadata[$PropertyName] = $Values[0] }
    }
    if (@($AppsAndFeaturesInfo.AppsAndFeaturesEntryEvidence | Where-Object IsVisible).Count -gt 0) {
      $State.Metadata.WritesAppsAndFeaturesEntry = $true
    }
  }
  $State.Metadata.AppsAndFeaturesProductCode = if ($State.Metadata.WritesAppsAndFeaturesEntry) { $State.Metadata.ProductCode } else { $null }
  $State.Metadata.AppsAndFeaturesInstallerType = if ($State.Metadata.WritesAppsAndFeaturesEntry) { 'nullsoft' } else { $null }
  $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
  foreach ($Warning in @($RegistryAssociationInfo.Diagnostics)) { $State.Diagnostics.Add($Warning) }
  $State.Metadata.RegistryAssociationInfo = $RegistryAssociationInfo
  $State.Metadata.Protocols = $RegistryAssociationInfo.Protocols
  $State.Metadata.FileExtensions = $RegistryAssociationInfo.FileExtensions
  $State.Metadata.ExtractedFiles = @($ExtractedFiles)
  $State.Metadata.ConditionalExtractedFiles = @($State.ConditionalExtractedFiles)
  $State.Metadata.ExecutedPayloads = @($ExecutedPayloads)
  $State.Metadata.Diagnostics = @(
    Merge-InstallerDiagnostics -Diagnostic @(
      $State.Metadata.Diagnostics
      @(ConvertTo-InstallerDiagnostic -InputObject @($State.Diagnostics) -Source 'NSISSimulation' -Kind Incomplete -Areas Metadata -AffectedFields $State.Metadata.UnresolvedFields)
    )
  )
  $State.Metadata.UnresolvedFields = [string[]]@($State.Metadata.UnresolvedFields | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
  $State.VersionInfo | Add-Member -NotePropertyName UnresolvedFileSystemPredicates -NotePropertyValue ([string[]]@($State.UnknownFileSystemPredicates | Sort-Object)) -Force
  $State.VersionInfo | Add-Member -NotePropertyName UnresolvedProcessPredicates -NotePropertyValue ([string[]]@($State.UnknownProcessPredicates | Sort-Object)) -Force
  $State.VersionInfo | Add-Member -NotePropertyName BranchPredicates -NotePropertyValue ([string[]]@($State.BranchPredicates | Sort-Object)) -Force
  $State.VersionInfo | Add-Member -NotePropertyName ExploredBranchCount -NotePropertyValue ([int]$State.ExploredBranchCount) -Force
  $State.VersionInfo | Add-Member -NotePropertyName TruncatedBranchCount -NotePropertyValue ([int]$State.TruncatedBranchCount) -Force
  $State.Metadata.ParserVersionInfo = $State.VersionInfo

  return [pscustomobject]$State.Metadata
}

function Invoke-NSISStaticSimulation {
  <#
  .SYNOPSIS
    Simulate NSIS installer code paths needed for deterministic static metadata
  .PARAMETER Path
    The path to the NSIS installer
  .PARAMETER FormatContext
    A previously parsed catalog-selected context. Internal callers use this to avoid decoding the installer twice.
  .PARAMETER Mode
    The simulation mode. Full runs initialization and sections; Fast returns early when direct uninstall metadata is complete.
  .PARAMETER Architecture
    The target Windows architecture used to resolve compiled runtime architecture checks
  .PARAMETER Scope
    The target installation scope used to resolve compiled MultiUser scope setters
  .PARAMETER AnsiCodePage
    Explicit source code page for ANSI compiler output when language metadata is insufficient.
  .PARAMETER Environment
    Virtual target environment variables. Missing variables remain unresolved and never read the parser host.
  .PARAMETER CommandLine
    Virtual installer command line exposed through the NSIS $CMDLINE variable.
  .PARAMETER FileSystem
    Explicit virtual target filesystem facts keyed by Windows path.
  .PARAMETER FileSystemComplete
    Treat unlisted target paths as absent rather than unknown.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, ParameterSetName = 'Path', HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [Parameter(Mandatory, ParameterSetName = 'FormatContext', HelpMessage = 'The catalog-selected NSIS format context')]
    [pscustomobject]$FormatContext,

    [Parameter(HelpMessage = 'The simulation mode')]
    [ValidateSet('Full', 'Fast')]
    [string]$Mode = 'Full',

    [Parameter(HelpMessage = 'The target Windows architecture used to resolve runtime architecture checks')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [Parameter(HelpMessage = 'The target installation scope used to resolve runtime scope checks')]
    [ValidateSet('user', 'machine')]
    [string]$Scope,

    [hashtable]$Environment = @{},

    [AllowEmptyString()][string]$CommandLine = '',

    [hashtable]$FileSystem = @{},

    [switch]$FileSystemComplete,

    [ValidateRange(1, 65535)][int]$AnsiCodePage
  )

  process {
    # Parse and normalize the compiled header once; all later phases share the
    # same mutable state so callbacks and sections observe prior variable writes.
    if ($PSCmdlet.ParameterSetName -eq 'Path') { $FormatContext = Get-NSISFormatContext -Path $Path }
    $FormatInfo = ConvertTo-NSISFormatInfo -Context $FormatContext
    if (-not $FormatInfo.IsSupported) {
      throw "The NSIS command layout '$($FormatInfo.CatalogProfileId)' is structurally unsupported: $([string]::Join(' ', $FormatInfo.Diagnostics))"
    }
    $HeaderData = $FormatContext.HeaderData
    $InitializationArguments = @{ FormatContext = $FormatContext; FileSystem = $FileSystem }
    if ($FileSystemComplete) { $InitializationArguments.FileSystemComplete = $true }
    if (-not [string]::IsNullOrWhiteSpace($Architecture)) { $InitializationArguments.Architecture = $Architecture }
    if (-not [string]::IsNullOrWhiteSpace($Scope)) { $InitializationArguments.Scope = $Scope }
    if ($AnsiCodePage -gt 0) { $InitializationArguments.AnsiCodePage = $AnsiCodePage }
    $InitializedState = Initialize-NSISState @InitializationArguments
    $State = $InitializedState.State
    $State.Environment = @{} + $Environment
    # CreateProcess always exposes at least the executable path in $CMDLINE.
    # Preserve an explicitly supplied test command line, including an explicit
    # empty value, but otherwise model the quoted resolved installer path.
    $EffectiveCommandLine = if ($PSBoundParameters.ContainsKey('CommandLine')) {
      $CommandLine
    } else {
      '"' + [string]$HeaderData.Path + '"'
    }
    $State.CommandLine = $EffectiveCommandLine
    Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_CMDLINE -Value $EffectiveCommandLine
    $Parameters = Get-NSISCommandLineParameters -CommandLine $EffectiveCommandLine
    $State.ExecFlags[$Script:NSIS_EXEC_FLAG_SILENT] = [int]([regex]::IsMatch($Parameters, '(?:^|\s)/S(?:\s|$)', [Text.RegularExpressions.RegexOptions]::CultureInvariant))
    $InstallDirectoryOverride = Get-NSISCommandLineOption -Parameters $Parameters -Option '/D='
    if (-not [string]::IsNullOrWhiteSpace($InstallDirectoryOverride)) {
      # Stock NSIS accepts /D only as the final command-line argument and uses
      # it to replace the compiled directory before initialization callbacks.
      Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_INSTDIR -Value $InstallDirectoryOverride
    }
    $Layout = $InitializedState.Layout
    $ArchitectureProbeStart = Get-NSISArchitectureProbeStart -State $State
    $State.Metadata.HasArchitectureRuntimeCheck = $ArchitectureProbeStart -ge 0
    $ScopeSelectionStarts = [ordered]@{
      user    = Get-NSISScopeSelectionStart -State $State -Scope user
      machine = Get-NSISScopeSelectionStart -State $State -Scope machine
    }
    $RegistryPluginScopeVariables = @(Get-NSISRegistryPluginScopeVariable -State $State)
    $State.RegistryPluginScopeVariables = [int[]]$RegistryPluginScopeVariables
    $State.Metadata.SupportedScopes = [string[]]@(@(
        @($ScopeSelectionStarts.Keys | Where-Object { $ScopeSelectionStarts[$_] -ge 0 })
        if ($RegistryPluginScopeVariables.Count -gt 0) { 'user'; 'machine' }
      ) | Select-Object -Unique)
    $State.Metadata.HasScopeRuntimeCheck = $State.Metadata.SupportedScopes.Count -gt 0
    $ScopeSelectionStart = if (-not [string]::IsNullOrWhiteSpace($Scope)) { $ScopeSelectionStarts[$Scope] } else { -1 }
    $HasTargetArchitectureResolver = $ArchitectureProbeStart -ge 0 -and -not [string]::IsNullOrWhiteSpace($Architecture)
    $HasCompiledTargetScopeResolver = $ScopeSelectionStart -ge 0 -and -not [string]::IsNullOrWhiteSpace($Scope)
    $HasRegistryPluginTargetScopeResolver = $RegistryPluginScopeVariables.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($Scope)
    $HasTargetScopeResolver = $HasCompiledTargetScopeResolver -or $HasRegistryPluginTargetScopeResolver
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
        # Initialization can establish variables and scope used by every later
        # section. Retain partial evidence, but mark subsequent effects conditional.
        $InitializationCompleted = $false
        $State.Diagnostics.Add("The .onInit callback could not be simulated completely: $($_.Exception.Message)")
        $State.Metadata.UnresolvedFields = [string[]]@($State.Metadata.UnresolvedFields + 'Callback:.onInit' | Select-Object -Unique)
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
          $State.Diagnostics.Add("The source-backed architecture probe could not be simulated completely: $($_.Exception.Message)")
          $State.Metadata.UnresolvedFields = [string[]]@($State.Metadata.UnresolvedFields + 'Architecture' | Select-Object -Unique)
        }
      }
    }

    if ($HasTargetScopeResolver) {
      Initialize-NSISTargetRegistryState -State $State
    }
    if ($HasCompiledTargetScopeResolver) {
      # Enter the compiled scope setter directly after initialization. This
      # mirrors the deterministic MultiUser macro branch without emulating UAC,
      # account privilege checks, dialogs, or command-line parsing.
      Initialize-NSISScopeSelectionInput -State $State -Position $ScopeSelectionStart -Scope $Scope
      try {
        $null = Invoke-NSISCodeSegment -State $State -Position $ScopeSelectionStart
      } catch {
        $State.Diagnostics.Add("The compiled '$Scope' scope selector could not be simulated completely: $($_.Exception.Message)")
      }
    }
    if ($HasRegistryPluginTargetScopeResolver) {
      # Registry plug-in based installers can keep the hive in a script
      # variable rather than SHCTX. Select only variables proven to have both
      # HKCU and HKLM assignments and to feed an explicit uninstall _Write.
      Set-NSISRegistryPluginScope -State $State -VariableIndex $RegistryPluginScopeVariables -Scope $Scope
    }

    # Initialization commonly establishes SHCTX before install sections begin.
    # Replay explicit writes so their scope reflects that context instead of the
    # conservative pre-simulation fallback used by the first literal scan.
    if ($State.ShellVarContext -and -not $HasTargetScopeResolver) { Add-NSISDirectUninstallWrites -State $State }

    # Large generated installers can contain one extraction command per payload
    # file. Walking all commands adds no identity evidence once initialization
    # and explicit uninstall writes are complete, and can exceed the parser CLI
    # timeout. Keep Full as the normal behavior while bounding this path only
    # after deterministic ARP identity has been recovered.
    $InitializedMetadata = Complete-NSISMetadata -State $State -SkipLocalizedAppsAndFeaturesEntries
    if ($State.Entries.Count -gt $Script:NSIS_MAX_FULL_SIMULATION_ENTRY_COUNT -and
      -not [string]::IsNullOrWhiteSpace($InitializedMetadata.DisplayName) -and
      -not [string]::IsNullOrWhiteSpace($InitializedMetadata.DisplayVersion) -and
      -not [string]::IsNullOrWhiteSpace($InitializedMetadata.ProductCode)) {
      $State.InformationalDiagnosticMessages.Add("Full section simulation was skipped after deterministic uninstall metadata was recovered because the validated NSIS command table contains $($State.Entries.Count) entries.")
      return [pscustomobject]@{
        State           = $State
        Layout          = $Layout
        HeaderData      = $HeaderData
        Metadata        = Complete-NSISMetadata -State $State
        IsEarlyExit     = $true
        EarlyExitReason = 'LargeCommandTable'
      }
    }

    foreach ($Section in $State.Sections) {
      if ($Section.CodeOffset -lt 0) { continue }
      if ($State.HasComponentPage -and ($Section.Flags -band $Script:NSIS_SECTION_FLAG_SELECTED) -eq 0) { continue }

      # Component-page stubs execute selected sections only; feature-stripped
      # stubs compile the selection guard out and execute every section.
      try {
        $Result = Invoke-NSISCodeSegment -State $State -Position $Section.CodeOffset
      } catch {
        $State.Diagnostics.Add("NSIS section $($Section.Index) could not be simulated completely: $($_.Exception.Message)")
        $State.Metadata.UnresolvedFields = [string[]]@($State.Metadata.UnresolvedFields + "Section:$($Section.Index)" | Select-Object -Unique)
        continue
      }
      if ($Result -eq 'Quit') { break }
    }

    if ($Layout.CodeOnInstSuccess -ge 0) {
      try {
        $null = Invoke-NSISCodeSegment -State $State -Position $Layout.CodeOnInstSuccess
      } catch {
        $State.Diagnostics.Add("The .onInstSuccess callback could not be simulated completely: $($_.Exception.Message)")
        $State.Metadata.UnresolvedFields = [string[]]@($State.Metadata.UnresolvedFields + 'Callback:.onInstSuccess' | Select-Object -Unique)
      }
    }

    if ($HasTargetArchitectureResolver -or $HasTargetScopeResolver) {
      # A selected architecture branch or an electron-builder custom scope hook
      # can stop the bounded simulator before every uninstall value is reached.
      # Reconcile one identity in the caller-requested hive idempotently; stable
      # values are deduplicated and only missing dynamic values stay unresolved.
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
  $Encoding = if ($State.VersionInfo.Unicode) { [System.Text.Encoding]::Unicode } else { $State.AnsiEncoding }
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
      InstallerType              = 'nullsoft'
      Family                     = 'NSIS/Nullsoft'
      IsTauri                    = $TauriInfo.IsTauri
      TauriInstallerMode         = $TauriInfo.InstallerMode
      Switches                   = $Switches.ToArray()
      TauriSwitches              = @($Switches | Where-Object { $_.IsTauriSwitch })
      AdditionalSwitches         = $AdditionalSwitches
      ScopeSwitches              = @($Switches | Where-Object { $_.IsScopeSwitch } | Select-Object -ExpandProperty Switch)
      SilentSwitches             = @($Switches | Where-Object { $_.IsSilentSwitch } | Select-Object -ExpandProperty Switch)
      CommandLineParsingEvidence = $ParsingMarkers
      RejectedSwitchCandidates   = $RejectedSwitches.ToArray()
      Diagnostics                = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings.ToArray()) -Source 'NSISSimulation' -Kind Incomplete -Areas Metadata)
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
      InstallerType          = 'exe'
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
