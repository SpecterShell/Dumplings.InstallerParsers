# SPDX-License-Identifier: GPL-3.0-or-later
# Format sources: historical Indigo Rose media, https://github.com/fragglet/lhasa, https://github.com/CybercentreCanada/sfextract, https://github.com/Puyodead1/SFUnpacker, https://codeberg.org/CYBERDEV/defactory, and https://github.com/madler/zlib
# Setup Factory 3.1-10 static parser. Setup Factory 3.1 structures were independently derived from historical media and its Crusher archive behavior was implemented from Lhasa's ISC-licensed LH5 decoder. Later format details are derived from sfextract (MIT), SFUnpacker (LGPL-3.0-or-later), and defactory (GPL-3.0-or-later); see Assets/THIRD-PARTY-NOTICES.md.
#
# Binary structure consumed by this parser (overlay-relative, LE integers):
#
#   Setup Factory 3.1 multi-file media
#   +-- SETUP.EXE: 16-bit MZ/NE launcher
#   +-- IRDATA.IRD: Crusher ARQ records
#   |   `-- [magic:4][version:u16][name length:u16][name][descriptor:33][payload]
#   |       +-- IRDATA.DAT: product and installed-file catalogs
#   |       +-- IRSETUP.EXE: setup runtime
#   |       `-- IRUNIN31.EXE: uninstaller runtime
#   `-- *.??_: independently compressed installed-file streams
#
#   Setup Factory 4-10 PE overlay
#   +-- v4: E0..E6, count:u8, 16-byte names
#   +-- v5/v6: E0..E7, count:u32, 16/260-byte names
#   +-- v7: E0..E7, runtime-size:u32, 260-byte names
#   `-- v8-10: doubled E0..E7, runtime-size:i64, 264-byte names
#       -> repeated [name][packed size][CRC32][compressed outer bytes]
#       -> optional CDependencyFile payloads
#       -> CFileInfo/CSetupFileData application payload streams
#
#   irsetup.dat (MFC serialization in versions 4-6)
#   +-- product and generated-uninstaller objects
#   +-- [count:u16][FFFF][schema:u16][class name][records...]
#   |   +-- v4: CRegistryData, CINIData
#   |   +-- v5: CRegistryData, CExecuteData, CFileOpData, CINIData, CVarRegistry
#   |   `-- v6: generic CAction lists
#   `-- nested CConditionData lists; class tags can reference an earlier archive-global declaration
#
# Only the first 2,000 irsetup.exe bytes are XORed with 07. File records use the
# supported bounded compression framing. irsetup.dat supplies structured
# session variables, uninstall settings, installed-file records, and literal
# Lua registry evidence. Setup Factory 10 adds one reserved byte before each
# installed-file compression flag; structurally validated candidate layouts
# keep that revision separate from the common outer container.

# Apply default function parameters

# SetupFactory Public layer. Internal modules are imported locally; public commands stay in the facade.
Import-Module (Join-Path $PSScriptRoot 'SetupFactoryContainer.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'SetupFactoryProject.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'SetupFactoryActions.psm1') -ErrorAction Stop

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

Set-StrictMode -Version 3.0

$Script:SetupFactoryMaximumFileBytes = 1073741824

$Script:SetupFactoryMaximumExpandedBytes = 17179869184

function Expand-SetupFactoryInstaller {
  <#
  .SYNOPSIS
    Expand a Setup Factory 3.1-10 installer without executing it
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select installed paths, or outer record names with RawEntries.
  .PARAMETER RawEntries
    Extract outer bootstrap records such as irsetup.exe and irsetup.dat plus separately framed bundled prerequisite payloads instead of installed application files.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or multiple records resolve to the same path.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [switch]$RawEntries,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = $Script:SetupFactoryMaximumExpandedBytes
  )
  process {
    $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ('Dumplings-SetupFactory-' + [guid]::NewGuid().ToString('N'))
    }
    if ($File.Name -ieq 'IRDATA.IRD' -or ($File.Name -ieq 'SETUP.EXE' -and (Test-Path -LiteralPath (Join-Path $File.Directory.FullName 'IRDATA.IRD') -PathType Leaf))) {
      $Media = Get-SetupFactory31Media -Path $File.FullName
      Expand-SetupFactory31Media -Media $Media -DestinationPath $DestinationPath -Name $Name -RawEntries:$RawEntries -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes
      return
    }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -ItemType Directory -Path $DestinationPath -Force
    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    $Written = 0L
    try {
      $Catalog = Get-SetupFactoryArchiveCatalog -Path $File.FullName -Stream $Stream
      if ($RawEntries) {
        # Raw mode includes the bootstrap catalog and any separately framed bundled
        # prerequisites. Decode irsetup.dat only to locate those physical records;
        # malformed prerequisite metadata must not hide otherwise valid outer entries.
        $Entries = [Collections.Generic.List[object]]::new()
        foreach ($Entry in $Catalog.Entries) { $Entries.Add($Entry) }
        $ScriptEntries = @($Catalog.Entries | Where-Object Name -CEQ 'irsetup.dat')
        if ($ScriptEntries.Count -eq 1) {
          $ScriptBytes = Read-SetupFactoryCatalogEntryData -Stream $Stream -Entry $ScriptEntries[0] -MaximumBytes $Script:SetupFactoryMaximumFileBytes
          $DependencyCatalog = Get-SetupFactoryDependencyFileCatalog -Bytes $ScriptBytes -PayloadDataOffset $Catalog.PayloadDataOffset -FileLength $Catalog.FileLength
          if ($DependencyCatalog.IsComplete) {
            foreach ($Entry in $DependencyCatalog.Entries) { $Entries.Add($Entry) }
          }
        }
        $Entries = $Entries.ToArray()
      } else {
        $ScriptEntries = @($Catalog.Entries | Where-Object Name -CEQ 'irsetup.dat')
        if ($ScriptEntries.Count -ne 1) { throw "The Setup Factory catalog contains $($ScriptEntries.Count) irsetup.dat entries; exactly one is required" }
        $ScriptBytes = Read-SetupFactoryCatalogEntryData -Stream $Stream -Entry $ScriptEntries[0] -MaximumBytes $Script:SetupFactoryMaximumFileBytes
        $Variables = if ($Catalog.Overlay.MetadataRoute -in 'irdat-v5', 'irdat-v6') {
          try { (Get-SetupFactoryLegacyMetadata -Bytes $ScriptBytes).Variables } catch { @{} }
        } elseif ($Catalog.Overlay.SupportsMetadata) {
          Get-SetupFactorySessionVariable -Bytes $ScriptBytes
        } else {
          @{}
        }
        $DependencyCatalog = Get-SetupFactoryDependencyFileCatalog -Bytes $ScriptBytes -PayloadDataOffset $Catalog.PayloadDataOffset -FileLength $Catalog.FileLength
        if (-not $DependencyCatalog.IsComplete) { throw "The Setup Factory dependency-file table could not be decoded: $($DependencyCatalog.Error)" }
        $InstalledCatalog = Get-SetupFactoryInstalledFileCatalog -Bytes $ScriptBytes -Catalog $Catalog -Variables $Variables -PayloadDataOffset $DependencyCatalog.PayloadDataEndOffset
        if (-not $InstalledCatalog.IsComplete) { throw "The Setup Factory installed-file table could not be decoded: $($InstalledCatalog.Error)" }
        $Entries = $InstalledCatalog.Entries
      }

      $SelectedEntries = @($Entries | Where-Object { Test-ExtractionPattern -Path $_.Name -Pattern $Name })
      if (-not $RawEntries) {
        $UnavailableEntries = @($SelectedEntries | Where-Object { -not $_.IsEmbedded -or $null -eq $_.DataOffset })
        if ($UnavailableEntries.Count) { throw "The Setup Factory media does not contain a proven physical payload range for $($UnavailableEntries.Count) selected installed file(s), beginning with '$($UnavailableEntries[0].Name)'" }
      }
      foreach ($Entry in $SelectedEntries) {
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Entry.Name `
          -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if (-not $Target.ShouldWrite) { continue }
        $Remaining = [Math]::Min($MaximumExpandedBytes - $Written, $Script:SetupFactoryMaximumFileBytes)
        if ($Remaining -le 0) { throw 'The Setup Factory expansion exceeds the configured limit' }
        $Expanded = if ($RawEntries) {
          if ($Entry.Kind -eq 'DependencyPayload') { Read-SetupFactoryInstalledFileData -Stream $Stream -Entry $Entry -MaximumBytes $Remaining }
          else { Read-SetupFactoryCatalogEntryData -Stream $Stream -Entry $Entry -MaximumBytes $Remaining }
        } else {
          Read-SetupFactoryInstalledFileData -Stream $Stream -Entry $Entry -MaximumBytes $Remaining
        }
        $Written += $Expanded.LongLength
        if ($Written -gt $MaximumExpandedBytes) { throw 'The Setup Factory expansion exceeds the configured limit' }
        $Parent = [IO.Path]::GetDirectoryName($Target.Path)
        if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
        [IO.File]::WriteAllBytes($Target.Path, $Expanded)
        Get-Item -LiteralPath $Target.Path
      }
    } finally {
      $Stream.Dispose()
    }
  }
}

function Get-SetupFactoryArpEntry {
  <#
  .SYNOPSIS
    Project literal uninstall-key writes into ARP entry evidence.
  .PARAMETER RegistryWrite
    Literal Setup Factory registry writes recovered from irsetup.dat.
  .PARAMETER Variables
    Session-variable map used to resolve key paths and values.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RegistryWrite,
    [Parameter(Mandatory)][hashtable]$Variables
  )

  $Entries = [ordered]@{}
  foreach ($Write in $RegistryWrite) {
    # HKCR is valid association evidence but cannot own an Add/Remove Programs
    # registration. Only HKLM and HKCU map to Win32 uninstall roots.
    if ($Write.Root -notmatch '^(?:HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER)$') { continue }
    $Key = Resolve-SetupFactoryVariable -Value ([string]$Write.Key) -Variables $Variables
    if (-not $Key) { continue }
    $Match = [regex]::Match($Key, '(?i)^Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\(?<code>[^\\]+)$')
    if (-not $Match.Success) { continue }

    $Identity = "$(($Write.Root -replace '^HKEY_LOCAL_MACHINE$', 'HKLM' -replace '^HKEY_CURRENT_USER$', 'HKCU').ToUpperInvariant())\$Key"
    if (-not $Entries.Contains($Identity)) {
      $Entries[$Identity] = [ordered]@{
        RegistryIdentity     = $Identity
        Root                 = $Write.Root
        Key                  = $Key
        ProductCode          = $Match.Groups['code'].Value
        DisplayName          = $null
        DisplayVersion       = $null
        Publisher            = $null
        InstallLocation      = $null
        DisplayIcon          = $null
        UninstallString      = $null
        QuietUninstallString = $null
        SystemComponent      = 0
      }
    }
    $Entry = $Entries[$Identity]
    $Value = Resolve-SetupFactoryVariable -Value ([string]$Write.Value) -Variables $Variables
    switch -Regex ([string]$Write.Name) {
      '^DisplayName$' { $Entry.DisplayName = $Value }
      '^DisplayVersion$' { $Entry.DisplayVersion = $Value }
      '^Publisher$' { $Entry.Publisher = $Value }
      '^InstallLocation$' { $Entry.InstallLocation = $Value }
      '^DisplayIcon$' { $Entry.DisplayIcon = $Value }
      '^UninstallString$' { $Entry.UninstallString = $Value }
      '^QuietUninstallString$' { $Entry.QuietUninstallString = $Value }
      '^SystemComponent$' { $Entry.SystemComponent = if ($Value -match '^\d+$') { [int]$Value } else { $Value } }
    }
  }

  foreach ($Entry in $Entries.Values) {
    [pscustomobject][ordered]@{
      RegistryIdentity     = $Entry.RegistryIdentity
      Root                 = $Entry.Root
      Key                  = $Entry.Key
      ProductCode          = $Entry.ProductCode
      DisplayName          = $Entry.DisplayName
      DisplayVersion       = $Entry.DisplayVersion
      Publisher            = $Entry.Publisher
      InstallLocation      = $Entry.InstallLocation
      DisplayIcon          = $Entry.DisplayIcon
      UninstallString      = $Entry.UninstallString
      QuietUninstallString = $Entry.QuietUninstallString
      SystemComponent      = $Entry.SystemComponent
      Scope                = $Entry.Root -match '^(?:HKCU|HKEY_CURRENT_USER)$' ? 'user' : 'machine'
      IsVisible            = $Entry.SystemComponent -ne 1 -and -not [string]::IsNullOrWhiteSpace($Entry.DisplayName)
    }
  }
}

function Get-SetupFactoryInfo {
  <#
  .SYNOPSIS
    Read structured Setup Factory product and ARP metadata
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force
    if ($File.Name -ieq 'IRDATA.IRD' -or ($File.Name -ieq 'SETUP.EXE' -and (Test-Path -LiteralPath (Join-Path $File.Directory.FullName 'IRDATA.IRD') -PathType Leaf))) {
      return Get-SetupFactory31Info -Path $File.FullName
    }
    $ScriptStream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    try {
      $Catalog = Get-SetupFactoryArchiveCatalog -Path $File.FullName -Stream $ScriptStream
      $Overlay = $Catalog.Overlay
      $EmbeddedRuntimeInfo = Get-SetupFactoryEmbeddedRuntimeInfo -Stream $ScriptStream -Catalog $Catalog
      $ScriptEntries = @($Catalog.Entries | Where-Object Name -CEQ 'irsetup.dat')
      if ($ScriptEntries.Count -ne 1) { throw "The Setup Factory catalog contains $($ScriptEntries.Count) irsetup.dat entries; exactly one is required" }
      # Metadata analysis decodes only irsetup.dat. It no longer writes a
      # temporary extraction tree or returns paths that disappear after cleanup.
      $Bytes = Read-SetupFactoryCatalogEntryData -Stream $ScriptStream -Entry $ScriptEntries[0] -MaximumBytes $Script:SetupFactoryMaximumFileBytes
    } finally {
      $ScriptStream.Dispose()
    }

    $Diagnostics = [Collections.Generic.List[object]]::new()
    $UnresolvedFields = [Collections.Generic.List[string]]::new()
    $SilentInstallationInfo = Get-SetupFactorySilentInstallationInfo -Bytes $Bytes -MetadataRoute $Overlay.MetadataRoute
    if ($SilentInstallationInfo.IsResolved) {
      if (-not $SilentInstallationInfo.SupportsSilentInstallation) {
        $EvidenceReason = $SilentInstallationInfo.Evidence.PSObject.Properties['Reason']
        if ($EvidenceReason -and $EvidenceReason.Value -ceq 'GenerationPredatesSilentMode') {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.SilentUnsupportedByGeneration' -Source 'SetupFactory' -Message 'This Setup Factory generation predates the /S silent-installation feature and is interactive-only.' -Kind Unsupported -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $SilentInstallationInfo.Evidence))
        } else {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.SilentDisabled' -Source 'SetupFactory' -Message 'The compiled Setup Factory project disables silent installation, so the documented /S switch is not valid for this artifact.' -Kind Unsupported -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $SilentInstallationInfo.Evidence))
        }
      }
    } else {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.SilentSupportUnresolved' -Source 'SetupFactory' -Message 'The compiled Setup Factory silent-installation setting could not be resolved for this structural generation; do not infer /S support from runtime strings alone.' -Kind Incomplete -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $SilentInstallationInfo.Evidence))
      $UnresolvedFields.Add('InstallerSwitches')
      $UnresolvedFields.Add('InstallModes')
    }
    if (-not $EmbeddedRuntimeInfo.IsReadable) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Release.EmbeddedRuntimeUnreadable' -Source 'SetupFactory' -Message "The embedded Setup Factory runtime could not be used as release evidence: $($EmbeddedRuntimeInfo.Error)" -Kind Incomplete -Areas Detection -Evidence ([ordered]@{ ProfileId = $Overlay.ProfileId; Error = $EmbeddedRuntimeInfo.Error })))
    } elseif (-not $EmbeddedRuntimeInfo.IsTrusted) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Release.EmbeddedRuntimeIdentityUnrecognized' -Source 'SetupFactory' -Message 'The embedded runtime is a valid PE image, but its version-resource identity does not match a catalogued Setup Factory generation.' -Kind Ambiguous -Areas Detection -Evidence $EmbeddedRuntimeInfo))
    } elseif (-not $EmbeddedRuntimeInfo.IsProfileCompatible) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Release.StructuralProfileMismatch' -Source 'SetupFactory' -Message "The embedded Setup Factory $($EmbeddedRuntimeInfo.Version) runtime identifies a different release family than the structurally validated '$($Overlay.ProfileId)' container." -Kind Mismatch -Areas Detection -Evidence $EmbeddedRuntimeInfo))
    }
    if ($Overlay.BuilderVersion -and $EmbeddedRuntimeInfo.IsTrusted -and $Overlay.Version -ne $EmbeddedRuntimeInfo.MajorVersion) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Release.MajorVersionConflict' -Source 'SetupFactory' -Message "Trusted outer runtime version '$($Overlay.BuilderVersion)' and embedded runtime version '$($EmbeddedRuntimeInfo.Version)' identify different Setup Factory major releases." -Kind Mismatch -Areas Detection -Evidence ([ordered]@{ OuterVersion = $Overlay.BuilderVersion; EmbeddedVersion = $EmbeddedRuntimeInfo.Version })))
    }
    # Resolve product variables through the generation-specific metadata route. Versions 5 and 6
    # use fixed object blocks; versions 7 and later use CSessionVar records.
    $LegacyMetadata = $null
    $LegacyMetadataError = $null
    if ($Overlay.MetadataRoute -eq 'irdat-v4') {
      try {
        $LegacyMetadata = Read-SetupFactoryClassic4Metadata -Bytes $Bytes
        $Variables = $LegacyMetadata.Variables
      } catch {
        $LegacyMetadataError = $_.Exception.Message
        $Variables = @{}
      }
    } elseif ($Overlay.MetadataRoute -in 'irdat-v5', 'irdat-v6') {
      try {
        $LegacyMetadata = Get-SetupFactoryLegacyMetadata -Bytes $Bytes
        $Variables = $LegacyMetadata.Variables
      } catch {
        $LegacyMetadataError = $_.Exception.Message
        $Variables = @{}
      }
    } elseif ($Overlay.SupportsMetadata) {
      $Variables = Get-SetupFactorySessionVariable -Bytes $Bytes
    } else {
      $Variables = @{}
    }
    $DependencyCatalog = Get-SetupFactoryDependencyFileCatalog -Bytes $Bytes -PayloadDataOffset $Catalog.PayloadDataOffset -FileLength $Catalog.FileLength
    $InstalledPayloadOffset = $DependencyCatalog.IsComplete ? $DependencyCatalog.PayloadDataEndOffset : $Catalog.PayloadDataOffset
    $InstalledCatalog = Get-SetupFactoryInstalledFileCatalog -Bytes $Bytes -Catalog $Catalog -Variables $Variables -PayloadDataOffset $InstalledPayloadOffset
    if (-not $DependencyCatalog.IsComplete) { $InstalledCatalog.CanExtract = $false }
    $FilePolicySummary = Get-SetupFactoryFilePolicySummary -Entry $InstalledCatalog.Entries
    $Resolve = { param($Name) if ($Variables.ContainsKey($Name)) { Resolve-SetupFactoryVariable -Value ([string]$Variables[$Name]) -Variables $Variables } }
    $DisplayName = & $Resolve '%ProductName%'
    $DisplayVersion = & $Resolve '%ProductVer%'
    $Publisher = & $Resolve '%CompanyName%'
    $InstallLocation = & $Resolve '%AppFolder%'
    # Custom registry writes can supersede built-in uninstall behavior and also provide
    # protocol/file-association evidence. Each legacy generation has a distinct object model;
    # modern media stores literal Lua Registry.SetValue calls instead.
    $UnresolvedRegistryCallCount = 0
    $LegacyActionCatalog = $null
    if ($LegacyMetadata -and $Overlay.MetadataRoute -eq 'irdat-v4') {
      $LegacyActionCatalog = Get-SetupFactoryActionCatalog4 -Bytes $Bytes -UninstallOffset $LegacyMetadata.Uninstall.Offset
      [object[]]$RegistryWrites = @($LegacyActionCatalog.RegistryWrites)
      $UnresolvedRegistryCallCount = $LegacyActionCatalog.UnresolvedCount
    } elseif ($LegacyMetadata -and $Overlay.MetadataRoute -eq 'irdat-v5') {
      $LegacyActionCatalog = Get-SetupFactoryActionCatalog5 -Bytes $Bytes -UninstallOffset $LegacyMetadata.Uninstall.Offset
      [object[]]$RegistryWrites = @($LegacyActionCatalog.RegistryWrites)
      $UnresolvedRegistryCallCount = $LegacyActionCatalog.UnresolvedCount
    } elseif ($LegacyMetadata -and $Overlay.MetadataRoute -eq 'irdat-v6') {
      $LegacyActionCatalog = Get-SetupFactoryActionCatalog6 -Bytes $Bytes -UninstallOffset $LegacyMetadata.Uninstall.Offset
      [object[]]$RegistryWrites = @($LegacyActionCatalog.RegistryWrites)
      $UnresolvedRegistryCallCount = $LegacyActionCatalog.UnresolvedCount
    } elseif ($Overlay.MetadataRoute -in 'irdat-v7', 'irdat-v8-plus') {
      [object[]]$RegistryWrites = @(Get-SetupFactoryLiteralRegistryWrite -Bytes $Bytes -UnresolvedCount ([ref]$UnresolvedRegistryCallCount))
    } else {
      [object[]]$RegistryWrites = @()
    }
    $ActionEffects = [pscustomobject][ordered]@{
      VariableAssignments    = @()
      ExecutionActions       = @()
      FileSystemActions      = @()
      IniActions             = @()
      VariableReads          = @()
      UserInteractionActions = @()
      InstallabilityActions  = @()
      ShortcutActions        = @()
      ServiceActions         = @()
      RebootActions          = @()
      ExternalCodeActions    = @()
      UnknownActions         = @()
    }
    if ($LegacyActionCatalog -and $Overlay.MetadataRoute -in 'irdat-v4', 'irdat-v5', 'irdat-v6') {
      foreach ($PropertyName in $ActionEffects.PSObject.Properties.Name) {
        $CatalogProperty = $LegacyActionCatalog.PSObject.Properties[$PropertyName]
        if ($CatalogProperty) { $ActionEffects.$PropertyName = [object[]]@($CatalogProperty.Value) }
      }
    }
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    $RegistryArpEntries = @(Get-SetupFactoryArpEntry -RegistryWrite $RegistryWrites -Variables $Variables)
    $VisibleRegistryArpEntries = @($RegistryArpEntries | Where-Object IsVisible)

    if ($LegacyMetadata) {
      # Legacy media stores the Control Panel description and unique uninstall key explicitly.
      # A disabled uninstaller retains these defaults in the project, so the enable byte gates ARP.
      $HasBuiltInUninstall = [bool]$LegacyMetadata.Uninstall.IncludeUninstall
      $BuiltInProductCode = if ($HasBuiltInUninstall) { Resolve-SetupFactoryVariable -Value $LegacyMetadata.Uninstall.UniqueRegistryKey -Variables $Variables }
      if ($HasBuiltInUninstall) {
        $LegacyArpDisplayName = Resolve-SetupFactoryVariable -Value $LegacyMetadata.Uninstall.ControlPanelDescription -Variables $Variables
        if ($LegacyArpDisplayName) { $DisplayName = $LegacyArpDisplayName }
      }
    } else {
      $ProductExpression = '%ProductName%%ProductVer%'
      $ExpressionBytes = [Text.Encoding]::UTF8.GetBytes($ProductExpression)
      # The modern built-in uninstaller composes its ARP key from ProductName and ProductVer.
      # Require that exact structured expression before returning the resolved ProductCode.
      $HasBuiltInUninstall = $Overlay.SupportsMetadata -and @(Find-BinaryPattern -Bytes $Bytes -Pattern $ExpressionBytes -Maximum 1).Count -gt 0
      $BuiltInProductCode = if ($HasBuiltInUninstall) { Resolve-SetupFactoryVariable -Value $ProductExpression -Variables $Variables }
    }

    # An explicit uninstall-key record is more precise than the built-in defaults.
    # Multiple visible keys remain entry evidence but do not collapse into one ProductCode.
    $PrimaryArp = $VisibleRegistryArpEntries.Count -eq 1 ? $VisibleRegistryArpEntries[0] : $null
    $ProductCode = $PrimaryArp ? $PrimaryArp.ProductCode : $BuiltInProductCode
    if ($PrimaryArp) {
      if ($PrimaryArp.DisplayName) { $DisplayName = $PrimaryArp.DisplayName }
      if ($PrimaryArp.DisplayVersion) { $DisplayVersion = $PrimaryArp.DisplayVersion }
      if ($PrimaryArp.Publisher) { $Publisher = $PrimaryArp.Publisher }
      if ($PrimaryArp.InstallLocation) { $InstallLocation = $PrimaryArp.InstallLocation }
    }

    $RegistryArpScopes = @($VisibleRegistryArpEntries | ForEach-Object { $_.Scope } | Sort-Object -Unique)
    $Scope = if ($RegistryArpScopes.Count -eq 1) { $RegistryArpScopes[0] }
    elseif ($RegistryArpScopes.Count -gt 1) { $null }
    elseif ($InstallLocation -match '^(?:%ProgramFiles|[A-Za-z]:\\Program Files(?: \(x86\))?\\)') { 'machine' }
    else { $null }

    if (-not $Overlay.SupportsMetadata) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.LegacyIrsetupDatPartial' -Source 'SetupFactory' -Message "The $($Overlay.FormatGeneration) outer catalog is supported, but its generation-specific irsetup.dat object tables are not yet decoded; metadata remains incomplete." -Kind Unsupported -Areas Metadata -AffectedFields DisplayName, DisplayVersion, Publisher, ProductCode, Scope, DefaultInstallLocation, AppsAndFeaturesEntries))
      foreach ($Field in 'DisplayName', 'DisplayVersion', 'Publisher', 'ProductCode', 'Scope', 'DefaultInstallLocation', 'AppsAndFeaturesEntries') { $UnresolvedFields.Add($Field) }
    } elseif ($LegacyMetadataError) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.LegacyProductBlockIncomplete' -Source 'SetupFactory' -Message "The Setup Factory legacy product or uninstall block could not be decoded: $LegacyMetadataError" -Kind Incomplete -Areas Metadata -AffectedFields DisplayName, DisplayVersion, Publisher, ProductCode, Scope, DefaultInstallLocation, AppsAndFeaturesEntries -Evidence ([ordered]@{ MetadataRoute = $Overlay.MetadataRoute })))
      foreach ($Field in 'DisplayName', 'DisplayVersion', 'Publisher', 'ProductCode', 'Scope', 'DefaultInstallLocation', 'AppsAndFeaturesEntries') { $UnresolvedFields.Add($Field) }
    } elseif ($Overlay.MetadataRoute -eq 'irdat-v4') {
      # Version 4 predates CSessionVar. Its global objects expose the built-in uninstall identity,
      # but do not carry the later product version, publisher, or destination variables.
      $Classic4AffectedFields = [Collections.Generic.List[string]]::new()
      foreach ($Field in 'DisplayVersion', 'Publisher', 'DefaultInstallLocation') {
        $Classic4AffectedFields.Add($Field)
        $UnresolvedFields.Add($Field)
      }
      if ([string]::IsNullOrWhiteSpace([string]$DisplayName)) {
        $Classic4AffectedFields.Add('DisplayName')
        $UnresolvedFields.Add('DisplayName')
      }
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.Classic4ProductFieldsUnavailable' -Source 'SetupFactory' -Message 'Setup Factory 4 global objects expose built-in uninstall identity but do not contain the later product version, publisher, or installation-directory variables.' -Kind Incomplete -Areas Metadata -AffectedFields $Classic4AffectedFields.ToArray() -Evidence ([ordered]@{ MetadataProfile = $LegacyMetadata.MetadataProfile })))
    } elseif (-not $Variables.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.SessionVariablesUnavailable' -Source 'SetupFactory' -Message 'CSessionVar records were not found or were malformed.' -Kind Incomplete -Areas Metadata -AffectedFields DisplayName, DisplayVersion, Publisher, DefaultInstallLocation))
      foreach ($Field in 'DisplayName', 'DisplayVersion', 'Publisher', 'DefaultInstallLocation') { $UnresolvedFields.Add($Field) }
    }
    if ($LegacyActionCatalog) {
      $RegistryCatalogProperty = $LegacyActionCatalog.PSObject.Properties['RegistryCatalog']
      if ($RegistryCatalogProperty -and -not $RegistryCatalogProperty.Value.IsComplete) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.LegacyRegistryActionsPartial' -Source 'SetupFactory' -Message "The Setup Factory legacy registry table was only partially decoded: $($RegistryCatalogProperty.Value.Error)" -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, Scope, AppsAndFeaturesEntries, Protocols, FileExtensions -Evidence ([ordered]@{ MetadataRoute = $Overlay.MetadataRoute; ParsedEntryCount = @($RegistryCatalogProperty.Value.Entries).Count })))
        $UnresolvedFields.Add('RegistryActions')
      }
      if (-not $LegacyActionCatalog.IsComplete) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.LegacyActionsPartial' -Source 'SetupFactory' -Message "One or more Setup Factory legacy command tables were only partially decoded: $($LegacyActionCatalog.Error)" -Kind Incomplete -Areas Metadata, Installability -AffectedFields InstallationMetadata, InstallerSwitches, InstallModes -Evidence ([ordered]@{ MetadataRoute = $Overlay.MetadataRoute; ParsedEntryCount = @($LegacyActionCatalog.Entries).Count })))
        $UnresolvedFields.Add('InstallationMetadata.Actions')
      }
    }
    if ($Overlay.MetadataRoute -in 'irdat-v4', 'irdat-v5', 'irdat-v6' -and $LegacyActionCatalog) {
      $ActiveExecutionActions = @($ActionEffects.ExecutionActions | Where-Object { $_.Phase -ne 'Uninstall' -and $_.ConditionState -ne 'False' })
      $ActiveInteractionActions = @($ActionEffects.UserInteractionActions | Where-Object { $_.Phase -ne 'Uninstall' -and $_.ConditionState -ne 'False' })
      $ActiveInstallabilityActions = @($ActionEffects.InstallabilityActions | Where-Object { $_.Phase -ne 'Uninstall' -and $_.ConditionState -ne 'False' })
      $ActiveRebootActions = @($ActionEffects.RebootActions | Where-Object { $_.Phase -ne 'Uninstall' -and $_.ConditionState -ne 'False' })
      $ActiveExternalCodeActions = @($ActionEffects.ExternalCodeActions | Where-Object { $_.Phase -ne 'Uninstall' -and $_.ConditionState -ne 'False' })
      $SilentModeAssignments = @($ActionEffects.VariableAssignments | Where-Object { $_.Phase -ne 'Uninstall' -and $_.ConditionState -ne 'False' -and $_.Details.VariableName -ieq '%SilentMode%' })

      if ($Overlay.MetadataRoute -eq 'irdat-v6' -and $SilentModeAssignments.Count) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.SilentModeAction' -Source 'SetupFactory' -Message 'A Setup Factory 6 action assigns %SilentMode% during installation. The assignment can override both the project default and the /S command-line request.' -Kind ManualValidation -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $SilentModeAssignments))
        $UnresolvedFields.Add('InstallerSwitches')
        $UnresolvedFields.Add('InstallModes')
      }
      if ($ActiveExecutionActions.Count) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.ExecutionActions' -Source 'SetupFactory' -Message 'Setup Factory actions can execute or open another file during installation or shutdown. Review their condition, arguments, and payload ownership before treating /S as fully unattended.' -Kind ManualValidation -Areas Metadata, Installability -AffectedFields Dependencies, InstallerSwitches, InstallModes -Evidence $ActiveExecutionActions))
        $UnresolvedFields.Add('Dependencies')
      }
      if ($ActiveInteractionActions.Count) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.UserInteractionActions' -Source 'SetupFactory' -Message 'Setup Factory contains a message or Yes/No action on a reachable or runtime-dependent installation path.' -Kind ManualValidation -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $ActiveInteractionActions))
        $UnresolvedFields.Add('InstallerSwitches')
        $UnresolvedFields.Add('InstallModes')
      }
      if ($ActiveInstallabilityActions.Count) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.RuntimeActions' -Source 'SetupFactory' -Message 'Setup Factory contains process-closing, abort, or connectivity actions whose runtime outcome can change whether installation completes.' -Kind ManualValidation -Areas Installability -AffectedFields InstallerSwitches, InstallModes, InstallerSuccessCodes -Evidence $ActiveInstallabilityActions))
        $UnresolvedFields.Add('InstallerSuccessCodes')
      }
      if ($ActiveRebootActions.Count) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.RebootActions' -Source 'SetupFactory' -Message 'Setup Factory schedules file operations or execution for reboot; restart behavior and return-code mapping require VM validation.' -Kind Risk -Areas Installability -AffectedFields ExpectedReturnCodes -Evidence $ActiveRebootActions))
        $UnresolvedFields.Add('ExpectedReturnCodes')
      }
      if ($ActiveExternalCodeActions.Count) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.ExternalCodeActions' -Source 'SetupFactory' -Message 'Setup Factory calls an external DLL function. Its registry, filesystem, prerequisite, and installability effects cannot be derived from the CAction record alone.' -Kind ManualValidation -Areas Metadata, Installability, Security -AffectedFields ProductCode, Scope, AppsAndFeaturesEntries, Protocols, FileExtensions, Dependencies, InstallerSwitches, InstallModes -Evidence $ActiveExternalCodeActions))
        foreach ($Field in 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions', 'Dependencies') { $UnresolvedFields.Add($Field) }
      }
      if ($ActionEffects.UnknownActions.Count) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.UnknownActionIds' -Source 'SetupFactory' -Message 'A Setup Factory command table contains action IDs absent from the source-backed vocabulary for that generation.' -Kind Unsupported -Areas Metadata, Installability -AffectedFields InstallationMetadata, InstallerSwitches, InstallModes -Evidence $ActionEffects.UnknownActions))
        $UnresolvedFields.Add('InstallationMetadata.Actions')
      }
      if ($LegacyActionCatalog.PSObject.Properties['UnresolvedControlFlowCount'] -and $LegacyActionCatalog.UnresolvedControlFlowCount -gt 0) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.ActionControlFlowUnresolved' -Source 'SetupFactory' -Message "$($LegacyActionCatalog.UnresolvedControlFlowCount) Setup Factory 6 loop, jump, or malformed block path(s) depend on runtime state and were preserved without speculative execution." -Kind Ambiguous -Areas Metadata, Installability -AffectedFields InstallationMetadata, InstallerSwitches, InstallModes -Evidence ([ordered]@{ Count = $LegacyActionCatalog.UnresolvedControlFlowCount })))
        $UnresolvedFields.Add('InstallationMetadata.Actions')
      }
    }
    if ($HasBuiltInUninstall -and -not $VisibleRegistryArpEntries.Count -and [string]::IsNullOrWhiteSpace([string]$BuiltInProductCode)) {
      # An enabled uninstaller proves that an ARP route exists, but unresolved variables in its key
      # do not prove the concrete registry identity required by a manifest.
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.BuiltInArpIdentityUnresolved' -Source 'SetupFactory' -Message 'The built-in uninstaller is enabled, but its uninstall-key expression could not be resolved to a concrete ProductCode.' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries))
      $UnresolvedFields.Add('ProductCode')
      $UnresolvedFields.Add('AppsAndFeaturesEntries')
    }
    if (-not $InstalledCatalog.IsComplete) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Payload.FileTableIncomplete' -Source 'SetupFactory' -Message "The generation-specific installed-file table could not be decoded: $($InstalledCatalog.Error)" -Kind Unsupported -Areas Extraction -AffectedFields InstallationMetadata -Evidence ([ordered]@{ ProfileId = $Overlay.ProfileId; ClassName = $InstalledCatalog.ClassName })))
      $UnresolvedFields.Add('InstallationMetadata.Files')
    } elseif (-not $InstalledCatalog.CanExtract -and $InstalledCatalog.CanExtractPartial) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Payload.Truncated' -Source 'SetupFactory' -Message 'The installed-file catalog exceeds the available payload range. The installer is incomplete or corrupt; complete prefix records remain forensic evidence only.' -Kind Invalid -Areas Extraction -AffectedFields InstallationMetadata -Evidence ([ordered]@{ EntryCount = @($InstalledCatalog.Entries).Count; ExtractableEntryCount = $InstalledCatalog.ExtractableEntryCount; UnavailableEntryCount = $InstalledCatalog.UnavailableEntryCount; DeclaredPayloadBytes = $InstalledCatalog.DeclaredPayloadBytes; AvailablePayloadBytes = $Catalog.FileLength - $InstalledPayloadOffset })))
      $UnresolvedFields.Add('InstallationMetadata.Files')
    } elseif (-not $InstalledCatalog.CanExtract) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Payload.LayoutUnresolved' -Source 'SetupFactory' -Message 'The installed-file catalog is readable, but none of its records map to the remaining executable as the supported sequential payload layout; extraction is disabled.' -Kind Unsupported -Areas Extraction -AffectedFields InstallationMetadata -Evidence ([ordered]@{ EntryCount = @($InstalledCatalog.Entries).Count; DeclaredPayloadBytes = $InstalledCatalog.DeclaredPayloadBytes; AvailablePayloadBytes = $Catalog.FileLength - $InstalledPayloadOffset })))
      $UnresolvedFields.Add('InstallationMetadata.Files')
    }
    if ($FilePolicySummary.AskUserOverwriteEntries.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.FileOverwritePrompt' -Source 'SetupFactory' -Message 'One or more payload files use the AskUser overwrite policy. An existing destination file can therefore make an otherwise unattended installation prompt for input.' -Kind ManualValidation -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence ([ordered]@{ EntryCount = $FilePolicySummary.AskUserOverwriteEntries.Count; Entries = $FilePolicySummary.AskUserOverwriteEntries })))
    }
    if ($FilePolicySummary.UnknownOverwriteEntries.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.FileOverwritePolicyUnresolved' -Source 'SetupFactory' -Message 'One or more payload files use an overwrite-policy value that is not defined by the supported Setup Factory runtime.' -Kind Incomplete -Areas Metadata, Installability -AffectedFields InstallationMetadata, InstallerSwitches, InstallModes -Evidence ([ordered]@{ EntryCount = $FilePolicySummary.UnknownOverwriteEntries.Count; Entries = $FilePolicySummary.UnknownOverwriteEntries })))
      $UnresolvedFields.Add('InstallationMetadata.FilePolicy')
    }
    if ($FilePolicySummary.ConditionalEntries.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.ConditionalInstalledFiles' -Source 'SetupFactory' -Message 'The installed-file catalog contains operating-system, language, advanced comparison, runtime, build-configuration, or package conditions; the effective installed-file set depends on the selected installation scenario.' -Kind Ambiguous -Areas Metadata -AffectedFields InstallationMetadata -Evidence ([ordered]@{ EntryCount = $FilePolicySummary.ConditionalEntries.Count; Entries = $FilePolicySummary.ConditionalEntries })))
      $UnresolvedFields.Add('InstallationMetadata.Files')
    }
    if ($FilePolicySummary.SelfRegisteringEntries.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.SelfRegistrationEffects' -Source 'SetupFactory' -Message 'One or more payload files are registered through DllRegisterServer or type-library registration. Registry effects implemented by those binaries require static inspection or VM validation.' -Kind ManualValidation -Areas Metadata -AffectedFields Protocols, FileExtensions -Evidence ([ordered]@{ EntryCount = $FilePolicySummary.SelfRegisteringEntries.Count; Entries = $FilePolicySummary.SelfRegisteringEntries })))
      $UnresolvedFields.Add('Protocols')
      $UnresolvedFields.Add('FileExtensions')
    }
    if ($FilePolicySummary.SuppressInUseNoticeEntries.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.InUseReplacementDeferred' -Source 'SetupFactory' -Message 'One or more payload files suppress the in-use warning. Setup Factory can defer their replacement until restart, so reboot behavior and exit-code evidence require VM validation.' -Kind Risk -Areas Installability -AffectedFields ExpectedReturnCodes -Evidence ([ordered]@{ EntryCount = $FilePolicySummary.SuppressInUseNoticeEntries.Count; Entries = $FilePolicySummary.SuppressInUseNoticeEntries })))
      $UnresolvedFields.Add('ExpectedReturnCodes')
    }
    if ($FilePolicySummary.CrcCheckDisabledEntries.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Security.FileCrcCheckDisabled' -Source 'SetupFactory' -Message 'The compiled project disables Setup Factory CRC verification for one or more payload files.' -Kind Risk -Areas Extraction, Security -AffectedFields InstallationMetadata -Evidence ([ordered]@{ EntryCount = $FilePolicySummary.CrcCheckDisabledEntries.Count; Entries = $FilePolicySummary.CrcCheckDisabledEntries })))
    }
    if (-not $DependencyCatalog.IsComplete) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Payload.DependencyTableIncomplete' -Source 'SetupFactory' -Message "The bundled prerequisite table could not be decoded: $($DependencyCatalog.Error)" -Kind Unsupported -Areas Extraction, Installability -AffectedFields Dependencies -Evidence ([ordered]@{ ProfileId = $Overlay.ProfileId })))
      $UnresolvedFields.Add('Dependencies')
    } elseif ($DependencyCatalog.Entries.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.BundledPrerequisite' -Source 'SetupFactory' -Message 'The installer bundles one or more prerequisite executables; their launch conditions and exit-code handling require static or VM validation.' -Kind ManualValidation -Areas Installability -AffectedFields Dependencies -Evidence $DependencyCatalog.Entries))
    }
    if ($Overlay.SupportsMetadata -and -not $HasBuiltInUninstall -and -not $RegistryArpEntries.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.ArpConfigurationAbsent' -Source 'SetupFactory' -Message 'No built-in uninstall configuration or literal uninstall-key write was found.' -Kind Information -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries))
    }
    if ($RegistryArpScopes.Count -gt 1) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.MixedArpScopes' -Source 'SetupFactory' -Message 'Literal uninstall-key writes target both user and machine registry hives; no single scope was selected.' -Kind Ambiguous -Areas Metadata -AffectedFields Scope, ProductCode, AppsAndFeaturesEntries -Evidence $RegistryArpEntries))
      $UnresolvedFields.Add('Scope')
    }
    if ($UnresolvedRegistryCallCount -gt 0) {
      $RegistryDiagnosticMessage = if ($LegacyActionCatalog) { "$UnresolvedRegistryCallCount legacy registry action or control-flow record(s) could not be projected as deterministic install-time evidence." } else { "$UnresolvedRegistryCallCount Registry.SetValue call(s) use computed, malformed, or unsupported arguments and were not projected as deterministic registry evidence." }
      # Opaque registry actions can always hide associations or an additional ARP row, but they do
      # not invalidate an independently proven built-in ProductCode or scope. Promote only fields
      # that still depend on unresolved calls so partial manifest updates remain actionable.
      $RegistryAffectedFields = [Collections.Generic.List[string]]::new()
      foreach ($Field in 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions') { $RegistryAffectedFields.Add($Field) }
      if ([string]::IsNullOrWhiteSpace([string]$ProductCode)) { $RegistryAffectedFields.Add('ProductCode') }
      if ([string]::IsNullOrWhiteSpace([string]$Scope)) { $RegistryAffectedFields.Add('Scope') }
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.RegistryActionsUnresolved' -Source 'SetupFactory' -Message $RegistryDiagnosticMessage -Kind Incomplete -Areas Metadata -AffectedFields $RegistryAffectedFields.ToArray() -Evidence ([ordered]@{ UnresolvedCallCount = $UnresolvedRegistryCallCount })))
      foreach ($Field in $RegistryAffectedFields) { $UnresolvedFields.Add($Field) }
    }
    foreach ($Diagnostic in @($RegistryAssociationInfo.Diagnostics)) { $Diagnostics.Add($Diagnostic) }

    $WritesAppsAndFeaturesEntry = [bool]($HasBuiltInUninstall -or $VisibleRegistryArpEntries.Count)
    $AppsAndFeaturesEntries = [Collections.Generic.List[object]]::new()
    if ($VisibleRegistryArpEntries.Count) {
      foreach ($Arp in $VisibleRegistryArpEntries) {
        $ManifestEntry = [ordered]@{}
        foreach ($Field in 'DisplayName', 'DisplayVersion', 'Publisher', 'ProductCode') {
          if (-not [string]::IsNullOrWhiteSpace([string]$Arp.$Field)) { $ManifestEntry[$Field] = $Arp.$Field }
        }
        $ManifestEntry.InstallerType = 'exe'
        $AppsAndFeaturesEntries.Add([pscustomobject]$ManifestEntry)
      }
    } elseif ($HasBuiltInUninstall) {
      $ManifestEntry = [ordered]@{}
      $BuiltInArpValues = [ordered]@{
        DisplayName    = $DisplayName
        DisplayVersion = $DisplayVersion
        Publisher      = $Publisher
        ProductCode    = $ProductCode
      }
      foreach ($Field in $BuiltInArpValues.Keys) {
        if (-not [string]::IsNullOrWhiteSpace([string]$BuiltInArpValues[$Field])) { $ManifestEntry[$Field] = $BuiltInArpValues[$Field] }
      }
      $ManifestEntry.InstallerType = 'exe'
      $AppsAndFeaturesEntries.Add([pscustomobject]$ManifestEntry)
    }

    $InstallerSwitches = [ordered]@{}
    $InstallModes = if ($SilentInstallationInfo.IsResolved -and $SilentInstallationInfo.SupportsSilentInstallation) {
      $InstallerSwitches['Silent'] = '/S'
      @('interactive', 'silent')
    } elseif ($SilentInstallationInfo.IsResolved) {
      @('interactive')
    } else {
      @()
    }

    # Construct the shared result from Setup Factory evidence directly.
    [pscustomobject][ordered]@{
      Path                         = $File.FullName
      InstallerType                = 'exe'
      ProductCode                  = $ProductCode
      UpgradeCode                  = $null
      DisplayName                  = $DisplayName
      DisplayVersion               = $DisplayVersion
      Publisher                    = $Publisher
      Scope                        = $Scope
      DefaultInstallLocation       = $InstallLocation
      WritesAppsAndFeaturesEntry   = $WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode   = $WritesAppsAndFeaturesEntry ? $ProductCode : $null
      AppsAndFeaturesInstallerType = $WritesAppsAndFeaturesEntry ? 'exe' : $null
      AppsAndFeaturesEntries       = $AppsAndFeaturesEntries.ToArray()
      Diagnostics                  = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
      UnresolvedFields             = [string[]]@($UnresolvedFields | Sort-Object -Unique)
      Family                       = 'Setup Factory'
      RegistryWrites               = $RegistryWrites
      RegistryArpEntries           = $RegistryArpEntries
      RegistryAssociationInfo      = $RegistryAssociationInfo
      Protocols                    = $RegistryAssociationInfo.Protocols
      FileExtensions               = $RegistryAssociationInfo.FileExtensions
      ContainerEntries             = $Catalog.Entries
      DependencyPayloads           = $DependencyCatalog.Entries
      PayloadCatalog               = $InstalledCatalog.Entries
      InstalledFileCatalog         = $InstalledCatalog
      FilePolicySummary            = $FilePolicySummary
      ExtractedFiles               = @()
      CanExpand                    = [bool]$InstalledCatalog.CanExtract
      CanExpandPartial             = [bool]$InstalledCatalog.CanExtractPartial
      CanExpandRawEntries          = $true
      SupportsSilentInstallation   = $SilentInstallationInfo.SupportsSilentInstallation
      StartsInSilentMode           = $SilentInstallationInfo.StartsInSilentMode
      InstallerSwitches            = [pscustomobject]$InstallerSwitches
      InstallModes                 = [string[]]$InstallModes
      SilentInstallationEvidence   = $SilentInstallationInfo.Evidence
      ProductMetadata              = $LegacyMetadata ? $LegacyMetadata.Product : $null
      UninstallConfiguration       = $LegacyMetadata ? $LegacyMetadata.Uninstall : $null
      LegacyActionCatalog          = $LegacyActionCatalog
      ActionEffects                = $ActionEffects
      VariableAssignments          = $ActionEffects.VariableAssignments
      ExecutionActions             = $ActionEffects.ExecutionActions
      FileSystemActions            = $ActionEffects.FileSystemActions
      IniActions                   = $ActionEffects.IniActions
      VariableReads                = $ActionEffects.VariableReads
      UserInteractionActions       = $ActionEffects.UserInteractionActions
      InstallabilityActions        = $ActionEffects.InstallabilityActions
      Shortcuts                    = $ActionEffects.ShortcutActions
      ServiceActions               = $ActionEffects.ServiceActions
      RebootActions                = $ActionEffects.RebootActions
      ExternalCodeActions          = $ActionEffects.ExternalCodeActions
      EmbeddedRuntimeInfo          = $EmbeddedRuntimeInfo
      ParserVersionInfo            = [pscustomobject][ordered]@{
        Family                 = 'Setup Factory'
        MajorVersion           = $EmbeddedRuntimeInfo.IsTrusted ? $EmbeddedRuntimeInfo.MajorVersion : ($Overlay.Version -ne 0 ? $Overlay.Version : $null)
        BuilderVersion         = $Overlay.BuilderVersion ?? ($EmbeddedRuntimeInfo.IsTrusted ? $EmbeddedRuntimeInfo.Version : $null)
        BuilderVersionSource   = $Overlay.BuilderVersionSource ?? ($EmbeddedRuntimeInfo.IsTrusted ? 'EmbeddedRuntimeVersionResource' : $null)
        OuterRuntimeVersion    = $Overlay.BuilderVersion
        EmbeddedRuntimeVersion = $EmbeddedRuntimeInfo.IsTrusted ? $EmbeddedRuntimeInfo.Version : $null
        ProfileId              = $Overlay.ProfileId
        FormatGeneration       = $Overlay.FormatGeneration
        MetadataRoute          = $Overlay.MetadataRoute
        MetadataProfile        = if ($LegacyMetadata -and $LegacyMetadata.PSObject.Properties['MetadataProfile']) { $LegacyMetadata.MetadataProfile } else { $null }
        HeaderRoute            = $Overlay.HeaderRoute
        HeaderPrefixLength     = $Overlay.HeaderPrefixLength
        OverlayOffset          = $Overlay.Offset
      }
    }
  }
}

function Test-SetupFactory {
  <#
  .SYNOPSIS
    Test whether a file is a supported Setup Factory installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    try {
      # A signature at the overlay boundary is only a candidate. Requiring the
      # complete bounded catalog rejects marker-only and truncated PE overlays.
      $null = Get-SetupFactoryArchiveCatalog -Path $Path
      return $true
    } catch {
      return $false
    }
  }
}

function Read-ProductVersionFromSetupFactory {
  <#
  .SYNOPSIS
    Read the product version from a Setup Factory installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromSetupFactory {
  <#
  .SYNOPSIS
    Read the product name from a Setup Factory installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).DisplayName }
}

function Read-PublisherFromSetupFactory {
  <#
  .SYNOPSIS
    Read the publisher from a Setup Factory installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromSetupFactory {
  <#
  .SYNOPSIS
    Read the ARP ProductCode from a Setup Factory installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).ProductCode }
}

function Read-ScopeFromSetupFactory {
  <#
  .SYNOPSIS
    Read the installation scope from a Setup Factory installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).Scope }
}

function Read-ProtocolsFromSetupFactory {
  <#
  .SYNOPSIS
    Read literal URL protocol names from Setup Factory registry actions.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromSetupFactory {
  <#
  .SYNOPSIS
    Read literal file-extension names from Setup Factory registry actions.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).FileExtensions }
}

Export-ModuleMember -Function Get-SetupFactoryInfo, Expand-SetupFactoryInstaller, Test-SetupFactory, Read-ProductVersionFromSetupFactory, Read-ProductNameFromSetupFactory, Read-PublisherFromSetupFactory, Read-ProductCodeFromSetupFactory, Read-ScopeFromSetupFactory, Read-ProtocolsFromSetupFactory, Read-FileExtensionsFromSetupFactory
