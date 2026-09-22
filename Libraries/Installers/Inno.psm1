# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# Format sources: https://github.com/jrsoftware/issrc, https://github.com/jrathlev/InnoUnpacker-Windows-GUI, https://github.com/Wack0/IFPSTools.NET, and https://github.com/russellbanks/Komac
#
# Binary structure consumed by this parser:
#
#   PE loader
#   +-- legacy: [abs 0x30] "Inno" + table pointer/complement
#   |            `-- S02/S04/S05/S06/S07 table -> Offset0/Offset1
#   `-- modern: .rsrc/RCDATA/#11111 -> 44-byte v1 or 64-byte v2 table
#
#   Offset0 -> setup signature[64] -> optional encryption header
#     -> legacy or chunk-framed metadata -> catalogued record tables
#   Offset1 != 0 -> embedded 7A 6C 62 1A ("zlb" 1A) payload blocks
#   Offset1 == 0 -> Setup-N[letter].bin external slices
#     +-- 69 64 73 6B 61 33 32 1A + uint32 size (structures < 6.5.2)
#     `-- 69 64 73 6B 62 33 32 1A + int64 size  (structures >= 6.5.2)
#
# InnoFormatCatalog.psd1 maps exact edition/signature/character-mode/loader
# combinations to immutable loader, framing, record, payload, checksum, and
# CALL-transform routes. Integers are little-endian. Every range, count, chunk,
# checksum, decompressed size, and extraction destination is bounded.

# Apply default function parameters

# Inno Public layer. Internal modules are imported locally; public commands stay in the facade.
Import-Module (Join-Path $PSScriptRoot 'InnoFormat.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'InnoScript.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'InnoPayload.psm1') -ErrorAction Stop

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$INNO_DEFAULT_MAX_DISASSEMBLY_CHARACTERS = 4194304

function Get-InnoFormatInfo {
  <#
  .SYNOPSIS
    Identify the Inno edition and select its catalogued binary-layout routes.
  .DESCRIPTION
    Reads only the PE loader table and the 64-byte setup-data signature. The
    result describes which loader, metadata, record, payload, checksum, and
    executable-transform routes the full parser will use. An ISX signature is
    returned as a structured unsupported format rather than being mistaken for
    official Inno Setup.
  .PARAMETER Path
    Path to an Inno Setup installer. The file is opened for bounded static reads
    and is never loaded or executed.
  .OUTPUTS
    PSCustomObject containing edition, character mode, structure version,
    selected route IDs, layout resolution, candidate IDs, and support status.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
    [string]$Path
  )

  process {
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $OffsetTable = Get-InnoOffsetTable -Path $InstallerPath
    $SignatureInfo = Get-InnoSignatureInfo -Path $InstallerPath -OffsetTable $OffsetTable
    $Layout = Get-InnoLayout -SignatureInfo $SignatureInfo -LoaderRoute $OffsetTable.LoaderRoute
    $Warnings = [Collections.Generic.List[object]]::new()
    if ($Layout.SupportStatus -eq 'Unsupported') {
      $Warnings.Add((New-InstallerDiagnostic -Id 'Inno.Format.RecordSpecificationUnsupported' -Source 'Inno' -Message "The Inno edition '$($Layout.Edition)' is identified, but no trustworthy record specification is available." -Kind Unsupported -Areas Detection, Metadata, Extraction))
    } elseif ($Layout.LayoutResolution -eq 'NearestOlderPendingValidation') {
      $Warnings.Add((New-InstallerDiagnostic -Id 'Inno.Format.NewerCompatibleFallback' -Source 'Inno' -Message 'The signature is newer than the catalogued layout. Full parsing must validate every count, range, record boundary, checksum, and stream boundary before accepting the fallback.' -Kind Fallback -Areas Detection, Metadata, Extraction))
    } elseif ($Layout.LayoutResolution -eq 'ExactSignatureAlias') {
      $Warnings.Add((New-InstallerDiagnostic -Id 'Inno.Format.SignatureAlias' -Source 'Inno' -Message 'Multiple catalog rows share this byte-equivalent setup-data signature. The source-defined canonical structure was selected and all alias IDs are reported.' -Kind Ambiguous -Areas Detection))
    }

    $GetLayoutValue = {
      param([string]$Name)
      $Property = $Layout.PSObject.Properties[$Name]
      if ($Property) { return $Property.Value }
      return $null
    }

    [pscustomobject]@{
      Path                     = $InstallerPath
      InstallerType            = 'inno'
      Signature                = $SignatureInfo.Signature
      SignatureVersion         = $SignatureInfo.VersionText
      CatalogFormatId          = & $GetLayoutValue 'Id'
      InternalStructureVersion = & $GetLayoutValue 'InternalStructureVersion'
      EditionId                = $SignatureInfo.EditionId
      Edition                  = $SignatureInfo.Edition
      CharacterMode            = $SignatureInfo.CharacterMode
      LoaderRoute              = $OffsetTable.LoaderRoute
      MetadataRoute            = & $GetLayoutValue 'MetadataRoute'
      RecordSchemaRoute        = & $GetLayoutValue 'RecordSchemaRoute'
      PayloadRoute             = & $GetLayoutValue 'PayloadRoute'
      CompressionCapabilities  = @((& $GetLayoutValue 'CompressionCapabilities') -split ',' | Where-Object { $_ })
      ChecksumRoute            = & $GetLayoutValue 'ChecksumRoute'
      CallTransformRoute       = & $GetLayoutValue 'CallTransformRoute'
      LayoutResolution         = $Layout.LayoutResolution
      CandidateIds             = [string[]]@($Layout.CandidateIds)
      SupportStatus            = $Layout.SupportStatus
      IsSupported              = $Layout.SupportStatus -eq 'Supported'
      Diagnostics              = @(Merge-InstallerDiagnostics -Diagnostic @(ConvertTo-InstallerDiagnostic -InputObject @($Warnings.ToArray()) -Source 'Inno' -Kind Incomplete -Areas Metadata))
    }
  }
}

function Get-InnoPascalScriptInfo {
  <#
  .SYNOPSIS
    Read and analyze the compiled Pascal Script embedded in an Inno installer.
  .PARAMETER Path
    Path to the Inno Setup installer. The installer is parsed but never executed.
  .PARAMETER IncludeDisassembly
    Include bounded textual IFPS disassembly.
  .PARAMETER MaximumDisassemblyCharacters
    Maximum characters retained from the optional disassembly.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [switch]$IncludeDisassembly,
    [ValidateRange(1024, 16777216)][int]$MaximumDisassemblyCharacters = $INNO_DEFAULT_MAX_DISASSEMBLY_CHARACTERS
  )

  process {
    $Context = Get-InnoAnalysisContext -Path $Path
    ConvertTo-InnoPascalScriptInfo -Bytes $Context.ParsedLayout.CompiledCodeBytes -IncludeDisassembly:$IncludeDisassembly `
      -MaximumDisassemblyCharacters $MaximumDisassemblyCharacters
  }
}

function Get-InnoInfo {
  <#
  .SYNOPSIS
    Get static metadata from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  .PARAMETER IncludePascalScriptAnalysis
    Decode functions, calls, constants, and bounded static-effect evidence in the same parse.
  .PARAMETER IncludeDisassembly
    Include bounded textual IFPS disassembly. This implies IncludePascalScriptAnalysis.
  .PARAMETER MaximumDisassemblyCharacters
    Maximum characters retained from optional disassembly.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path,
    [switch]$IncludePascalScriptAnalysis,
    [switch]$IncludeDisassembly,
    [ValidateRange(1024, 16777216)][int]$MaximumDisassemblyCharacters = $INNO_DEFAULT_MAX_DISASSEMBLY_CHARACTERS
  )

  process {
    $Context = Get-InnoAnalysisContext -Path $Path
    $InstallerPath = $Context.Path
    $OffsetTable = $Context.OffsetTable
    $SignatureInfo = $Context.SignatureInfo
    $Layout = $Context.Layout

    # The exact catalog row, not PE FileVersion, selects string counts, fixed
    # fields, metadata framing, payload layout, checksum, and call transform.
    $PEInfo = $Context.PEInfo
    $ParsedLayout = $Context.ParsedLayout
    $VersionNumber = $Layout.VersionNumber
    $HeaderBlockInfo = $ParsedLayout.HeaderBlockInfo
    $HeaderBytes = $HeaderBlockInfo.Bytes
    $HeaderValues = $ParsedLayout.HeaderValues
    $ExtractionHeader = $ParsedLayout.ExtractionHeader
    $HeaderFixedData = Read-InnoHeaderFixedData -Bytes $HeaderBytes -Layout $Layout
    $HeaderArchitectureData = Get-InnoHeaderArchitectureData -HeaderValues $HeaderValues -PEInfo $PEInfo -HeaderFixedData $HeaderFixedData -Layout $Layout
    $Warnings = [System.Collections.Generic.List[object]]::new()
    foreach ($Warning in $HeaderArchitectureData.Diagnostics) { $Warnings.Add($Warning) }
    $PascalScriptInfo = $null
    $HeaderFields = $Layout.HeaderFields
    $ManifestHeaderValues = [string[]]@(
      $HeaderValues[$HeaderFields.AppName], $HeaderValues[$HeaderFields.AppVerName], $HeaderValues[$HeaderFields.AppId]
      $HeaderValues[$HeaderFields.Publisher], $HeaderValues[$HeaderFields.AppVersion], $HeaderValues[$HeaderFields.DefaultDirName]
      $HeaderValues[$HeaderFields.UninstallDisplayName]
    )
    $HasCodeConstant = @($ManifestHeaderValues | Where-Object { $_ -match '(?i)\{code:' }).Count -gt 0
    $HasDynamicDirectiveCheck = @(
      if ($null -eq $Layout.LegacyCreateUninstallRegKeyOptionBit -and $HeaderValues.Count -gt 24 -and
        -not [string]::IsNullOrWhiteSpace($HeaderValues[24]) -and $HeaderValues[24] -notmatch '^(?i:yes|no|true|false|0|1)$') { $HeaderValues[24] }
      if ($null -eq $Layout.LegacyUninstallableOptionBit -and $HeaderValues.Count -gt 25 -and
        -not [string]::IsNullOrWhiteSpace($HeaderValues[25]) -and $HeaderValues[25] -notmatch '^(?i:yes|no|true|false|0|1)$') { $HeaderValues[25] }
    ).Count -gt 0
    $RequiresDetailedPascalAnalysis = $IncludePascalScriptAnalysis -or $IncludeDisassembly -or $HasCodeConstant -or $HasDynamicDirectiveCheck
    try {
      if ($RequiresDetailedPascalAnalysis) {
        $PascalScriptInfo = ConvertTo-InnoPascalScriptInfo -Bytes $ParsedLayout.CompiledCodeBytes `
          -IncludeDisassembly:$IncludeDisassembly -MaximumDisassemblyCharacters $MaximumDisassemblyCharacters
      } else {
        # Ordinary metadata parsing validates only the fixed IFPS header.
        $PascalScriptInfo = Read-InnoPascalScriptHeader -Bytes $ParsedLayout.CompiledCodeBytes
      }
    } catch {
      # Compiled code can be absent, vendor-modified, or from a future IFPS
      # generation. Preserve the setup-header evidence instead of making the
      # optional script analysis fatal to ordinary manifest parsing.
      $Warnings.Add("Compiled Pascal Script analysis failed: $($_.Exception.Message)")
    }
    $PascalScriptReturnMap = Get-InnoPascalScriptReturnMap -PascalScriptInfo $PascalScriptInfo
    $PascalScriptConstantMap = Get-InnoPascalScriptConstantMap -PascalScriptInfo $PascalScriptInfo -Values $HeaderValues
    $AppsAndFeaturesEntryInfo = Get-InnoAppsAndFeaturesEntryInfo -HeaderValues $HeaderValues -Layout $Layout `
      -HeaderFixedData $HeaderFixedData -StaticReturnValues $PascalScriptReturnMap
    if ($HeaderBlockInfo.EncryptionHeader.EncryptionUse -eq 'Files') {
      $Warnings.Add((New-InstallerDiagnostic -Id 'Inno.Extraction.PasswordRequired' -Source 'Inno' -Message 'The installer payload files are encrypted; static metadata is available, but extraction requires the setup password.' -Kind Unsupported -Areas Extraction))
    }
    if (-not $AppsAndFeaturesEntryInfo.IsResolved) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'Inno.ARP.DynamicRegistrationExpression' -Source 'Inno' -Message 'CreateUninstallRegKey or Uninstallable is a dynamic expression, so Apps & Features registration cannot be determined statically.' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries))
    }

    # The file table supplies an exact boundary for the icon, INI, registry,
    # delete, and run tables that follow it. Keep metadata useful when a
    # proprietary or malformed record variant cannot be consumed, but expose a
    # warning rather than returning guessed registry associations.
    $PostFileRecordInfo = [pscustomobject]@{
      IsResolved = $false; EndOffset = $null; Icons = @(); IniEntries = @(); RegistryEntries = @()
      InstallDeleteEntries = @(); UninstallDeleteEntries = @(); RunEntries = @(); UninstallRunEntries = @()
    }
    if ($ExtractionHeader.Counts.NumFileEntries -gt 0 -and $ExtractionHeader.Counts.NumFileLocationEntries -gt 0) {
      try {
        $FileEntries = @(Get-InnoFileEntries -Bytes $HeaderBytes -Layout $Layout -Count $ExtractionHeader.Counts.NumFileEntries `
            -FileLocationCount $ExtractionHeader.Counts.NumFileLocationEntries -SearchOffset $ExtractionHeader.SearchOffset)
        $PostFileRecordInfo = Get-InnoPostFileRecordInfo -Bytes $HeaderBytes -Layout $Layout -Counts $ExtractionHeader.Counts -FileEntries $FileEntries
      } catch {
        $Warnings.Add("The catalogued post-file metadata tables could not be parsed: $($_.Exception.Message)")
      }
    } elseif (
      $ExtractionHeader.Counts.NumIconEntries -gt 0 -or $ExtractionHeader.Counts.NumIniEntries -gt 0 -or
      $ExtractionHeader.Counts.NumRegistryEntries -gt 0 -or $ExtractionHeader.Counts.NumInstallDeleteEntries -gt 0 -or
      $ExtractionHeader.Counts.NumUninstallDeleteEntries -gt 0 -or $ExtractionHeader.Counts.NumRunEntries -gt 0 -or
      $ExtractionHeader.Counts.NumUninstallRunEntries -gt 0
    ) {
      $Warnings.Add('Post-file metadata records exist without an anchorable embedded file table; registry and association evidence requires manual validation.')
    }
    $AssociationInfo = Get-InnoRegistryAssociationInfo -RegistryEntries ([pscustomobject[]]@($PostFileRecordInfo.RegistryEntries))

    $AppNameInfo = Get-InnoStaticStringInfo -Value $HeaderValues[$HeaderFields.AppName] -ConstantMap $PascalScriptConstantMap
    $AppVerNameInfo = Get-InnoStaticStringInfo -Value $HeaderValues[$HeaderFields.AppVerName] -ConstantMap $PascalScriptConstantMap
    $RawAppId = $HeaderValues[$HeaderFields.AppId]
    $AppIdInfo = Get-InnoStaticStringInfo -Value $RawAppId -ConstantMap $PascalScriptConstantMap
    $AppPublisherInfo = Get-InnoStaticStringInfo -Value $HeaderValues[$HeaderFields.Publisher] -ConstantMap $PascalScriptConstantMap
    $AppVersionInfo = Get-InnoStaticStringInfo -Value $HeaderValues[$HeaderFields.AppVersion] -ConstantMap $PascalScriptConstantMap
    $DefaultDirName = $HeaderValues[$HeaderFields.DefaultDirName]
    $UninstallDisplayNameInfo = Get-InnoStaticStringInfo -Value $HeaderValues[$HeaderFields.UninstallDisplayName] -ConstantMap $PascalScriptConstantMap

    $DefaultScope = Convert-InnoPrivilegeToScope -PrivilegesRequired $HeaderFixedData.PrivilegesRequired

    # PrivilegesRequiredOverridesAllowed exposes explicit command-line scope
    # selection; without it only the compiled default scope is supported.
    $SupportedScopes = if ($HeaderFixedData.SupportsCommandLineScopeOverride -and $DefaultScope) {
      @('user', 'machine')
    } elseif ($DefaultScope) {
      @($DefaultScope)
    } else {
      @()
    }
    $InstallIn64BitMode = $HeaderArchitectureData.InstallIn64BitMode

    $DefaultDirectoryConstantMap = Get-InnoDefaultDirectoryConstantMap -DefaultScope $DefaultScope -InstallIn64BitMode $InstallIn64BitMode
    foreach ($Constant in $PascalScriptConstantMap.GetEnumerator()) {
      $DefaultDirectoryConstantMap[$Constant.Key] = $Constant.Value
    }
    $DefaultDirInfo = Get-InnoStaticStringInfo -Value $DefaultDirName -ConstantMap $DefaultDirectoryConstantMap
    $ResolvedDefaultDirName = $DefaultDirInfo.Value

    # ArchitecturesAllowed is not sufficient when a mandatory setup path uses
    # a constant that ExpandIndividualConst rejects on 32-bit Windows. Inno
    # expands DefaultDirName while initializing the wizard, before file-table
    # conditions can suppress the path, so this is deterministic compatibility
    # evidence rather than payload-architecture inference.
    $RequiredArchitectureValues = [ordered]@{ DefaultDirName = $DefaultDirName }
    if ($DefaultDirInfo.DecodedValue -cne $DefaultDirName) {
      # A statically interpreted {code:*} function can return another built-in
      # constant. Inspect that recovered value as a second expansion stage.
      $RequiredArchitectureValues['ResolvedDefaultDirName'] = $DefaultDirInfo.DecodedValue
    }
    $ArchitectureConstantRequirement = Get-InnoArchitectureConstantRequirement -Values $RequiredArchitectureValues `
      -DefaultScope $DefaultScope -SupportsScopeOverride:$HeaderFixedData.SupportsCommandLineScopeOverride
    $SupportedArchitectures = [string[]]@(
      $HeaderArchitectureData.SupportedArchitectures |
        Where-Object { $ArchitectureConstantRequirement.UnsupportedArchitectures -notcontains $_ }
    )
    $UnsupportedArchitectures = [string[]]@(
      @($HeaderArchitectureData.UnsupportedArchitectures) + @($ArchitectureConstantRequirement.UnsupportedArchitectures) |
        Select-Object -Unique
    )
    if ($ArchitectureConstantRequirement.Requires64BitWindows) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'Inno.Architecture.Required64BitConstant' -Source 'Inno' -Message 'Inno expands an x64-only constant from a required setup field; x86 is excluded even though ArchitecturesAllowed may permit it.' -Kind Information -Areas Metadata, Installability -AffectedFields SupportedArchitectures, UnsupportedArchitectures -Evidence ([ordered]@{
              RequiredConstants = $ArchitectureConstantRequirement.RequiredConstants
              Fields            = [string[]]@($ArchitectureConstantRequirement.Evidence.Field | Select-Object -Unique)
            })))
    }

    # A resolved root token is stronger scope evidence than the launcher PE
    # architecture. Dynamic {code:...} paths remain unresolved and do not guess.
    $Scope = if ($ResolvedDefaultDirName -and $ResolvedDefaultDirName -match '^(?i)%(?:ProgramFiles(?:\(x86\))?|ProgramData|SystemRoot|SystemDrive)%') {
      'machine'
    } elseif ($ResolvedDefaultDirName -and $ResolvedDefaultDirName -match '^(?i)%(?:LocalAppData|AppData|UserProfile)%') {
      'user'
    } else {
      $null
    }

    $DisplayNameInfo = if (-not [string]::IsNullOrWhiteSpace($HeaderValues[$HeaderFields.UninstallDisplayName])) {
      $UninstallDisplayNameInfo
    } elseif (-not [string]::IsNullOrWhiteSpace($HeaderValues[$HeaderFields.AppVerName])) {
      $AppVerNameInfo
    } else {
      $AppNameInfo
    }
    $DisplayName = $DisplayNameInfo.Value
    $UninstallRegKeyBaseName = if ($AppIdInfo.IsResolved -and -not [string]::IsNullOrWhiteSpace($AppIdInfo.Value)) {
      Get-InnoUninstallRegKeyBaseName -AppId $AppIdInfo.Value
    } else {
      $null
    }
    # Inno appends _is1 to the normalized AppId only when its own uninstall key
    # is enabled; wrapper installers that suppress ARP receive no ProductCode.
    $ProductCode = if ($AppsAndFeaturesEntryInfo.WritesAppsAndFeaturesEntry -eq $true -and $UninstallRegKeyBaseName) {
      "${UninstallRegKeyBaseName}_is1"
    } else {
      $null
    }

    $UnresolvedConstants = [ordered]@{}

    # Preserve dynamic-field evidence explicitly so callers can distinguish an
    # absent value from one that depends on runtime Pascal Script code.
    $StaticFieldInfo = [ordered]@{
      AppName              = $AppNameInfo
      AppVerName           = $AppVerNameInfo
      AppId                = $AppIdInfo
      AppPublisher         = $AppPublisherInfo
      AppVersion           = $AppVersionInfo
      DefaultDirName       = $DefaultDirInfo
      UninstallDisplayName = $UninstallDisplayNameInfo
    }
    foreach ($FieldInfo in $StaticFieldInfo.GetEnumerator()) {
      if (-not $FieldInfo.Value.IsResolved) { $UnresolvedConstants[$FieldInfo.Key] = $FieldInfo.Value.UnresolvedConstants }
    }
    $UnresolvedFields = @(
      if (-not $AppIdInfo.IsResolved -or $null -eq $AppsAndFeaturesEntryInfo.WritesAppsAndFeaturesEntry) { 'ProductCode' }
      if (-not $AppPublisherInfo.IsResolved) { 'Publisher' }
      if (-not $AppVersionInfo.IsResolved) { 'DisplayVersion' }
      if (-not $DefaultDirInfo.IsResolved) { 'DefaultInstallLocation' }
      if (-not $DisplayNameInfo.IsResolved) { 'DisplayName' }
    )

    # Preserve unresolved Pascal constants as diagnostics while emitting only
    # values proven by the decoded setup header in the canonical envelope.
    return [pscustomobject][ordered]@{
      Path                                       = $InstallerPath
      InstallerType                              = 'inno'
      ProductCode                                = $ProductCode
      UpgradeCode                                = $null
      DisplayName                                = $DisplayName
      DisplayVersion                             = $AppVersionInfo.Value
      Publisher                                  = $AppPublisherInfo.Value
      Scope                                      = $Scope
      DefaultInstallLocation                     = $ResolvedDefaultDirName
      WritesAppsAndFeaturesEntry                 = $AppsAndFeaturesEntryInfo.WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode                 = $AppsAndFeaturesEntryInfo.WritesAppsAndFeaturesEntry -eq $true ? $ProductCode : $null
      AppsAndFeaturesInstallerType               = $AppsAndFeaturesEntryInfo.WritesAppsAndFeaturesEntry -eq $true ? 'inno' : $null
      Diagnostics                                = @(Merge-InstallerDiagnostics -Diagnostic @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings) -Source 'Inno' -Kind Incomplete -Areas Metadata))
      UnresolvedFields                           = [string[]]@($UnresolvedFields | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
      Family                                     = 'Inno Setup'

      RegistryWrites                             = [pscustomobject[]]@($PostFileRecordInfo.RegistryEntries)
      FileExtensions                             = [string[]]@($AssociationInfo.FileExtensions)
      Protocols                                  = [string[]]@($AssociationInfo.Protocols)
      ConditionalFileExtensions                  = [string[]]@($AssociationInfo.ConditionalFileExtensions)
      ConditionalProtocols                       = [string[]]@($AssociationInfo.ConditionalProtocols)
      FileExtensionAssociations                  = [pscustomobject[]]@($AssociationInfo.FileExtensionAssociations)
      ProtocolAssociations                       = [pscustomobject[]]@($AssociationInfo.ProtocolAssociations)
      ConditionalRegistryAssociations            = [pscustomobject[]]@($AssociationInfo.ConditionalRegistryAssociations)
      MetadataTablesResolved                     = $PostFileRecordInfo.IsResolved
      MetadataRecordCounts                       = [pscustomobject]@{
        Icons           = @($PostFileRecordInfo.Icons).Count
        Ini             = @($PostFileRecordInfo.IniEntries).Count
        Registry        = @($PostFileRecordInfo.RegistryEntries).Count
        InstallDelete   = @($PostFileRecordInfo.InstallDeleteEntries).Count
        UninstallDelete = @($PostFileRecordInfo.UninstallDeleteEntries).Count
        Run             = @($PostFileRecordInfo.RunEntries).Count
        UninstallRun    = @($PostFileRecordInfo.UninstallRunEntries).Count
      }
      UninstallRegKeyBaseName                    = $UninstallRegKeyBaseName
      DefaultScope                               = $DefaultScope
      SupportedScopes                            = $SupportedScopes
      SupportsDualScope                          = $SupportedScopes.Count -gt 1
      PrivilegesRequired                         = $HeaderFixedData.PrivilegesRequired
      PrivilegesRequiredOverridesAllowed         = $HeaderFixedData.PrivilegesRequiredOverridesAllowed
      SupportsCommandLineScopeOverride           = $HeaderFixedData.SupportsCommandLineScopeOverride
      UserScopeSwitch                            = $HeaderFixedData.SupportsCommandLineScopeOverride ? '/CURRENTUSER' : $null
      MachineScopeSwitch                         = $HeaderFixedData.SupportsCommandLineScopeOverride ? '/ALLUSERS' : $null
      CreateUninstallRegKey                      = $AppsAndFeaturesEntryInfo.CreateUninstallRegKey
      Uninstallable                              = $AppsAndFeaturesEntryInfo.Uninstallable
      CreatesUninstallRegistryKey                = $AppsAndFeaturesEntryInfo.CreatesUninstallRegistryKey
      RegistersUninstaller                       = $AppsAndFeaturesEntryInfo.RegistersUninstaller
      CreateUninstallRegKeyResolved              = $AppsAndFeaturesEntryInfo.CreateUninstallRegKeyResolved
      UninstallableResolved                      = $AppsAndFeaturesEntryInfo.UninstallableResolved
      ArchitecturesAllowed                       = $HeaderArchitectureData.ArchitecturesAllowed
      ArchitecturesInstallIn64BitMode            = $HeaderArchitectureData.ArchitecturesInstallIn64BitMode
      EffectiveArchitecturesAllowed              = $HeaderArchitectureData.EffectiveArchitecturesAllowed
      EffectiveArchitecturesInstallIn64BitMode   = $HeaderArchitectureData.EffectiveArchitecturesInstallIn64BitMode
      PackedArchitecturesAllowed                 = $HeaderArchitectureData.PackedArchitecturesAllowed
      PackedArchitecturesInstallIn64BitMode      = $HeaderArchitectureData.PackedArchitecturesInstallIn64BitMode
      InstallIn64BitMode                         = $InstallIn64BitMode
      SupportedArchitectures                     = $SupportedArchitectures
      UnsupportedArchitectures                   = $UnsupportedArchitectures
      RequiredArchitectureConstants              = $ArchitectureConstantRequirement.RequiredConstants
      ArchitectureRequirementEvidence            = $ArchitectureConstantRequirement.Evidence
      ConditionalArchitectureRequirementEvidence = $ArchitectureConstantRequirement.ConditionalEvidence
      InstallerArchitecture                      = $PEInfo.Architecture
      AppName                                    = $AppNameInfo.DecodedValue
      AppVerName                                 = $AppVerNameInfo.DecodedValue
      AppVersion                                 = $AppVersionInfo.DecodedValue
      AppId                                      = $AppIdInfo.DecodedValue
      ResolvedAppId                              = $AppIdInfo.Value
      RawAppId                                   = $RawAppId
      RawDefaultDirName                          = $DefaultDirName
      UninstallDisplayName                       = $UninstallDisplayNameInfo.DecodedValue
      ResolvedPascalCodeConstants                = [pscustomobject]$PascalScriptConstantMap
      UnresolvedConstants                        = [pscustomobject]$UnresolvedConstants
      Signature                                  = $SignatureInfo.Signature
      VersionNumber                              = $VersionNumber
      EditionId                                  = $Layout.EditionId
      Edition                                    = $Layout.Edition
      CharacterMode                              = $Layout.CharacterMode
      EncryptionUse                              = $HeaderBlockInfo.EncryptionHeader.EncryptionUse
      IsHeaderEncrypted                          = $HeaderBlockInfo.EncryptionHeader.EncryptionUse -eq 'Full'
      FilesEncrypted                             = $HeaderBlockInfo.EncryptionHeader.EncryptionUse -in @('Files', 'Full')
      CompressMethod                             = $HeaderFixedData.CompressMethod
      PascalScriptInfo                           = $PascalScriptInfo
      UsesExternalDiskSlices                     = $OffsetTable.Offset1 -eq 0
      SlicesPerDisk                              = $HeaderFixedData.SlicesPerDisk
      ParserVersionInfo                          = [pscustomobject]@{
        CatalogVersion                = $Context.CatalogVersion
        CatalogFormatId               = $Layout.Id
        SignatureVersion              = $SignatureInfo.VersionText
        InternalStructureVersion      = $Layout.InternalStructureVersion
        EditionId                     = $Layout.EditionId
        Edition                       = $Layout.Edition
        CharacterMode                 = $Layout.CharacterMode
        LayoutResolution              = $Layout.LayoutResolution
        CandidateFormatIds            = [string[]]@($Layout.CandidateIds)
        LoaderRoute                   = $Layout.LoaderRoute
        MetadataRoute                 = $Layout.MetadataRoute
        RecordSchemaRoute             = $Layout.RecordSchemaRoute
        PayloadRoute                  = $Layout.PayloadRoute
        ChecksumRoute                 = $Layout.ChecksumRoute
        CallTransformRoute            = $Layout.CallTransformRoute
        HeaderStringCount             = $Layout.HeaderStringCount
        HeaderAnsiStringCount         = $Layout.HeaderAnsiStringCount
        EntryCounts                   = $ExtractionHeader.Counts
        FileEntryStringCount          = $Layout.FileEntryStringCount
        FileEntryAnsiStringCount      = $Layout.FileEntryAnsiStringCount
        FileLocationEntrySize         = $Layout.FileLocationEntrySize
        FileLocationDigestAlgorithm   = $Layout.FileLocationDigestAlgorithm
        FileLocationStartOffsetSize   = $Layout.FileLocationStartOffsetSize
        FixedHeaderArchitectureFormat = $Layout.ArchitecturesEncoding
        UsesInt64BlockHeader          = $Layout.UsesInt64BlockHeader
        UsesLegacyCallTransform       = $Layout.UsesLegacyCallInstructionTransform
        OffsetTableVersion            = $OffsetTable.Version
        PascalScriptByteLength        = $ParsedLayout.CompiledCodeBytes.Length
        PascalScriptVersion           = $null -ne $PascalScriptInfo ? $PascalScriptInfo.FileVersion : $null
        PascalScriptStaticReturnPaths = $null -ne $PascalScriptInfo -and $null -ne $PascalScriptInfo.PSObject.Properties['StaticReturnExploredPathCount'] ? $PascalScriptInfo.StaticReturnExploredPathCount : 0
        PascalScriptStaticReturnForks = $null -ne $PascalScriptInfo -and $null -ne $PascalScriptInfo.PSObject.Properties['StaticReturnForkCount'] ? $PascalScriptInfo.StaticReturnForkCount : 0
        PascalScriptTruncatedPaths    = $null -ne $PascalScriptInfo -and $null -ne $PascalScriptInfo.PSObject.Properties['StaticReturnTruncatedPathCount'] ? $PascalScriptInfo.StaticReturnTruncatedPathCount : 0
      }
    }
  }
}

function Read-ProductVersionFromInno {
  <#
  .SYNOPSIS
    Read the product version from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $Info = Get-InnoInfo -Path $Path

    if (Test-InnoResolvedValue -Value $Info.AppVersion) { return $Info.AppVersion }

    $Match = [regex]::Match($Info.AppVerName, '(\d+(?:[.-]\d+)+)')
    if ($Match.Success) { return $Match.Groups[1].Value }

    throw 'The Inno Setup installer does not expose a deterministic version value'
  }
}

function Read-ProductNameFromInno {
  <#
  .SYNOPSIS
    Read the product name from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $Info = Get-InnoInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.DisplayName)) { throw 'The Inno Setup installer does not expose a product name' }
    return $Info.DisplayName
  }
}

function Read-PublisherFromInno {
  <#
  .SYNOPSIS
    Read the publisher from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $Info = Get-InnoInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.Publisher)) { throw 'The Inno Setup installer does not expose a publisher value' }
    return $Info.Publisher
  }
}

function Read-ProductCodeFromInno {
  <#
  .SYNOPSIS
    Read the built-in Apps & Features ProductCode from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $Info = Get-InnoInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.ProductCode)) { throw 'The Inno Setup installer does not expose a built-in Apps & Features ProductCode' }
    return $Info.ProductCode
  }
}

function Read-UnsupportedArchitecturesFromInno {
  <#
  .SYNOPSIS
    Read Windows architectures that an Inno Setup installer does not support
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    (Get-InnoInfo -Path $Path).UnsupportedArchitectures
  }
}

function Test-InnoUnsupportedArchitecture {
  <#
  .SYNOPSIS
    Test whether an Inno Setup installer does not support a Windows architecture
  .PARAMETER Path
    The path to the Inno Setup installer
  .PARAMETER Architecture
    The Windows architecture to test
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The Windows architecture to test')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  process {
    (Get-InnoInfo -Path $Path).UnsupportedArchitectures -contains $Architecture
  }
}

function Test-InnoAppsAndFeaturesEntry {
  <#
  .SYNOPSIS
    Test whether an Inno Setup installer writes its own Apps & Features registry entry
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    (Get-InnoInfo -Path $Path).WritesAppsAndFeaturesEntry
  }
}

function Expand-InnoInstaller {
  <#
  .SYNOPSIS
    Extract selected files from an unencrypted Inno Setup installer without executing it
  .PARAMETER Path
    The path to the Inno Setup installer
  .PARAMETER DestinationPath
    The directory where matching files should be written
  .PARAMETER Name
    Optional wildcard matched against source, destination, and base file names. All embedded files are selected when omitted.
  .PARAMETER Language
    An optional Inno Setup language name used to disambiguate language-specific payloads
  .PARAMETER CollisionAction
    Behavior when an output path already exists or multiple file entries resolve to the same path.
  .PARAMETER MaximumExpandedBytes
    Maximum aggregate bytes written, including aliases that share one payload location.
  .PARAMETER DiskSourcePath
    Optional directories or explicit setup-*.bin files used for external multi-disk media. The setup executable directory is searched automatically.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The directory where matching files should be written')]
    [string]$DestinationPath,

    [Parameter(HelpMessage = 'The source, destination, or base file wildcard to extract')]
    [string]$Name = '*',

    [Parameter(HelpMessage = 'An optional Inno Setup language name used to disambiguate language-specific payloads')]
    [string]$Language,

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Prompt',

    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumExpandedBytes = 17179869184,

    [Parameter(HelpMessage = 'Directories or explicit files containing external Inno Setup disk slices')]
    [string[]]$DiskSourcePath
  )

  process {
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $DestinationPath = Split-Path -Path $InstallerPath -Parent
    }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force

    $OffsetTable = Get-InnoOffsetTable -Path $InstallerPath

    $SignatureInfo = Get-InnoSignatureInfo -Path $InstallerPath -OffsetTable $OffsetTable
    $Layout = Get-InnoLayout -SignatureInfo $SignatureInfo -LoaderRoute $OffsetTable.LoaderRoute
    if ($Layout.SupportStatus -ne 'Supported') {
      throw "The Inno edition '$($Layout.Edition)' is identified but its record layout is not supported"
    }

    # Parse the first metadata block once to obtain counts, compression method,
    # encryption state, and the exact versioned file-entry layout.
    $ParsedLayout = Resolve-InnoParsedLayout -Path $InstallerPath -OffsetTable $OffsetTable -Layout $Layout
    $Layout = $ParsedLayout.Layout
    $HeaderBlockInfo = $ParsedLayout.HeaderBlockInfo
    if ($HeaderBlockInfo.EncryptionHeader.EncryptionUse -eq 'Files') {
      throw 'The Inno Setup payload files are encrypted and require the setup password'
    }
    $Header = $ParsedLayout.ExtractionHeader
    $HeaderFixedData = Read-InnoHeaderFixedData -Bytes $HeaderBlockInfo.Bytes -Layout $Layout
    if ($Header.Counts.NumFileLocationEntries -le 0) { throw 'The Inno Setup installer does not contain embedded file locations' }
    if ($Layout.InternalStructureVersion -lt 5303 -and $Name.IndexOfAny([char[]]'*?[') -lt 0) {
      # Exact selection can use the serialized path as a bounded index and
      # validate the complete surrounding record. This avoids traversing every
      # unrelated historical table when the caller requests one known payload.
      $FileEntries = @(
        Find-InnoFileEntry -Bytes $HeaderBlockInfo.Bytes -Layout $Layout -Name $Name `
          -FileLocationCount $Header.Counts.NumFileLocationEntries -SearchOffset $Header.SearchOffset -Language $Language
      )
    } else {
      $FileEntries = @(Get-InnoFileEntries -Bytes $HeaderBlockInfo.Bytes -Layout $Layout -Count $Header.Counts.NumFileEntries `
          -FileLocationCount $Header.Counts.NumFileLocationEntries -SearchOffset $Header.SearchOffset)
    }
    $SelectedEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($Entry in $FileEntries) {
      if ($Entry.LocationEntry -lt 0) { continue }
      # Compiler-generated entries, including the uninstaller payload, can
      # omit SourceFilename. Only match populated fields so the shared pattern
      # helper never receives an invalid empty path.
      $MatchesName = -not [string]::IsNullOrWhiteSpace($Entry.SourceFilename) -and
      (Test-ExtractionPattern -Path $Entry.SourceFilename -Pattern $Name)
      if (-not $MatchesName -and -not [string]::IsNullOrWhiteSpace($Entry.DestName)) {
        $MatchesName = Test-ExtractionPattern -Path $Entry.DestName -Pattern $Name
      }
      if (-not $MatchesName) { continue }
      if (-not [string]::IsNullOrWhiteSpace($Language) -and -not [string]::IsNullOrWhiteSpace($Entry.Languages)) {
        $LanguageMatch = @($Entry.Languages -split '[,\s]+' | Where-Object { $_ -ieq $Language }).Count -gt 0
        if (-not $LanguageMatch) { continue }
      }
      $SelectedEntries.Add($Entry)
    }
    if ($SelectedEntries.Count -eq 0) { throw "No Inno Setup file entry matched: $Name" }

    $FileStream = [System.IO.File]::OpenRead($InstallerPath)
    $Reader = [System.IO.BinaryReader]::new($FileStream)
    try {
      $LocationBlockInfo = Read-InnoMetadataBlock -Reader $Reader -Offset $HeaderBlockInfo.NextOffset -Layout $Layout
    } finally {
      $Reader.Close()
      $FileStream.Close()
    }

    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $LocationOutput = [Collections.Generic.Dictionary[int, string]]::new()
    $LocationCache = [Collections.Generic.Dictionary[int, object]]::new()
    $Files = [Collections.Generic.List[IO.FileInfo]]::new()
    $ExpandedBytes = 0L
    foreach ($Entry in $SelectedEntries) {
      # DestName is an explicit installed path override. Otherwise the compiled
      # SourceFilename contains the destination beneath an Inno constant such
      # as {app}; remove that virtual root but preserve its subdirectories.
      $RelativePath = if ([string]::IsNullOrWhiteSpace($Entry.DestName)) {
        $Entry.SourceFilename
      } else {
        $Entry.DestName
      }
      if ($RelativePath -match '^\{[^}]+\}[\\/](.+)$') {
        $RelativePath = $Matches[1]
      }
      if ([string]::IsNullOrWhiteSpace($RelativePath)) {
        throw "The Inno Setup file entry at offset $($Entry.RecordOffset) has no extractable path"
      }
      $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath `
        -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
      if (-not $Target.ShouldWrite) { continue }

      $Location = $null
      if (-not $LocationCache.TryGetValue($Entry.LocationEntry, [ref]$Location)) {
        $Location = Read-InnoFileLocation -Bytes $LocationBlockInfo.Bytes -Count $Header.Counts.NumFileLocationEntries `
          -Index $Entry.LocationEntry -Layout $Layout
        $LocationCache[$Entry.LocationEntry] = $Location
      }
      if ($Location.OriginalSize -gt $MaximumExpandedBytes - $ExpandedBytes) {
        throw "The selected Inno Setup payloads exceed the $MaximumExpandedBytes-byte limit"
      }

      $ExistingPath = $null
      if ($LocationOutput.TryGetValue($Entry.LocationEntry, [ref]$ExistingPath)) {
        # Several [Files] entries may install the same physical location under
        # aliases. Reuse the authenticated first output instead of decoding the
        # same solid chunk from its beginning for every alias.
        $Source = [IO.File]::Open($ExistingPath, 'Open', 'Read', 'Read')
        $Parent = [IO.Path]::GetDirectoryName($Target.Path)
        if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
        $Destination = [IO.File]::Open($Target.Path, 'Create', 'Write', 'None')
        try {
          $null = Copy-BoundedStream -Source $Source -Destination $Destination -MaximumBytes $Location.OriginalSize -ExpectedBytes $Location.OriginalSize
        } finally {
          $Destination.Dispose()
          $Source.Dispose()
        }
        $File = Get-Item -LiteralPath $Target.Path -Force
      } else {
        $CompressionMethod = if ([string]::IsNullOrWhiteSpace($HeaderFixedData.CompressMethod)) {
          Get-InnoPayloadCompressionMethod -Path $InstallerPath -Offset1 $OffsetTable.Offset1 -Location $Location -Layout $Layout `
            -SlicesPerDisk $HeaderFixedData.SlicesPerDisk -DiskSourcePath $DiskSourcePath
        } else { $HeaderFixedData.CompressMethod }
        $File = Write-InnoFilePayload -Path $InstallerPath -Offset1 $OffsetTable.Offset1 -Location $Location `
          -CompressionMethod $CompressionMethod -OutputPath $Target.Path -PayloadRoute $Layout.PayloadRoute `
          -CallTransformRoute $Layout.CallTransformRoute -InternalStructureVersion $Layout.InternalStructureVersion `
          -SlicesPerDisk $HeaderFixedData.SlicesPerDisk -DiskSourcePath $DiskSourcePath
        $LocationOutput[$Entry.LocationEntry] = $File.FullName
      }
      $ExpandedBytes += $File.Length
      $Files.Add($File)
    }
    return $Files.ToArray()
  }
}

Export-ModuleMember -Function Get-InnoFormatInfo, Get-InnoInfo, Get-InnoPascalScriptInfo, Read-ProductVersionFromInno, Read-ProductNameFromInno, Read-PublisherFromInno, Read-ProductCodeFromInno, Read-UnsupportedArchitecturesFromInno, Test-InnoUnsupportedArchitecture, Test-InnoAppsAndFeaturesEntry, Expand-InnoInstaller
