# SPDX-License-Identifier: GPL-3.0-or-later
# Internal SetupFactory implementation. See SetupFactory.psm1 for format sources and the binary layout.
# Parsed operation contexts are passed explicitly; no caller-owned stream is retained globally.

# SetupFactory Actions layer. Internal modules are imported locally; public commands stay in the facade.
Import-Module (Join-Path $PSScriptRoot 'SetupFactoryProject.psm1') -ErrorAction Stop

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

Set-StrictMode -Version 3.0

$Script:SetupFactoryMaximumEntries = 100000

$Script:SetupFactoryActionNames6 = @{
  0 = 'Latest Version'; 1 = 'Download (FTP)'; 2 = 'HTTP Download'; 3 = 'Execute'; 4 = 'Open Document'; 5 = 'Unzip Files'; 6 = 'Close Program'
  7 = 'Copy Files'; 8 = 'Delete Files'; 9 = 'Rename File'; 10 = 'Create Directory'; 11 = 'Remove Directory'; 12 = 'Read from Registry'
  13 = 'Read from INI File'; 14 = 'Assign Value'; 17 = 'Modify Registry'; 18 = 'Modify INI File'; 19 = 'Submit to Web'; 20 = 'Show Message Box'
  21 = 'Read File Association'; 22 = 'Abort Setup'; 24 = 'Send Email'; 26 = 'Upload File FTP'; 28 = 'Show Yes/No Dialog'; 29 = 'Read File Information'
  30 = 'Find String'; 31 = 'Mid String'; 32 = 'Left String'; 33 = 'Right String'; 34 = 'Length of String'; 35 = 'Move Files'; 36 = 'Read Text File'
  37 = 'Write to Text File'; 38 = 'Generate Random Value'; 39 = 'Zip Files'; 42 = 'Count Text Lines'; 43 = 'Delete Text Line'; 44 = 'Find Text Line'
  45 = 'Get Text Line'; 46 = 'Insert Text Line'; 50 = 'Create Shortcut'; 51 = 'Remove Shortcut'; 52 = 'Install File'; 53 = 'Register File'
  54 = 'Register Font'; 55 = 'Check Internet Connection'; 56 = 'Set File Attributes'; 57 = 'Stop Service'; 58 = 'Pause Service'; 59 = 'Continue Service'
  60 = 'Delete Service'; 61 = 'Query Service'; 62 = 'Start Service'; 63 = 'Create Service'; 70 = 'Count Delimited Strings'; 71 = 'Get Delimited String'
  72 = 'Parse Path'; 73 = 'Search for File'; 74 = 'Move File on Reboot'; 75 = 'Delete File on Reboot'; 76 = 'Run File on Reboot'
  77 = 'Call DLL Function'; 78 = 'Format Number'; 79 = 'Write to Log File'; 80 = 'Get Disk Space'; 100 = 'IF'; 101 = 'END IF'; 102 = 'WHILE'
  103 = 'END WHILE'; 104 = 'GOTO Label'; 105 = 'Label'; 200 = 'Comment'; 201 = 'Blank line'
}

function Get-SetupFactoryLegacyConditionState5 {
  <#
  .SYNOPSIS
    Reduce Setup Factory 5 command selectors to a conservative three-valued state.
  .PARAMETER OperatingSystemMask
    Serialized 32-bit operating-system selector. All bits set means every supported system; zero rejects every system.
  .PARAMETER PackageSelector
    Serialized package selector. Zero means that the command is not tied to an optional package.
  .PARAMETER LanguageSelector
    Serialized language name. Empty and None apply to every runtime language.
  .PARAMETER Conditions
    Decoded CConditionData comparisons. Their operands can depend on runtime variables, so a non-empty list remains Unknown.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][uint32]$OperatingSystemMask,
    [Parameter(Mandatory)][uint32]$PackageSelector,
    [AllowEmptyString()][string]$LanguageSelector,
    [AllowEmptyCollection()][object[]]$Conditions = @()
  )

  if ($OperatingSystemMask -eq 0) { return 'False' }
  if ($OperatingSystemMask -ne [uint32]::MaxValue -or $PackageSelector -ne 0 -or $LanguageSelector -notin '', 'None' -or $Conditions.Count) { return 'Unknown' }
  return 'True'
}

function Get-SetupFactoryLegacyActionPhase5 {
  <#
  .SYNOPSIS
    Resolve a Setup Factory 5 command timing code or generated-uninstaller placement.
  .PARAMETER TableOffset
    Offset of the owning MFC table relative to decompressed irsetup.dat.
  .PARAMETER UninstallOffset
    Offset where the generated-uninstaller configuration begins.
  .PARAMETER TimingCode
    Source-backed Execute/File Operation timing enum used by installation commands.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][long]$TableOffset,
    [Parameter(Mandatory)][long]$UninstallOffset,
    [Parameter(Mandatory)][uint32]$TimingCode
  )

  if ($TableOffset -ge $UninstallOffset) { return 'Uninstall' }
  switch ($TimingCode) {
    0 { return 'Startup' }
    1 { return 'BeforeInstalling' }
    2 { return 'AfterInstalling' }
    3 { return 'Shutdown' }
    default { return 'Unknown' }
  }
}

function Get-SetupFactoryLegacyObjectTable {
  <#
  .SYNOPSIS
    Decode one declared MFC object table from legacy irsetup.dat data.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER ClassName
    Exact MFC runtime class name expected in the table declaration.
  .PARAMETER RecordReader
    Private record-reader function that accepts Bytes and a mutable Offset reference.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateSet('CExecuteData', 'CFileOpData', 'CINIData', 'CVarRegistry')][string]$ClassName,
    [Parameter(Mandatory)][ValidateSet('Read-SetupFactoryExecuteRecord5', 'Read-SetupFactoryFileOperationRecord5', 'Read-SetupFactoryIniRecord4', 'Read-SetupFactoryIniRecord5', 'Read-SetupFactoryRegistryVariableRecord5')][string]$RecordReader
  )

  $Marker = [Text.Encoding]::ASCII.GetBytes($ClassName)
  foreach ($MarkerOffset in @(Find-BinaryPattern -Bytes $Bytes -Pattern $Marker -Maximum 16)) {
    # MFC CObList framing is [count:u16][new-class:FFFF][schema:u16][name-length:u16][name].
    # Matching the full declaration avoids treating diagnostic strings in project data as tables.
    if ($MarkerOffset -lt 8 -or [BitConverter]::ToUInt16($Bytes, $MarkerOffset - 6) -ne 0xFFFF -or [BitConverter]::ToUInt16($Bytes, $MarkerOffset - 4) -ne 1 -or [BitConverter]::ToUInt16($Bytes, $MarkerOffset - 2) -ne $Marker.Length) { continue }
    $Count = [int][BitConverter]::ToUInt16($Bytes, $MarkerOffset - 8)
    if ($Count -le 0 -or $Count -gt $Script:SetupFactoryMaximumEntries) { continue }

    $Entries = [Collections.Generic.List[object]]::new($Count)
    $Cursor = [ref]([long]($MarkerOffset + $Marker.Length))
    $ClassReference = $null
    $ErrorMessage = $null
    for ($Index = 0; $Index -lt $Count; $Index++) {
      try {
        $ObjectReference = [uint16]0xFFFF
        if ($Index -gt 0) {
          $ObjectReference = [uint16](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Cursor -Size 2)
          if (($ObjectReference -band 0x8000) -eq 0) { throw "The $ClassName object reference is invalid" }
          if ($null -eq $ClassReference) { $ClassReference = $ObjectReference }
          elseif ($ObjectReference -ne $ClassReference) { throw "The $ClassName object reference changed inside the table" }
        }
        $Record = & $RecordReader -Bytes $Bytes -Offset $Cursor
        $Record | Add-Member -NotePropertyName ObjectReference -NotePropertyValue $ObjectReference
        $Entries.Add($Record)
      } catch {
        $ErrorMessage = $_.Exception.Message
        break
      }
    }

    return [pscustomobject][ordered]@{
      IsPresent       = $true
      IsComplete      = $Entries.Count -eq $Count -and -not $ErrorMessage
      Error           = $ErrorMessage
      ClassName       = $ClassName
      MarkerOffset    = [long]$MarkerOffset
      EndOffset       = [long]$Cursor.Value
      DeclaredCount   = $Count
      ClassReference  = $ClassReference
      Entries         = $Entries.ToArray()
      UnresolvedCount = ($Count - $Entries.Count)
    }
  }

  return [pscustomobject][ordered]@{ IsPresent = $false; IsComplete = $true; Error = $null; ClassName = $ClassName; MarkerOffset = $null; EndOffset = $null; DeclaredCount = 0; ClassReference = $null; Entries = @(); UnresolvedCount = 0 }
}

function Read-SetupFactoryExecuteRecord5 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 5 CExecuteData command.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable offset positioned after the owning MFC class tag or object reference.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Offset)

  $StartOffset = [long]$Offset.Value
  $Action = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $Target = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Arguments = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $WorkingDirectory = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $WaitCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $RunModeCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $PromptForDiskCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $DiskTitle = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $TimingCode = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $ObservedFlag16 = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $OperatingSystemMask = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $PackageSelector = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $LanguageSelector = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $ConditionCount = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 2)
  $Conditions = @(Read-SetupFactoryConditionList5 -Bytes $Bytes -Offset $Offset -Count $ConditionCount)
  $ObservedIntegers = [uint32[]](1..4 | ForEach-Object { Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4 })
  $ObservedStrings = [string[]](1..4 | ForEach-Object { Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable })
  foreach ($Text in @($Target, $Arguments, $WorkingDirectory, $DiskTitle, $LanguageSelector) + $ObservedStrings) {
    if (-not (Test-SetupFactoryLegacyMetadataText -Value $Text)) { throw 'The Setup Factory 5 execute command contains invalid text' }
  }

  [pscustomobject][ordered]@{
    Offset               = $StartOffset
    EndOffset            = [long]$Offset.Value
    Action               = $Action
    ActionName           = @('ExecuteProgram', 'OpenDocument', 'OpenUrl', 'PrintDocument', 'ExploreFolder', 'PlayMultimedia')[$Action]
    Category             = 'Execution'
    Target               = $Target
    Arguments            = $Arguments
    WorkingDirectory     = $WorkingDirectory
    WaitForProgram       = $WaitCode -in 0, 1 ? [bool]$WaitCode : $null
    WaitCode             = $WaitCode
    RunModeCode          = $RunModeCode
    RunMode              = @('Normal', 'Maximized', 'Minimized')[$RunModeCode]
    PromptForDisk        = $PromptForDiskCode -in 0, 1 ? [bool]$PromptForDiskCode : $null
    PromptForDiskCode    = $PromptForDiskCode
    DiskTitle            = $DiskTitle
    TimingCode           = $TimingCode
    ObservedFlag16       = $ObservedFlag16
    OperatingSystemMask  = $OperatingSystemMask
    PackageSelector      = $PackageSelector
    LanguageSelector     = $LanguageSelector
    ConditionCount       = $ConditionCount
    Conditions           = $Conditions
    ConditionState       = Get-SetupFactoryLegacyConditionState5 -OperatingSystemMask $OperatingSystemMask -PackageSelector $PackageSelector -LanguageSelector $LanguageSelector -Conditions $Conditions
    ObservedPolicyValues = $ObservedIntegers
    ObservedPolicyText   = $ObservedStrings
  }
}

function Read-SetupFactoryFileOperationRecord5 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 5 CFileOpData command.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable offset positioned after the owning MFC class tag or object reference.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Offset)

  $StartOffset = [long]$Offset.Value
  $Action = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $Source = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Destination = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $ConfirmCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $SuppressErrorsCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $PromptForDiskCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $DiskTitle = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $TimingCode = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $OperatingSystemMask = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $PackageSelector = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $LanguageSelector = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $ConditionCount = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 2)
  $Conditions = @(Read-SetupFactoryConditionList5 -Bytes $Bytes -Offset $Offset -Count $ConditionCount)
  $ObservedIntegers = [uint32[]](1..4 | ForEach-Object { Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4 })
  $ObservedStrings = [string[]](1..4 | ForEach-Object { Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable })
  foreach ($Text in @($Source, $Destination, $DiskTitle, $LanguageSelector) + $ObservedStrings) {
    if (-not (Test-SetupFactoryLegacyMetadataText -Value $Text)) { throw 'The Setup Factory 5 file operation contains invalid text' }
  }

  [pscustomobject][ordered]@{
    Offset               = $StartOffset
    EndOffset            = [long]$Offset.Value
    Action               = $Action
    ActionName           = @('Copy', 'Delete', 'Move', 'Rename', 'MakeDirectory', 'RemoveDirectory')[$Action]
    Category             = 'FileSystem'
    Source               = $Source
    Destination          = $Destination
    ConfirmWithUser      = $ConfirmCode -in 0, 1 ? [bool]$ConfirmCode : $null
    ConfirmCode          = $ConfirmCode
    SuppressErrors       = $SuppressErrorsCode -in 0, 1 ? [bool]$SuppressErrorsCode : $null
    SuppressErrorsCode   = $SuppressErrorsCode
    PromptForDisk        = $PromptForDiskCode -in 0, 1 ? [bool]$PromptForDiskCode : $null
    PromptForDiskCode    = $PromptForDiskCode
    DiskTitle            = $DiskTitle
    TimingCode           = $TimingCode
    OperatingSystemMask  = $OperatingSystemMask
    PackageSelector      = $PackageSelector
    LanguageSelector     = $LanguageSelector
    ConditionCount       = $ConditionCount
    Conditions           = $Conditions
    ConditionState       = Get-SetupFactoryLegacyConditionState5 -OperatingSystemMask $OperatingSystemMask -PackageSelector $PackageSelector -LanguageSelector $LanguageSelector -Conditions $Conditions
    ObservedPolicyValues = $ObservedIntegers
    ObservedPolicyText   = $ObservedStrings
  }
}

function Read-SetupFactoryIniRecord4 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 4 CINIData command.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable offset positioned after the owning MFC class tag or object reference.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Offset)

  $StartOffset = [long]$Offset.Value
  $Action = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $FileName = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Section = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Key = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Value = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $OperatingSystemMask = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $LanguageSelector = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  foreach ($Text in $FileName, $Section, $Key, $Value, $LanguageSelector) {
    if (-not (Test-SetupFactoryLegacyMetadataText -Value $Text)) { throw 'The Setup Factory 4 INI command contains invalid text' }
  }
  $ConditionState = if ($OperatingSystemMask -eq 0) { 'False' } elseif ($OperatingSystemMask -eq 0x1F -and $LanguageSelector -in '', 'None') { 'True' } else { 'Unknown' }

  [pscustomobject][ordered]@{
    Offset                = $StartOffset
    EndOffset             = [long]$Offset.Value
    Action                = $Action
    ActionName            = $Action -eq 1 ? 'SetValue' : $null
    Category              = 'Ini'
    FileName              = $FileName
    Section               = $Section
    Key                   = $Key
    Value                 = $Value
    OperatingSystemMask   = $OperatingSystemMask
    OperatingSystemPolicy = Get-SetupFactoryLegacyOperatingSystemPolicy -Generation Classic4 -Mask $OperatingSystemMask
    LanguageSelector      = $LanguageSelector
    ConditionState        = $ConditionState
  }
}

function Read-SetupFactoryIniRecord5 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 5 CINIData command.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable offset positioned after the owning MFC class tag or object reference.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Offset)

  $StartOffset = [long]$Offset.Value
  $Action = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $FileName = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Section = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Key = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Value = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $ExistingValueAction = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $Separator = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Flags = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $OperatingSystemMask = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $PackageSelector = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $LanguageSelector = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $ConditionCount = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 2)
  $Conditions = @(Read-SetupFactoryConditionList5 -Bytes $Bytes -Offset $Offset -Count $ConditionCount)
  $ObservedIntegers = [uint32[]](1..4 | ForEach-Object { Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4 })
  $ObservedStrings = [string[]](1..4 | ForEach-Object { Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable })
  foreach ($Text in @($FileName, $Section, $Key, $Value, $Separator, $LanguageSelector) + $ObservedStrings) {
    if (-not (Test-SetupFactoryLegacyMetadataText -Value $Text)) { throw 'The Setup Factory 5 INI command contains invalid text' }
  }

  [pscustomobject][ordered]@{
    Offset                  = $StartOffset
    EndOffset               = [long]$Offset.Value
    Action                  = $Action
    ActionName              = @('SetValue', 'DeleteKey', 'DeleteSection')[$Action]
    Category                = 'Ini'
    FileName                = $FileName
    Section                 = $Section
    Key                     = $Key
    Value                   = $Value
    ExistingValueAction     = $ExistingValueAction
    ExistingValueActionName = @('Overwrite', 'DoNotOverwrite', 'Prepend', 'PrependIfMissing', 'Append', 'AppendIfMissing', 'Increment', 'Decrement')[$ExistingValueAction]
    Separator               = $Separator
    Flags                   = $Flags
    OperatingSystemMask     = $OperatingSystemMask
    PackageSelector         = $PackageSelector
    LanguageSelector        = $LanguageSelector
    ConditionCount          = $ConditionCount
    Conditions              = $Conditions
    ConditionState          = Get-SetupFactoryLegacyConditionState5 -OperatingSystemMask $OperatingSystemMask -PackageSelector $PackageSelector -LanguageSelector $LanguageSelector -Conditions $Conditions
    ObservedPolicyValues    = $ObservedIntegers
    ObservedPolicyText      = $ObservedStrings
  }
}

function Read-SetupFactoryRegistryVariableRecord5 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 5 CVarRegistry variable source.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable offset positioned after the owning MFC class tag or object reference.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Offset)

  $StartOffset = [long]$Offset.Value
  $VariableName = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $RootCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $Key = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $ValueName = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $UseKeyExistenceCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $DefaultValue = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $ObservedIntegers = [uint32[]](1..4 | ForEach-Object { Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4 })
  $ObservedStrings = [string[]](1..4 | ForEach-Object { Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable })
  foreach ($Text in @($VariableName, $Key, $ValueName, $DefaultValue) + $ObservedStrings) {
    if (-not (Test-SetupFactoryLegacyMetadataText -Value $Text)) { throw 'The Setup Factory 5 registry variable contains invalid text' }
  }

  [pscustomobject][ordered]@{
    Offset               = $StartOffset
    EndOffset            = [long]$Offset.Value
    Category             = 'VariableRead'
    VariableName         = $VariableName
    RootCode             = $RootCode
    Root                 = ConvertTo-SetupFactoryRegistryRoot -Value $RootCode -Generation Legacy5
    Key                  = $Key
    ValueName            = $ValueName
    UseKeyExistence      = $UseKeyExistenceCode -in 0, 1 ? [bool]$UseKeyExistenceCode : $null
    UseKeyExistenceCode  = $UseKeyExistenceCode
    DefaultValue         = $DefaultValue
    ObservedPolicyValues = $ObservedIntegers
    ObservedPolicyText   = $ObservedStrings
  }
}

function Get-SetupFactoryActionCatalog4 {
  <#
  .SYNOPSIS
    Compose Setup Factory 4 registry and INI command evidence.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER UninstallOffset
    Start of the generated-uninstaller configuration.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][long]$UninstallOffset)

  $Registry = Get-SetupFactoryRegistryCatalog4 -Bytes $Bytes
  $Ini = Get-SetupFactoryLegacyObjectTable -Bytes $Bytes -ClassName CINIData -RecordReader Read-SetupFactoryIniRecord4
  foreach ($Entry in $Ini.Entries) { $Entry | Add-Member -NotePropertyName Phase -NotePropertyValue ($Ini.MarkerOffset -ge $UninstallOffset ? 'Uninstall' : 'Install') }
  $UnknownActions = @($Ini.Entries | Where-Object { -not $_.ActionName })
  $Errors = @($Registry.Error, $Ini.Error) | Where-Object { $_ }

  [pscustomobject][ordered]@{
    IsPresent                  = $Registry.IsPresent -or $Ini.IsPresent
    IsComplete                 = $Registry.IsComplete -and $Ini.IsComplete
    Error                      = $Errors -join '; '
    DeclaredCount              = $Registry.DeclaredCount + $Ini.DeclaredCount
    Entries                    = [object[]]@($Registry.Entries) + [object[]]@($Ini.Entries)
    RegistryWrites             = $Registry.RegistryWrites
    RegistryCatalog            = $Registry
    IniCatalog                 = $Ini
    VariableAssignments        = @()
    ExecutionActions           = @()
    FileSystemActions          = @()
    IniActions                 = $Ini.Entries
    VariableReads              = @()
    UserInteractionActions     = @()
    InstallabilityActions      = @()
    ShortcutActions            = @()
    ServiceActions             = @()
    RebootActions              = @()
    ExternalCodeActions        = @()
    UnknownActions             = $UnknownActions
    UnresolvedCount            = $Registry.UnresolvedCount
    UnresolvedActionCount      = $Ini.UnresolvedCount + $UnknownActions.Count
    UnresolvedControlFlowCount = 0
  }
}

function Get-SetupFactoryActionCatalog5 {
  <#
  .SYNOPSIS
    Compose Setup Factory 5 registry, execute, file-operation, INI, and registry-variable evidence.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER UninstallOffset
    Start of the generated-uninstaller configuration.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][long]$UninstallOffset)

  $Registry = Get-SetupFactoryRegistryCatalog5 -Bytes $Bytes -UninstallOffset $UninstallOffset
  $Execute = Get-SetupFactoryLegacyObjectTable -Bytes $Bytes -ClassName CExecuteData -RecordReader Read-SetupFactoryExecuteRecord5
  $FileOperation = Get-SetupFactoryLegacyObjectTable -Bytes $Bytes -ClassName CFileOpData -RecordReader Read-SetupFactoryFileOperationRecord5
  $Ini = Get-SetupFactoryLegacyObjectTable -Bytes $Bytes -ClassName CINIData -RecordReader Read-SetupFactoryIniRecord5
  $RegistryVariable = Get-SetupFactoryLegacyObjectTable -Bytes $Bytes -ClassName CVarRegistry -RecordReader Read-SetupFactoryRegistryVariableRecord5

  foreach ($Entry in $Execute.Entries) { $Entry | Add-Member -NotePropertyName Phase -NotePropertyValue (Get-SetupFactoryLegacyActionPhase5 -TableOffset $Execute.MarkerOffset -UninstallOffset $UninstallOffset -TimingCode $Entry.TimingCode) }
  foreach ($Entry in $FileOperation.Entries) { $Entry | Add-Member -NotePropertyName Phase -NotePropertyValue (Get-SetupFactoryLegacyActionPhase5 -TableOffset $FileOperation.MarkerOffset -UninstallOffset $UninstallOffset -TimingCode $Entry.TimingCode) }
  foreach ($Entry in $Ini.Entries) { $Entry | Add-Member -NotePropertyName Phase -NotePropertyValue ($Ini.MarkerOffset -ge $UninstallOffset ? 'Uninstall' : 'Install') }
  foreach ($Entry in $RegistryVariable.Entries) { $Entry | Add-Member -NotePropertyName Phase -NotePropertyValue 'VariableResolution' }

  $Tables = @($Registry, $Execute, $FileOperation, $Ini, $RegistryVariable)
  $AllEntries = [object[]]@($Registry.Entries) + [object[]]@($Execute.Entries) + [object[]]@($FileOperation.Entries) + [object[]]@($Ini.Entries) + [object[]]@($RegistryVariable.Entries)
  $UnknownActions = @($Execute.Entries + $FileOperation.Entries + $Ini.Entries | Where-Object { $_.PSObject.Properties['ActionName'] -and -not $_.ActionName })
  $UserInteractionActions = @($Execute.Entries + $FileOperation.Entries | Where-Object { $_.PromptForDisk -eq $true -or ($_.PSObject.Properties['ConfirmWithUser'] -and $_.ConfirmWithUser -eq $true) })
  $Errors = @($Tables.Error | Where-Object { $_ })

  [pscustomobject][ordered]@{
    IsPresent                  = @($Tables | Where-Object IsPresent).Count -gt 0
    IsComplete                 = @($Tables | Where-Object { -not $_.IsComplete }).Count -eq 0
    Error                      = $Errors -join '; '
    DeclaredCount              = ($Tables.DeclaredCount | Measure-Object -Sum).Sum
    Entries                    = $AllEntries
    RegistryWrites             = $Registry.RegistryWrites
    RegistryCatalog            = $Registry
    ExecuteCatalog             = $Execute
    FileOperationCatalog       = $FileOperation
    IniCatalog                 = $Ini
    RegistryVariableCatalog    = $RegistryVariable
    VariableAssignments        = @()
    ExecutionActions           = $Execute.Entries
    FileSystemActions          = $FileOperation.Entries
    IniActions                 = $Ini.Entries
    VariableReads              = $RegistryVariable.Entries
    UserInteractionActions     = $UserInteractionActions
    InstallabilityActions      = $UserInteractionActions
    ShortcutActions            = @()
    ServiceActions             = @()
    RebootActions              = @()
    ExternalCodeActions        = @()
    UnknownActions             = $UnknownActions
    UnresolvedCount            = $Registry.UnresolvedCount
    UnresolvedActionCount      = ($Tables.UnresolvedCount | Measure-Object -Sum).Sum + $UnknownActions.Count
    UnresolvedControlFlowCount = 0
  }
}

function Get-SetupFactoryActionDescriptor6 {
  <#
  .SYNOPSIS
    Identify one Setup Factory 6 action ID using the builder runtime's action vocabulary.
  .PARAMETER ActionId
    Numeric CAction identifier stored in member I04.
  .OUTPUTS
    Action name, broad behavior category, and projection status. Unknown IDs remain explicit instead of receiving guessed semantics.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][ValidateRange(0, 1024)][int]$ActionId)

  $Name = $Script:SetupFactoryActionNames6[$ActionId]
  $Category = switch ($ActionId) {
    { $_ -in 0, 1, 2, 19, 24, 26, 55 } { 'Network'; break }
    { $_ -in 3, 4 } { 'Execution'; break }
    { $_ -in 5, 7, 8, 9, 10, 11, 18, 23, 35, 36, 37, 39, 42, 43, 44, 45, 46, 50, 51, 52, 53, 54, 56 } { 'FileSystem'; break }
    { $_ -in 6 } { 'Process'; break }
    { $_ -in 12, 17, 21 } { 'Registry'; break }
    { $_ -in 13, 14, 29, 30, 31, 32, 33, 34, 38, 70, 71, 72, 73, 78, 80 } { 'Data'; break }
    { $_ -in 20, 28 } { 'UserInteraction'; break }
    { $_ -in 22, 100, 101, 102, 103, 104, 105 } { 'ControlFlow'; break }
    { $_ -in 57, 58, 59, 60, 61, 62, 63 } { 'Service'; break }
    { $_ -in 74, 75, 76 } { 'Reboot'; break }
    { $_ -in 77 } { 'ExternalCode'; break }
    { $_ -in 79, 200, 201 } { 'Informational'; break }
    default { 'Unknown' }
  }
  $ProjectionStatus = if ($ActionId -in 3, 4, 12, 14, 17, 28, 50, 74, 75, 76, 77, 100, 102, 104, 105, 200) { 'Decoded' }
  elseif ($Name) { 'Catalogued' }
  else { 'Unknown' }

  [pscustomobject][ordered]@{
    Name             = $Name
    Category         = $Category
    ProjectionStatus = $ProjectionStatus
  }
}

function Get-SetupFactoryActionDetails6 {
  <#
  .SYNOPSIS
    Project source-backed CAction members into named operands for selected Setup Factory 6 actions.
  .PARAMETER ActionId
    Numeric action identifier.
  .PARAMETER Fields
    Complete generic CAction member map decoded by Read-SetupFactoryActionRecord6.
  .OUTPUTS
    A named operand object for actions whose member meanings are established by the 6.0 builder runtime, or null when only action identity is known.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][ValidateRange(0, 1024)][int]$ActionId,
    [Parameter(Mandatory)][pscustomobject]$Fields
  )

  $Values = switch ($ActionId) {
    3 { [ordered]@{ FilePath = [string]$Fields.S0C; Arguments = [string]$Fields.S2C; WorkingDirectory = [string]$Fields.S30; RunMode = [int]$Fields.I38; WaitForReturn = [bool]$Fields.I34 }; break }
    4 { [ordered]@{ FilePath = [string]$Fields.S0C; Verb = [string]$Fields.S3C; WorkingDirectory = [string]$Fields.S30; RunMode = [int]$Fields.I38 }; break }
    12 { [ordered]@{ VariableName = [string]$Fields.S60; DefaultValue = [string]$Fields.S64; Root = ConvertTo-SetupFactoryRegistryRoot -Value ([int]$Fields.I78) -Generation Legacy6; SubKey = [string]$Fields.S74; ValueName = [string]$Fields.S68; TrueIfExists = [bool]$Fields.I6C; ExpandEnvironmentStrings = [bool]$Fields.I98 }; break }
    14 { [ordered]@{ VariableName = [string]$Fields.S60; Value = [string]$Fields.S58; EvaluateAsExpression = [bool]$Fields.I6C }; break }
    17 {
      $OperationId = [int]$Fields.I38
      [ordered]@{ Operation = $OperationId -in 0..3 ? @('CreateKey', 'DeleteKey', 'SetValue', 'DeleteValue')[$OperationId] : $null; OperationId = $OperationId; Root = ConvertTo-SetupFactoryRegistryRoot -Value ([int]$Fields.I78) -Generation Legacy6; SubKey = [string]$Fields.S74; ValueName = [string]$Fields.S58; Value = [string]$Fields.S68; Type = ConvertTo-SetupFactoryRegistryValueType -Value ([int]$Fields.I90) -Generation Legacy6 }
      break
    }
    28 { [ordered]@{ Title = [string]$Fields.S64; Message = [string]$Fields.S68; ResultVariable = [string]$Fields.S60; YesValue = [string]$Fields.SA0; NoValue = [string]$Fields.SA4 }; break }
    50 { [ordered]@{ Folder = [string]$Fields.S58; Description = [string]$Fields.S68; TargetPath = [string]$Fields.S0C; Arguments = [string]$Fields.S2C; WorkingDirectory = [string]$Fields.S30; IconIndex = [int]$Fields.I98; ExternalIconPath = [string]$Fields.SA0; RunMode = [int]$Fields.I38 }; break }
    74 { [ordered]@{ SourcePath = [string]$Fields.S58; DestinationPath = [string]$Fields.S5C }; break }
    75 { [ordered]@{ FilePath = [string]$Fields.S58 }; break }
    76 { [ordered]@{ FilePath = [string]$Fields.S58; Arguments = [string]$Fields.S2C }; break }
    77 { [ordered]@{ DllPath = [string]$Fields.S0C; FunctionName = [string]$Fields.S08; Arguments = [string]$Fields.S2C; ReturnType = [int]$Fields.I38 }; break }
    100 { [ordered]@{ Expression = [string]$Fields.S54 }; break }
    102 { [ordered]@{ Expression = [string]$Fields.S54 }; break }
    104 { [ordered]@{ TargetLabel = [string]$Fields.S5C }; break }
    105 { [ordered]@{ Label = [string]$Fields.S5C }; break }
    200 { [ordered]@{ Text = [string]$Fields.S68 }; break }
    default { $null }
  }
  if ($null -ne $Values) { [pscustomobject]$Values }
}

function Resolve-SetupFactoryActionCondition6 {
  <#
  .SYNOPSIS
    Resolve the Boolean subset of a Setup Factory 6 action expression.
  .PARAMETER Expression
    CAction condition text using Setup Factory variables and textual or symbolic Boolean operators.
  .PARAMETER IdentifierState
    Known three-valued states accumulated from earlier literal Boolean assignments in the same uncertainties-free action path.
  .OUTPUTS
    The shared Boolean-evaluator result augmented with the original and normalized expressions.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][AllowEmptyString()][string]$Expression,
    [Parameter(Mandatory)][Collections.IDictionary]$IdentifierState
  )

  # The Setup Factory editor serializes AND/OR/NOT and wraps built-in variables in percent signs.
  # Normalize only that Boolean surface syntax; comparisons, arithmetic, functions, and quoted
  # values intentionally remain unsupported and resolve to Unknown.
  $NormalizedExpression = $Expression -replace '(?i)\bAND\b', '&&' -replace '(?i)\bOR\b', '||' -replace '(?i)\bNOT\b', '!'
  $NormalizedStates = [ordered]@{}
  foreach ($Match in [regex]::Matches($NormalizedExpression, '%(?<Name>[A-Za-z_][A-Za-z0-9_]*)%')) {
    $OriginalName = $Match.Value
    $NormalizedName = "SF_$($Match.Groups['Name'].Value)"
    $NormalizedExpression = $NormalizedExpression.Replace($OriginalName, $NormalizedName)
    foreach ($Key in $IdentifierState.Keys) {
      if ([string]$Key -ieq $OriginalName) { $NormalizedStates[$NormalizedName] = $IdentifierState[$Key]; break }
    }
  }
  foreach ($Key in $IdentifierState.Keys) {
    if ([string]$Key -notmatch '^%.*%$') { $NormalizedStates[[string]$Key] = $IdentifierState[$Key] }
  }

  $Result = Resolve-InstallerBooleanExpression -Expression $NormalizedExpression -IdentifierState $NormalizedStates
  $Result | Add-Member -NotePropertyName Expression -NotePropertyValue $Expression
  $Result | Add-Member -NotePropertyName NormalizedExpression -NotePropertyValue $NormalizedExpression
  return $Result
}

function Read-SetupFactoryActionRecord6 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 6 CAction object using the runtime serializer layout.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable offset positioned at the CAction schema field, after its MFC class declaration or reference tag.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Offset
  )

  $StartOffset = [long]$Offset.Value
  $SchemaVersion = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  if ($SchemaVersion -ne 1) { throw "The Setup Factory 6 CAction schema $SchemaVersion is unsupported" }
  $Layout = @(
    @('I04', 'Integer'), @('S08', 'String'), @('S0C', 'String'), @('S10', 'String'), @('S14', 'String'), @('S18', 'String'),
    @('I1C', 'Integer'), @('I20', 'Integer'), @('I24', 'Integer'), @('I28', 'Integer'), @('S2C', 'String'), @('S30', 'String'),
    @('I34', 'Integer'), @('I38', 'Integer'), @('S3C', 'String'), @('I40', 'Integer'), @('S44', 'String'), @('I48', 'Integer'),
    @('I4C', 'Integer'), @('I50', 'Integer'), @('S54', 'String'), @('S58', 'String'), @('S5C', 'String'), @('S60', 'String'),
    @('S64', 'String'), @('S68', 'String'), @('I6C', 'Integer'), @('S70', 'String'), @('S74', 'String'), @('I78', 'Integer'),
    @('I8C', 'Integer'), @('S7C', 'String'), @('S80', 'String'), @('S84', 'String'), @('S88', 'String'), @('IB0', 'Integer'),
    @('SB4', 'String'), @('IB8', 'Integer'), @('SBC', 'String'), @('I90', 'Integer'), @('I94', 'Integer'), @('I98', 'Integer'),
    @('I9C', 'Integer'), @('SA0', 'String'), @('SA4', 'String'), @('SA8', 'String'), @('SAC', 'String')
  )
  $Fields = [ordered]@{}
  foreach ($Field in $Layout) {
    $Fields[$Field[0]] = if ($Field[1] -eq 'Integer') { Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4 } else { Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable }
  }
  $ActionId = [int]$Fields.I04
  if ($ActionId -lt 0 -or $ActionId -gt 1024) { throw "The Setup Factory 6 action ID $ActionId is outside the supported structural range" }
  $Descriptor = Get-SetupFactoryActionDescriptor6 -ActionId $ActionId
  $FieldObject = [pscustomobject]$Fields
  [pscustomobject][ordered]@{
    Offset           = $StartOffset
    EndOffset        = [long]$Offset.Value
    Schema           = $SchemaVersion
    ActionId         = $ActionId
    ActionName       = $Descriptor.Name
    Category         = $Descriptor.Category
    ProjectionStatus = $Descriptor.ProjectionStatus
    Details          = Get-SetupFactoryActionDetails6 -ActionId $ActionId -Fields $FieldObject
    Fields           = $FieldObject
  }
}

function Get-SetupFactoryActionCatalog6 {
  <#
  .SYNOPSIS
    Recover counted Setup Factory 6 CAction lists and deterministic install-time registry writes.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER UninstallOffset
    Start of the built-in uninstall configuration. Action lists after this boundary belong to the generated uninstaller.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$UninstallOffset
  )

  $Marker = [Text.Encoding]::ASCII.GetBytes('CAction')
  $MarkerOffsets = @(Find-BinaryPattern -Bytes $Bytes -Pattern $Marker -Maximum 8)
  $ClassMarker = $MarkerOffsets | Where-Object { $_ -ge 8 -and [BitConverter]::ToUInt16($Bytes, $_ - 6) -eq 0xFFFF -and [BitConverter]::ToUInt16($Bytes, $_ - 4) -eq 1 -and [BitConverter]::ToUInt16($Bytes, $_ - 2) -eq $Marker.Length } | Select-Object -First 1
  if ($null -eq $ClassMarker) {
    return [pscustomobject][ordered]@{
      IsPresent = $false; IsComplete = $true; Error = $null; Groups = @(); Entries = @(); RegistryWrites = @(); VariableAssignments = @(); ExecutionActions = @()
      UserInteractionActions = @(); InstallabilityActions = @(); ShortcutActions = @(); ServiceActions = @(); RebootActions = @(); ExternalCodeActions = @()
      UnknownActions = @(); UnresolvedCount = 0; UnresolvedControlFlowCount = 0
    }
  }

  $Groups = [Collections.Generic.List[object]]::new()
  # Copy the caller-provided boundary into the list-reader closure explicitly. Besides making the
  # ownership clear, this keeps static analysis from treating the captured parameter as unused.
  $UninstallBoundary = $UninstallOffset
  $ReadGroup = {
    param ([long]$ObjectPrefixOffset, [int]$Count, [bool]$HasClassDeclaration, [int]$Ordinal)
    if ($Count -le 0 -or $Count -gt $Script:SetupFactoryMaximumEntries) { throw "The Setup Factory 6 action-list count $Count is invalid" }
    $Records = [Collections.Generic.List[object]]::new($Count)
    $Cursor = if ($HasClassDeclaration) { [ref]([long]($ClassMarker + $Marker.Length)) } else { [ref]([long]($ObjectPrefixOffset + 2)) }
    $Reference = $HasClassDeclaration ? $null : [int][BitConverter]::ToUInt16($Bytes, [int]$ObjectPrefixOffset)
    if ($null -ne $Reference -and ($Reference -band 0x8000) -eq 0) { throw 'The Setup Factory 6 CAction class reference is invalid' }
    for ($Index = 0; $Index -lt $Count; $Index++) {
      if ($Index -gt 0) {
        $CurrentReference = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Cursor -Size 2)
        if ($null -eq $Reference) { $Reference = $CurrentReference }
        if (($CurrentReference -band 0x8000) -eq 0 -or $CurrentReference -ne $Reference) { throw 'The Setup Factory 6 CAction reference changed inside a counted list' }
      }
      $Records.Add((Read-SetupFactoryActionRecord6 -Bytes $Bytes -Offset $Cursor))
    }
    $Phase = if ($ObjectPrefixOffset -ge $UninstallBoundary) { 'Uninstall' } else {
      @('Startup', 'BeforeInstalling', 'AfterInstalling', 'Shutdown')[[Math]::Min($Ordinal, 3)]
    }
    foreach ($Record in $Records) { $Record | Add-Member -NotePropertyName Phase -NotePropertyValue $Phase }
    return [pscustomobject][ordered]@{ Offset = $ObjectPrefixOffset; EndOffset = [long]$Cursor.Value; Count = $Count; Phase = $Phase; ClassReference = $Reference; Entries = $Records.ToArray() }
  }

  $ErrorMessage = $null
  try {
    $FirstCount = [int][BitConverter]::ToUInt16($Bytes, $ClassMarker - 8)
    $Groups.Add((& $ReadGroup -ObjectPrefixOffset ($ClassMarker - 6) -Count $FirstCount -HasClassDeclaration $true -Ordinal 0))

    # Later lists start with [count:u16][class-reference:u16]. Scan only for complete counted lists;
    # internal object references cannot pass the count/end-boundary checks for their enclosing list.
    $SearchOffset = [long]$Groups[0].EndOffset
    while ($SearchOffset + 8 -le $Bytes.LongLength) {
      $Accepted = $false
      for ($Prefix = $SearchOffset + 2; $Prefix + 8 -le $Bytes.LongLength; $Prefix++) {
        $Reference = [int][BitConverter]::ToUInt16($Bytes, [int]$Prefix)
        if (($Reference -band 0x8000) -eq 0 -or [BitConverter]::ToInt32($Bytes, [int]$Prefix + 2) -ne 1) { continue }
        $Count = [int][BitConverter]::ToUInt16($Bytes, [int]$Prefix - 2)
        if ($Count -le 0 -or $Count -gt $Script:SetupFactoryMaximumEntries) { continue }
        try {
          $Group = & $ReadGroup -ObjectPrefixOffset $Prefix -Count $Count -HasClassDeclaration $false -Ordinal $Groups.Count
          # A complete list must stop before another object of the same MFC class; otherwise the
          # preceding bytes were an accidental count inside an existing list.
          if ($Group.EndOffset + 2 -le $Bytes.LongLength -and [BitConverter]::ToUInt16($Bytes, [int]$Group.EndOffset) -eq $Reference) { continue }
          $Groups.Add($Group)
          $SearchOffset = $Group.EndOffset
          $Accepted = $true
          break
        } catch {
          continue
        }
      }
      if (-not $Accepted) { break }
    }
  } catch {
    $ErrorMessage = $_.Exception.Message
  }

  $AllEntries = [Collections.Generic.List[object]]::new()
  foreach ($Group in $Groups) { $AllEntries.AddRange([object[]]$Group.Entries) }
  $RegistryWrites = [Collections.Generic.List[object]]::new()
  $VariableAssignments = [Collections.Generic.List[object]]::new()
  $ExecutionActions = [Collections.Generic.List[object]]::new()
  $UserInteractionActions = [Collections.Generic.List[object]]::new()
  $InstallabilityActions = [Collections.Generic.List[object]]::new()
  $ShortcutActions = [Collections.Generic.List[object]]::new()
  $ServiceActions = [Collections.Generic.List[object]]::new()
  $RebootActions = [Collections.Generic.List[object]]::new()
  $ExternalCodeActions = [Collections.Generic.List[object]]::new()
  $UnknownActions = [Collections.Generic.List[object]]::new()
  $UnresolvedCount = 0
  $UnresolvedControlFlowCount = 0
  foreach ($Group in $Groups) {
    # CAction lists contain their own block controls. Track IF and WHILE nesting so every effect
    # carries the condition state under which the runtime reaches it. Runtime variable expressions
    # remain Unknown; the parser never executes project actions against the host.
    $ConditionStack = [Collections.Generic.List[object]]::new()
    $IdentifierState = [ordered]@{}
    foreach ($Action in $Group.Entries) {
      $ParentState = $ConditionStack.Count ? [string]$ConditionStack[$ConditionStack.Count - 1].State : 'True'
      if ($Action.ActionId -in 100, 102) {
        $ResolvedCondition = Resolve-SetupFactoryActionCondition6 -Expression ([string]$Action.Fields.S54) -IdentifierState $IdentifierState
        $ConditionState = Merge-InstallerConditionState -State @($ParentState, $ResolvedCondition.State) -Operator All
        $Action | Add-Member -NotePropertyName ConditionState -NotePropertyValue $ConditionState
        $Action | Add-Member -NotePropertyName ConditionEvidence -NotePropertyValue $ResolvedCondition
        $ConditionStack.Add([pscustomobject]@{ ActionId = $Action.ActionId; State = $ConditionState })
        if ($Action.ActionId -eq 102 -and $ConditionState -eq 'Unknown') { $UnresolvedControlFlowCount++ }
        continue
      }
      if ($Action.ActionId -in 101, 103) {
        $Action | Add-Member -NotePropertyName ConditionState -NotePropertyValue $ParentState
        $ExpectedOpen = $Action.ActionId -eq 101 ? 100 : 102
        if (-not $ConditionStack.Count -or $ConditionStack[$ConditionStack.Count - 1].ActionId -ne $ExpectedOpen) {
          $UnresolvedCount++
          $UnresolvedControlFlowCount++
        } else {
          $ConditionStack.RemoveAt($ConditionStack.Count - 1)
        }
        continue
      }

      $ConditionState = $ParentState
      $Action | Add-Member -NotePropertyName ConditionState -NotePropertyValue $ConditionState
      if (-not $Action.ActionName) {
        $UnknownActions.Add($Action)
        if ($Action.Phase -ne 'Uninstall' -and $ConditionState -ne 'False') { $UnresolvedControlFlowCount++ }
        continue
      }

      # GOTO changes which subsequent records run. Preserve the exact label target, but do not
      # pretend a single-pass walk can model branches that depend on unresolved runtime state.
      if ($Action.ActionId -eq 104 -and $ConditionState -ne 'False') { $UnresolvedControlFlowCount++ }
      if ($Action.ActionId -eq 14) {
        $VariableAssignments.Add($Action)
        $VariableName = [string]$Action.Details.VariableName
        $LiteralValue = [string]$Action.Details.Value
        if (-not $Action.Details.EvaluateAsExpression -and $VariableName -match '^%[A-Za-z_][A-Za-z0-9_]*%$' -and $LiteralValue -in 'TRUE', 'FALSE') {
          if ($ConditionState -eq 'True') { $IdentifierState[$VariableName] = $LiteralValue -eq 'TRUE' ? 'True' : 'False' }
          elseif ($ConditionState -eq 'Unknown') { $IdentifierState[$VariableName] = 'Unknown' }
        }
      }
      if ($Action.ActionId -in 3, 4) { $ExecutionActions.Add($Action) }
      if ($Action.ActionId -in 20, 28) { $UserInteractionActions.Add($Action) }
      if ($Action.ActionId -in 6, 22, 55) { $InstallabilityActions.Add($Action) }
      if ($Action.ActionId -in 50, 51) { $ShortcutActions.Add($Action) }
      if ($Action.ActionId -in 57, 58, 59, 60, 61, 62, 63) { $ServiceActions.Add($Action) }
      if ($Action.ActionId -in 74, 75, 76) { $RebootActions.Add($Action) }
      if ($Action.ActionId -eq 77) { $ExternalCodeActions.Add($Action) }

      # Registry writes are projected only for installation phases, reachable Set Value actions,
      # and source-backed root/type enums. Other operations remain in the action catalog.
      if ($Group.Phase -eq 'Uninstall' -or $Action.ActionId -ne 17) { continue }
      if ($ConditionState -eq 'Unknown') { $UnresolvedCount++; continue }
      if ($ConditionState -eq 'False' -or [int]$Action.Fields.I38 -ne 2) { continue }
      $Root = ConvertTo-SetupFactoryRegistryRoot -Value ([int]$Action.Fields.I78) -Generation Legacy6
      $Type = ConvertTo-SetupFactoryRegistryValueType -Value ([int]$Action.Fields.I90) -Generation Legacy6
      if (-not $Root -or -not $Type) { $UnresolvedCount++; continue }
      $RegistryWrites.Add([pscustomobject][ordered]@{
          Root           = $Root
          Key            = [string]$Action.Fields.S74
          Name           = [string]$Action.Fields.S58
          Value          = [string]$Action.Fields.S68
          Type           = $Type
          ActionOffset   = $Action.Offset
          ActionPhase    = $Action.Phase
          ConditionState = $ConditionState
        })
    }
    if ($ConditionStack.Count) {
      $UnresolvedCount += $ConditionStack.Count
      $UnresolvedControlFlowCount += $ConditionStack.Count
    }
  }

  return [pscustomobject][ordered]@{
    IsPresent                  = $true
    IsComplete                 = -not $ErrorMessage
    Error                      = $ErrorMessage
    Groups                     = $Groups.ToArray()
    Entries                    = $AllEntries.ToArray()
    RegistryWrites             = $RegistryWrites.ToArray()
    VariableAssignments        = $VariableAssignments.ToArray()
    ExecutionActions           = $ExecutionActions.ToArray()
    UserInteractionActions     = $UserInteractionActions.ToArray()
    InstallabilityActions      = $InstallabilityActions.ToArray()
    ShortcutActions            = $ShortcutActions.ToArray()
    ServiceActions             = $ServiceActions.ToArray()
    RebootActions              = $RebootActions.ToArray()
    ExternalCodeActions        = $ExternalCodeActions.ToArray()
    UnknownActions             = $UnknownActions.ToArray()
    UnresolvedCount            = $UnresolvedCount
    UnresolvedControlFlowCount = $UnresolvedControlFlowCount
  }
}

function Read-SetupFactoryLuaString {
  <#
  .SYNOPSIS
    Read one quoted literal Lua string without evaluating Lua code.
  .PARAMETER Text
    Decompiled or embedded Lua text.
  .PARAMETER Offset
    Mutable character offset positioned at optional whitespace before a quoted string.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$Text,
    [Parameter(Mandatory)][ref]$Offset
  )

  while ($Offset.Value -lt $Text.Length -and [char]::IsWhiteSpace($Text[$Offset.Value])) { $Offset.Value++ }
  if ($Offset.Value -ge $Text.Length -or $Text[$Offset.Value] -notin "'", '"') { throw 'The Lua argument is not a literal string' }
  $Quote = $Text[$Offset.Value++]
  $Builder = [Text.StringBuilder]::new()
  while ($Offset.Value -lt $Text.Length) {
    $Character = $Text[$Offset.Value++]
    if ($Character -eq $Quote) { return $Builder.ToString() }
    if ($Character -ne '\') { $null = $Builder.Append($Character); continue }
    if ($Offset.Value -ge $Text.Length) { throw 'The Lua string ends in an escape prefix' }
    $Escape = $Text[$Offset.Value++]
    switch ($Escape) {
      'a' { $null = $Builder.Append([char]7) }
      'b' { $null = $Builder.Append([char]8) }
      'f' { $null = $Builder.Append([char]12) }
      'n' { $null = $Builder.Append("`n") }
      'r' { $null = $Builder.Append("`r") }
      't' { $null = $Builder.Append("`t") }
      'v' { $null = $Builder.Append([char]11) }
      "`n" { }
      "`r" { if ($Offset.Value -lt $Text.Length -and $Text[$Offset.Value] -eq "`n") { $Offset.Value++ } }
      'z' { while ($Offset.Value -lt $Text.Length -and [char]::IsWhiteSpace($Text[$Offset.Value])) { $Offset.Value++ } }
      default {
        if ([char]::IsDigit($Escape)) {
          $Digits = [string]$Escape
          while ($Digits.Length -lt 3 -and $Offset.Value -lt $Text.Length -and [char]::IsDigit($Text[$Offset.Value])) { $Digits += $Text[$Offset.Value++] }
          $Code = [int]$Digits
          if ($Code -gt 255) { throw 'The Lua decimal escape is outside the byte range' }
          $null = $Builder.Append([char]$Code)
        } elseif ($Escape -in "'", '"', '\') {
          $null = $Builder.Append($Escape)
        } else {
          # Compiled Setup Factory action text commonly contains ordinary Windows paths with
          # single backslashes. Preserve an unrecognized escape verbatim rather than silently
          # deleting the path separator while still decoding escaped quotes and backslashes.
          $null = $Builder.Append('\').Append($Escape)
        }
      }
    }
  }
  throw 'The Lua string is unterminated'
}

function Get-SetupFactoryLiteralRegistryWrite {
  <#
  .SYNOPSIS
    Recover literal Lua Registry.SetValue calls from irsetup.dat.
  .PARAMETER Bytes
    Complete irsetup.dat bytes decoded as UTF-8 for literal action parsing. Conditional or computed calls are not returned.
  .PARAMETER UnresolvedCount
    Optional reference receiving the number of Registry.SetValue calls whose arguments or registry roots could not be represented as deterministic registry evidence.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [ref]$UnresolvedCount
  )
  if ($null -ne $UnresolvedCount) { $UnresolvedCount.Value = 0 }
  # Parse quoted arguments with a small lexer instead of a quote-delimited regex. Setup Factory
  # commonly emits escaped quotes in uninstall and association commands.
  $Text = ConvertFrom-SetupFactoryText -Bytes $Bytes
  foreach ($Match in [regex]::Matches($Text, '(?i)Registry\.SetValue\s*\(')) {
    $Cursor = [ref]($Match.Index + $Match.Length)
    try {
      $Arguments = [Collections.Generic.List[string]]::new()
      for ($Index = 0; $Index -lt 4; $Index++) {
        $Arguments.Add((Read-SetupFactoryLuaString -Text $Text -Offset $Cursor))
        while ($Cursor.Value -lt $Text.Length -and [char]::IsWhiteSpace($Text[$Cursor.Value])) { $Cursor.Value++ }
        if ($Index -lt 3) {
          if ($Cursor.Value -ge $Text.Length -or $Text[$Cursor.Value] -ne ',') { throw 'The Lua argument separator is missing' }
          $Cursor.Value++
        }
      }
      if ($Arguments[0] -notmatch '^(?:HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKCR|HKEY_CLASSES_ROOT)$') {
        if ($null -ne $UnresolvedCount) { $UnresolvedCount.Value++ }
        continue
      }
      [pscustomobject]@{
        Root  = $Arguments[0]
        Key   = $Arguments[1]
        Name  = $Arguments[2]
        Value = $Arguments[3]
        Type  = 'REG_SZ'
      }
    } catch {
      # Computed arguments, long-bracket strings, and malformed calls are not deterministic
      # registry evidence. The aggregate parser reports their count as unresolved Lua effects.
      if ($null -ne $UnresolvedCount) { $UnresolvedCount.Value++ }
      continue
    }
  }
}

Export-ModuleMember -Function Get-SetupFactoryLegacyConditionState5, Get-SetupFactoryLegacyActionPhase5, Get-SetupFactoryLegacyObjectTable, Read-SetupFactoryExecuteRecord5, Read-SetupFactoryFileOperationRecord5, Read-SetupFactoryIniRecord4, Read-SetupFactoryIniRecord5, Read-SetupFactoryRegistryVariableRecord5, Get-SetupFactoryActionCatalog4, Get-SetupFactoryActionCatalog5, Get-SetupFactoryActionDescriptor6, Get-SetupFactoryActionDetails6, Resolve-SetupFactoryActionCondition6, Read-SetupFactoryActionRecord6, Get-SetupFactoryActionCatalog6, Read-SetupFactoryLuaString, Get-SetupFactoryLiteralRegistryWrite
