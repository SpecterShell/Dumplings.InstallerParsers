. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\NSISTestSetup.ps1')

Describe 'NSIS command simulation' -Tag Unit {
  It 'Should simulate prior INI and registry writes and decode shortcut records' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $StringBytes = [System.Collections.Generic.List[byte]]::new()
      $StringBytes.AddRange([byte[]](0, 0))
      function Add-TestString([string]$Text) {
        $Offset = [int]($StringBytes.Count / 2)
        $StringBytes.AddRange([Text.Encoding]::Unicode.GetBytes($Text + [char]0))
        return $Offset
      }
      function New-TestEntry([int]$Opcode, [uint32[]]$Operands) {
        $Raw = [uint32[]]@($Opcode) + $Operands
        $Values = [int[]]::new($Raw.Count)
        for ($Index = 0; $Index -lt $Raw.Count; $Index++) {
          $Values[$Index] = [BitConverter]::ToInt32([BitConverter]::GetBytes($Raw[$Index]), 0)
        }
        [pscustomobject]@{ Opcode = $Opcode; RawOpcode = $Opcode; LayoutOpcode = $Opcode; Raw = $Raw; Values = $Values }
      }

      $Section = Add-TestString 'Application'
      $Key = Add-TestString 'Mode'
      $Value = Add-TestString 'Quiet'
      $IniFile = Add-TestString '$INSTDIR\unit.ini'
      $RegistryKey = Add-TestString 'Software\Dumplings\Unit'
      $IndexZero = Add-TestString '0'
      $Shortcut = Add-TestString '$DESKTOP\Unit.lnk'
      $Target = Add-TestString '$INSTDIR\unit.exe'
      $Arguments = Add-TestString '--open'
      $Icon = Add-TestString '$INSTDIR\unit.exe'
      $Comment = Add-TestString 'Unit shortcut'
      $Hklm = [uint32]$Script:NSIS_REG_ROOT_HKLM
      $PackedShortcut = [uint32](7 -bor (3 -shl 12) -bor 0x8000 -bor (0x0241 -shl 16))

      $State = [pscustomobject]@{
        Path                  = 'unit.exe'
        StringsBlock          = $StringBytes.ToArray()
        LanguageTable         = $null
        VersionInfo           = [pscustomobject]@{ Unicode = $true; IsV3 = $true; Type = 'NSIS3'; VariableRoute = 'current' }
        Variables             = @{}
        Registry              = @{}
        IniFiles              = @{}
        IniWrites             = [System.Collections.Generic.List[object]]::new()
        CreatedShortcuts      = [System.Collections.Generic.List[object]]::new()
        HasUnknownControlFlow = $false
        ConditionalReasons    = [System.Collections.Generic.HashSet[string]]::new()
        ShellVarContext       = 'HKLM'
        TargetScope           = 'machine'
        Metadata              = [ordered]@{ DefaultInstallLocation = $null; RequestedExecutionLevel = 'requireAdministrator'; UnresolvedFields = [string[]]@() }
      }
      Set-NSISVariableValue -State $State -Index $Script:NSIS_PREDEFINED_VAR_INSTDIR -Value '$INSTDIR'
      Set-NSISRegistryValue -State $State -Root 'HKLM' -Key 'Software\Dumplings\Unit' -Name 'DisplayName' -Value 'Unit'
      Set-NSISRegistryValue -State $State -Root 'HKLM' -Key 'Software\Dumplings\Unit\Child' -Name 'Value' -Value '1'

      $null = Invoke-NSISEntry -State $State -Entry (New-TestEntry $Script:NSIS_OPCODE_WRITE_INI ([uint32[]]@($Section, $Key, $Value, $IniFile, 1, 0)))
      $null = Invoke-NSISEntry -State $State -Entry (New-TestEntry $Script:NSIS_OPCODE_READ_INI ([uint32[]]@(0, $Section, $Key, $IniFile, 0, 0)))
      $null = Invoke-NSISEntry -State $State -Entry (New-TestEntry $Script:NSIS_OPCODE_ENUM_REG ([uint32[]]@(1, $Hklm, $RegistryKey, $IndexZero, 0, 0)))
      $null = Invoke-NSISEntry -State $State -Entry (New-TestEntry $Script:NSIS_OPCODE_ENUM_REG ([uint32[]]@(2, $Hklm, $RegistryKey, $IndexZero, 1, 0)))
      $null = Invoke-NSISEntry -State $State -Entry (New-TestEntry $Script:NSIS_OPCODE_CREATE_SHORTCUT ([uint32[]]@($Shortcut, $Target, $Arguments, $Icon, $PackedShortcut, $Comment)))

      [pscustomobject]@{
        IniValue        = $State.Variables[0]
        EnumeratedValue = $State.Variables[1]
        EnumeratedChild = $State.Variables[2]
        IniWrite        = $State.IniWrites[0]
        Shortcut        = $State.CreatedShortcuts[0]
      }
    }

    $Result.IniValue | Should -Be 'Quiet'
    $Result.EnumeratedValue | Should -Be 'DisplayName'
    $Result.EnumeratedChild | Should -Be 'Child'
    $Result.IniWrite.Action | Should -Be 'Write'
    $Result.IniWrite.File | Should -Be '$INSTDIR\unit.ini'
    $Result.Shortcut.Path | Should -Be '$DESKTOP\Unit.lnk'
    $Result.Shortcut.Target | Should -Be '$INSTDIR\unit.exe'
    $Result.Shortcut.Arguments | Should -Be '--open'
    $Result.Shortcut.IconIndex | Should -Be 7
    $Result.Shortcut.ShowCommand | Should -Be 3
    $Result.Shortcut.HotKey | Should -Be 0x0241
    $Result.Shortcut.NoWorkingDirectory | Should -BeTrue
    $Result.Shortcut.WorkingDirectory | Should -BeNullOrEmpty
    $Result.Shortcut.Comment | Should -Be 'Unit shortcut'
  }

  It 'Should project Registry plug-in writes into ARP evidence' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $State = [pscustomobject]@{
        Registry              = @{}
        RegistryWrites        = [System.Collections.Generic.List[object]]::new()
        Stack                 = [System.Collections.Generic.List[string]]::new()
        HasUnknownControlFlow = $false
        ConditionalReasons    = [System.Collections.Generic.HashSet[string]]::new()
        Metadata              = [ordered]@{
          ProductCode = $null; Scope = $null; RegistryValues = @{}; WritesAppsAndFeaturesEntry = $false
          DisplayName = $null; DisplayVersion = $null; Publisher = $null; DefaultInstallLocation = $null
          UninstallString = $null; QuietUninstallString = $null; DisplayIcon = $null; SystemComponent = $null
          UnresolvedFields = [string[]]@()
        }
      }

      # _Write pops path, name, data, and type in that order.
      foreach ($Value in 'REG_SZ', 'Unit App', 'DisplayName', 'HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Unit.App') { $State.Stack.Add($Value) }
      $Handled = Invoke-NSISRegistryPluginCall -State $State -FunctionName '_Write'
      $ReturnCode = Pop-NSISStackValue -State $State

      # _Read pushes type followed by value, so the value is popped first.
      $State.Stack.Add('DisplayName')
      $State.Stack.Add('HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Unit.App')
      $null = Invoke-NSISRegistryPluginCall -State $State -FunctionName '_Read'
      [pscustomobject]@{
        Handled    = $Handled
        ReturnCode = $ReturnCode
        Value      = Pop-NSISStackValue -State $State
        Type       = Pop-NSISStackValue -State $State
        Metadata   = $State.Metadata
        Write      = $State.RegistryWrites[0]
      }
    }

    $Result.Handled | Should -BeTrue
    $Result.ReturnCode | Should -Be '0'
    $Result.Value | Should -Be 'Unit App'
    $Result.Type | Should -Be 'REG_SZ'
    $Result.Metadata.ProductCode | Should -Be 'Unit.App'
    $Result.Metadata.Scope | Should -Be 'user'
    $Result.Metadata.DisplayName | Should -Be 'Unit App'
    $Result.Metadata.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Result.Write.Source | Should -Be 'RegistryPlugin'
  }

  It 'Should model empty INI operands without PowerShell binding failures' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $State = [pscustomobject]@{ IniFiles = @{ '' = @{ '' = @{ '' = 'empty-key-value' } } } }
      Get-NSISIniValue -State $State -File '' -Section '' -Key ''
    }

    $Result | Should -Be 'empty-key-value'
  }

  It 'Should reproduce environment, registry, and INI read error contracts' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $StringBytes = [System.Collections.Generic.List[byte]]::new()
      $StringBytes.AddRange([byte[]](0, 0))
      function Add-TestString([string]$Text) {
        $Offset = [int]($StringBytes.Count / 2)
        $StringBytes.AddRange([Text.Encoding]::Unicode.GetBytes($Text + [char]0))
        return $Offset
      }
      function New-TestEntry([int]$Opcode, [uint32[]]$Operands) {
        $Raw = [uint32[]]@($Opcode) + $Operands
        $Values = [int[]]::new($Raw.Count)
        for ($Index = 0; $Index -lt $Raw.Count; $Index++) { $Values[$Index] = [BitConverter]::ToInt32([BitConverter]::GetBytes($Raw[$Index]), 0) }
        [pscustomobject]@{ Opcode = $Opcode; RawOpcode = $Opcode; LayoutOpcode = $Opcode; Raw = $Raw; Values = $Values }
      }

      $ReadEnv = Add-TestString '%TEMP%'
      $ExpandEnv = Add-TestString '%TEMP%\payload;%MISSING%'
      $RegistryKey = Add-TestString 'Software\Dumplings\Missing'
      $RegistryName = Add-TestString 'Value'
      $IniSection = Add-TestString 'Application'
      $IniKey = Add-TestString 'Mode'
      $IniFile = Add-TestString '$INSTDIR\missing.ini'
      $State = [pscustomobject]@{
        StringsBlock       = $StringBytes.ToArray()
        LanguageTable      = $null
        VersionInfo        = [pscustomobject]@{ Unicode = $true; IsV3 = $true; Type = 'NSIS3'; VariableRoute = 'current' }
        Variables          = @{}
        Environment        = @{ TEMP = '$TEMP' }
        UnknownEnvironment = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        Registry           = @{}
        IniFiles           = @{}
        ExecFlags          = @{}
        UnknownExecFlags   = [System.Collections.Generic.HashSet[int]]::new()
        ShellVarContext    = 'HKLM'
      }

      $null = Invoke-NSISEntry -State $State -Entry (New-TestEntry $Script:NSIS_OPCODE_READ_ENV ([uint32[]]@(0, $ReadEnv, 1, 0, 0, 0)))
      $ReadEnvValue = $State.Variables[0]
      $null = Invoke-NSISEntry -State $State -Entry (New-TestEntry $Script:NSIS_OPCODE_READ_ENV ([uint32[]]@(1, $ExpandEnv, 0, 0, 0, 0)))
      $ExpandEnvValue = $State.Variables[1]
      $null = Invoke-NSISEntry -State $State -Entry (New-TestEntry $Script:NSIS_OPCODE_READ_REG ([uint32[]]@(2, [uint32]$Script:NSIS_REG_ROOT_HKLM, $RegistryKey, $RegistryName, 0, 0)))
      $null = Invoke-NSISEntry -State $State -Entry (New-TestEntry $Script:NSIS_OPCODE_READ_INI ([uint32[]]@(3, $IniSection, $IniKey, $IniFile, 0, 0)))

      [pscustomobject]@{
        ReadEnv      = $ReadEnvValue
        ExpandEnv    = $ExpandEnvValue
        MissingNames = [string[]]$State.UnknownEnvironment
        MissingReg   = $State.Variables[2]
        MissingIni   = $State.Variables[3]
        ErrorCount   = $State.ExecFlags[$Script:NSIS_EXEC_FLAG_ERROR]
      }
    }

    $Result.ReadEnv | Should -Be '$TEMP'
    $Result.ExpandEnv | Should -Be '$TEMP\payload;%MISSING%'
    $Result.MissingNames | Should -Contain 'MISSING'
    $Result.MissingReg | Should -BeNullOrEmpty
    $Result.MissingIni | Should -BeNullOrEmpty
    $Result.ErrorCount | Should -Be 2
  }

  It 'Should keep target filesystem predicates independent from the parser host' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $State = [pscustomobject]@{
        FileSystem         = @{}
        FileSystemComplete = $false
        Directories        = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        Files              = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      }
      $null = Set-NSISVirtualFileRecord -State $State -Path '%ProgramFiles%\Dumplings\present.dll' -Exists $true -FileVersion '1.2.3.4'
      $null = Set-NSISVirtualFileRecord -State $State -Path '%ProgramFiles%\Dumplings\absent.dll' -Exists $false

      [pscustomobject]@{
        Present  = Get-NSISPathExistence -State $State -Path '%ProgramFiles%\Dumplings\present.dll'
        Absent   = Get-NSISPathExistence -State $State -Path '%ProgramFiles%\Dumplings\absent.dll'
        Unknown  = Get-NSISPathExistence -State $State -Path '%SystemRoot%\host-dependent.dll'
        Wildcard = Get-NSISPathExistence -State $State -Path '%ProgramFiles%\Dumplings\*.dll'
      }
    }

    $Result.Present | Should -Be 'Present'
    $Result.Absent | Should -Be 'Absent'
    $Result.Unknown | Should -Be 'Unknown'
    $Result.Wildcard | Should -Be 'Present'
  }

  It 'Should fork unresolved file predicates and merge common registry effects' {
    $Fixture = Get-InstallerFixture -Name 'alist-desktop_3.60.0_x64-setup.exe' `
      -Url 'https://github.com/AlistGo/desktop-release/releases/download/v3.60.0/alist-desktop_3.60.0_x64-setup.exe'
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      param($Fixture)
      $Initialized = Initialize-NSISState -FormatContext (Get-NSISFormatContext -Path $Fixture)
      $State = $Initialized.State
      $StringBytes = [Collections.Generic.List[byte]]::new()
      $StringBytes.AddRange([byte[]](0, 0))
      function Add-TestString([string]$Text) {
        $Offset = [int]($StringBytes.Count / 2)
        $StringBytes.AddRange([Text.Encoding]::Unicode.GetBytes($Text + [char]0))
        return $Offset
      }
      function New-TestEntry([int]$Opcode, [uint32[]]$Operands) {
        $Raw = [uint32[]]@($Opcode) + $Operands
        $Values = [int[]]::new($Raw.Count)
        for ($Index = 0; $Index -lt $Raw.Count; $Index++) { $Values[$Index] = [BitConverter]::ToInt32([BitConverter]::GetBytes($Raw[$Index]), 0) }
        [pscustomobject]@{ Opcode = $Opcode; RawOpcode = $Opcode; LayoutOpcode = $Opcode; Raw = $Raw; Values = $Values }
      }

      $Path = Add-TestString '%ProgramFiles%\Dumplings\existing.exe'
      $Key = Add-TestString 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Dumplings.Branch'
      $DisplayName = Add-TestString 'DisplayName'
      $PresentName = Add-TestString 'Present branch'
      $AbsentName = Add-TestString 'Absent branch'
      $Publisher = Add-TestString 'Publisher'
      $PublisherValue = Add-TestString 'Dumplings'
      $Hklm = [uint32]$Script:NSIS_REG_ROOT_HKLM
      $WriteType = [uint32]$Script:NSIS_REG_TYPE_STRING
      $State.StringsBlock = $StringBytes.ToArray()
      $State.Sections = @()
      $State.Entries = [object[]]@(
        (New-TestEntry $Script:NSIS_OPCODE_IF_FILE_EXISTS ([uint32[]]@($Path, 2, 6, 0, 0, 0)))
        (New-TestEntry $Script:NSIS_OPCODE_IF_FILE_EXISTS ([uint32[]]@($Path, 3, 5, 0, 0, 0)))
        (New-TestEntry $Script:NSIS_OPCODE_WRITE_REG ([uint32[]]@($Hklm, $Key, $DisplayName, $PresentName, $WriteType, $WriteType)))
        (New-TestEntry $Script:NSIS_OPCODE_JUMP ([uint32[]]@(10, 0, 0, 0, 0, 0)))
        (New-TestEntry $Script:NSIS_OPCODE_RETURN ([uint32[]]@(0, 0, 0, 0, 0, 0)))
        (New-TestEntry $Script:NSIS_OPCODE_IF_FILE_EXISTS ([uint32[]]@($Path, 5, 7, 0, 0, 0)))
        (New-TestEntry $Script:NSIS_OPCODE_WRITE_REG ([uint32[]]@($Hklm, $Key, $DisplayName, $AbsentName, $WriteType, $WriteType)))
        (New-TestEntry $Script:NSIS_OPCODE_JUMP ([uint32[]]@(10, 0, 0, 0, 0, 0)))
        (New-TestEntry $Script:NSIS_OPCODE_RETURN ([uint32[]]@(0, 0, 0, 0, 0, 0)))
        (New-TestEntry $Script:NSIS_OPCODE_WRITE_REG ([uint32[]]@($Hklm, $Key, $Publisher, $PublisherValue, $WriteType, $WriteType)))
        (New-TestEntry $Script:NSIS_OPCODE_RETURN ([uint32[]]@(0, 0, 0, 0, 0, 0)))
      )

      $Outcome = Invoke-NSISCodeSegment -State $State -Position 0
      [pscustomobject]@{
        Outcome           = $Outcome
        DisplayWrites     = @($State.RegistryWrites | Where-Object Name -CEQ 'DisplayName')
        PublisherWrite    = @($State.RegistryWrites | Where-Object Name -CEQ 'Publisher')
        ProductCode       = $State.Metadata.ProductCode
        DisplayName       = $State.Metadata.DisplayName
        Publisher         = $State.Metadata.Publisher
        ExploredBranches  = $State.ExploredBranchCount
        TruncatedBranches = $State.TruncatedBranchCount
        Predicates        = [string[]]$State.BranchPredicates
      }
    } $Fixture

    $Result.Outcome | Should -Be 'Return'
    $Result.DisplayWrites | Should -HaveCount 2
    $Result.DisplayWrites.Conditional | Should -Not -Contain $false
    $Result.PublisherWrite | Should -HaveCount 1
    $Result.PublisherWrite.Conditional | Should -BeFalse
    $Result.ProductCode | Should -Be 'Dumplings.Branch'
    $Result.DisplayName | Should -BeNullOrEmpty
    $Result.Publisher | Should -Be 'Dumplings'
    $Result.ExploredBranches | Should -Be 1
    $Result.TruncatedBranches | Should -Be 0
    $Result.Predicates | Should -HaveCount 1
  }

  It 'Should preserve divergent branch variables as unknown values' {
    $Fixture = Get-InstallerFixture -Name 'alist-desktop_3.60.0_x64-setup.exe' `
      -Url 'https://github.com/AlistGo/desktop-release/releases/download/v3.60.0/alist-desktop_3.60.0_x64-setup.exe'
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      param($Fixture)
      $State = (Initialize-NSISState -FormatContext (Get-NSISFormatContext -Path $Fixture)).State
      $Strings = [Collections.Generic.List[byte]]::new()
      $Strings.AddRange([byte[]](0, 0))
      function Add-TestString([string]$Text) {
        $Offset = [int]($Strings.Count / 2)
        $Strings.AddRange([Text.Encoding]::Unicode.GetBytes($Text + [char]0))
        return $Offset
      }
      function New-TestEntry([int]$Opcode, [uint32[]]$Operands) {
        $Raw = [uint32[]]@($Opcode) + $Operands
        $Values = [int[]]::new($Raw.Count)
        for ($Index = 0; $Index -lt $Raw.Count; $Index++) { $Values[$Index] = [BitConverter]::ToInt32([BitConverter]::GetBytes($Raw[$Index]), 0) }
        [pscustomobject]@{ Opcode = $Opcode; RawOpcode = $Opcode; LayoutOpcode = $Opcode; Raw = $Raw; Values = $Values }
      }
      $TrueOffset = Add-TestString 'true'
      $FalseOffset = Add-TestString 'false'
      $State.StringsBlock = $Strings.ToArray()
      $State.Sections = @()
      $State.Entries = [object[]]@(
        (New-TestEntry $Script:NSIS_OPCODE_IF_FLAG ([uint32[]]@(2, 4, $Script:NSIS_EXEC_FLAG_ERROR, [uint32]::MaxValue, 0, 0)))
        (New-TestEntry $Script:NSIS_OPCODE_ASSIGN_VAR ([uint32[]]@(0, $TrueOffset, 0, 0, 0, 0)))
        (New-TestEntry $Script:NSIS_OPCODE_RETURN ([uint32[]]@(0, 0, 0, 0, 0, 0)))
        (New-TestEntry $Script:NSIS_OPCODE_ASSIGN_VAR ([uint32[]]@(0, $FalseOffset, 0, 0, 0, 0)))
        (New-TestEntry $Script:NSIS_OPCODE_RETURN ([uint32[]]@(0, 0, 0, 0, 0, 0)))
      )
      $null = $State.UnknownExecFlags.Add($Script:NSIS_EXEC_FLAG_ERROR)
      $Outcome = Invoke-NSISCodeSegment -State $State -Position 0
      [pscustomobject]@{
        Outcome     = $Outcome
        IsUnknown   = $State.UnknownVariables.Contains(0)
        Value       = Get-NSISVariableValue -State $State -Index 0
        Branches    = $State.ExploredBranchCount
        Diagnostics = [object[]]$State.Diagnostics
      }
    } $Fixture

    $Result.Outcome | Should -Be 'Return'
    $Result.IsUnknown | Should -BeTrue
    $Result.Value | Should -Be '$_NSIS_UNKNOWN_VAR_0_'
    $Result.Branches | Should -Be 1
    $Result.Diagnostics | Should -BeNullOrEmpty
  }

  It 'Should bound exponential branch exploration and retain truncation evidence' {
    $Fixture = Get-InstallerFixture -Name 'alist-desktop_3.60.0_x64-setup.exe' `
      -Url 'https://github.com/AlistGo/desktop-release/releases/download/v3.60.0/alist-desktop_3.60.0_x64-setup.exe'
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      param($Fixture)
      $State = (Initialize-NSISState -FormatContext (Get-NSISFormatContext -Path $Fixture)).State
      $Strings = [Collections.Generic.List[byte]]::new()
      $Strings.AddRange([byte[]](0, 0))
      function Add-TestString([string]$Text) {
        $Offset = [int]($Strings.Count / 2)
        $Strings.AddRange([Text.Encoding]::Unicode.GetBytes($Text + [char]0))
        return $Offset
      }
      function New-TestEntry([int]$Opcode, [uint32[]]$Operands) {
        $Raw = [uint32[]]@($Opcode) + $Operands
        $Values = [int[]]::new($Raw.Count)
        for ($Index = 0; $Index -lt $Raw.Count; $Index++) { $Values[$Index] = [BitConverter]::ToInt32([BitConverter]::GetBytes($Raw[$Index]), 0) }
        [pscustomobject]@{ Opcode = $Opcode; RawOpcode = $Opcode; LayoutOpcode = $Opcode; Raw = $Raw; Values = $Values }
      }

      $Entries = [Collections.Generic.List[object]]::new()
      for ($Level = 0; $Level -lt 5; $Level++) {
        $Path = Add-TestString "%ProgramFiles%\Dumplings\predicate-$Level.dat"
        $FirstBranchAddress = $Entries.Count + 2
        $SecondBranchAddress = $Entries.Count + 3
        $JoinAddress = $Entries.Count + 4
        $Entries.Add((New-TestEntry $Script:NSIS_OPCODE_IF_FILE_EXISTS ([uint32[]]@($Path, $FirstBranchAddress, $SecondBranchAddress, 0, 0, 0))))
        $Entries.Add((New-TestEntry $Script:NSIS_OPCODE_JUMP ([uint32[]]@($JoinAddress, 0, 0, 0, 0, 0))))
        $Entries.Add((New-TestEntry $Script:NSIS_OPCODE_JUMP ([uint32[]]@($JoinAddress, 0, 0, 0, 0, 0))))
      }
      $Entries.Add((New-TestEntry $Script:NSIS_OPCODE_RETURN ([uint32[]]@(0, 0, 0, 0, 0, 0))))
      $State.StringsBlock = $Strings.ToArray()
      $State.Sections = @()
      $State.Entries = $Entries.ToArray()

      $Outcome = Invoke-NSISCodeSegment -State $State -Position 0
      [pscustomobject]@{
        Outcome             = $Outcome
        ExploredPredicates  = $State.ExploredBranchCount
        TruncatedBranches   = $State.TruncatedBranchCount
        HasUnresolvedBranch = $State.Metadata.UnresolvedFields -contains 'ControlFlowBranches'
        Diagnostics         = [object[]]$State.Diagnostics
      }
    } $Fixture

    $Result.Outcome | Should -Be 'Return'
    $Result.ExploredPredicates | Should -Be 5
    $Result.TruncatedBranches | Should -Be 1
    $Result.HasUnresolvedBranch | Should -BeTrue
    $Result.Diagnostics | Should -BeNullOrEmpty
  }

  It 'Should parse command-line options and file versions with source-defined operand order' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $StringsBlock = [Text.Encoding]::ASCII.GetBytes("%TEMP%\app.exe`0")
      $State = [pscustomobject]@{
        Variables          = @{}
        StringsBlock       = $StringsBlock
        LanguageTable      = $null
        VersionInfo        = [pscustomobject]@{ Unicode = $false; IsV3 = $true; Type = 'NSIS3' }
        AnsiEncoding       = [Text.Encoding]::ASCII
        FileSystem         = @{}
        FileSystemComplete = $true
        Directories        = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        Files              = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        ExecFlags          = @{}
        UnknownExecFlags   = [System.Collections.Generic.HashSet[int]]::new()
      }
      $null = Set-NSISVirtualFileRecord -State $State -Path '%TEMP%\app.exe' -FileVersion '1.2.3.4' -ProductVersion '5.6.7.8'
      $Entry = [pscustomobject]@{ Opcode = $Script:NSIS_OPCODE_GET_DLL_VERSION; Values = [int[]]@(43, 0, 1, 0, 0, 0, 0) }
      Set-NSISFileVersionResult -State $State -Entry $Entry

      [pscustomobject]@{
        Parameters  = Get-NSISCommandLineParameters -CommandLine '"C:\Program Files\App\setup.exe" /S /D="C:\App Dir"'
        InstallPath = Get-NSISCommandLineOption -Parameters '/S /D="C:\App Dir"' -Option '/D='
        HighWord    = $State.Variables[0]
        LowWord     = $State.Variables[1]
      }
    }

    $Result.Parameters | Should -Be '/S /D="C:\App Dir"'
    $Result.InstallPath | Should -Be 'C:\App Dir'
    $Result.HighWord | Should -Be '65538'
    $Result.LowWord | Should -Be '196612'
  }

  It 'Should emulate bounded virtual file handles and section mutation' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $StringsBlock = [Text.Encoding]::ASCII.GetBytes("%TEMP%\state.txt`0hello`05`0")
      $State = [pscustomobject]@{
        Variables          = @{}
        StringsBlock       = $StringsBlock
        LanguageTable      = $null
        VersionInfo        = [pscustomobject]@{ Unicode = $false; IsV3 = $true; Type = 'NSIS3' }
        AnsiEncoding       = [Text.Encoding]::ASCII
        FileSystem         = @{}
        FileSystemComplete = $true
        Directories        = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        Files              = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        FileHandles        = @{}
        NextFileHandle     = 1
        FindHandles        = @{}
        NextFindHandle     = 1
        ExecFlags          = @{}
        UnknownExecFlags   = [System.Collections.Generic.HashSet[int]]::new()
        CurrentInstallType = 0
        InstallTypeNames   = @{}
        Sections           = @([pscustomobject]@{ Index = 0; NameOffset = 0; InstallTypes = 1; Flags = 0; CodeOffset = 0; CodeSize = 0; SizeKb = 1 })
      }
      $Open = [pscustomobject]@{ Opcode = $Script:NSIS_OPCODE_FILE_OPEN; Values = [int[]]@(55, 0, 0x40000000, 2, 0, 0, 0) }
      $Write = [pscustomobject]@{ Opcode = $Script:NSIS_OPCODE_FILE_WRITE; Values = [int[]]@(56, 0, 17, 0, 0, 0, 0) }
      $Close = [pscustomobject]@{ Opcode = $Script:NSIS_OPCODE_FILE_CLOSE; Values = [int[]]@(54, 0, 0, 0, 0, 0, 0) }
      Invoke-NSISFileOperation -State $State -Entry $Open
      Invoke-NSISFileOperation -State $State -Entry $Write
      Invoke-NSISFileOperation -State $State -Entry $Close

      $State.StringsBlock = [Text.Encoding]::ASCII.GetBytes("0`01`01`0")
      $SectionSet = [pscustomobject]@{ Opcode = $Script:NSIS_OPCODE_SECTION_SET; Values = [int[]]@(63, 0, 4, -3, 0, 0, 0) }
      Invoke-NSISSectionOperation -State $State -Entry $SectionSet
      $SetInstallTypeOne = [pscustomobject]@{ Opcode = $Script:NSIS_OPCODE_INSTALL_TYPE_SET; Values = [int[]]@(64, 2, 0, 1, 1, 0, 0) }
      $SetInstallTypeZero = [pscustomobject]@{ Opcode = $Script:NSIS_OPCODE_INSTALL_TYPE_SET; Values = [int[]]@(64, 0, 0, 1, 1, 0, 0) }
      Invoke-NSISSectionOperation -State $State -Entry $SetInstallTypeOne
      $SelectedForTypeOne = ($State.Sections[0].Flags -band $Script:NSIS_SECTION_FLAG_SELECTED) -ne 0
      Invoke-NSISSectionOperation -State $State -Entry $SetInstallTypeZero
      [pscustomobject]@{
        Content             = [Text.Encoding]::ASCII.GetString((Get-NSISVirtualFileRecord -State $State -Path '%TEMP%\state.txt').Content)
        Flags               = $State.Sections[0].Flags
        SelectedForTypeOne  = $SelectedForTypeOne
        SelectedForTypeZero = ($State.Sections[0].Flags -band $Script:NSIS_SECTION_FLAG_SELECTED) -ne 0
      }
    }

    $Result.Content | Should -Be 'hello'
    $Result.Flags | Should -Be 1
    $Result.SelectedForTypeOne | Should -BeFalse
    $Result.SelectedForTypeZero | Should -BeTrue
  }

  It 'Should apply source-defined silent MessageBox defaults and arithmetic errors' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $State = [pscustomobject]@{
        Variables        = @{}
        StringsBlock     = [Text.Encoding]::ASCII.GetBytes("10`00`0")
        LanguageTable    = $null
        VersionInfo      = [pscustomobject]@{ Unicode = $false; IsV3 = $true; Type = 'NSIS3' }
        AnsiEncoding     = [Text.Encoding]::ASCII
        ExecFlags        = @{ $Script:NSIS_EXEC_FLAG_SILENT = 1; $Script:NSIS_EXEC_FLAG_ERROR = 0 }
        LastExecFlags    = @{}
        UnknownExecFlags = [System.Collections.Generic.HashSet[int]]::new()
        Stack            = [System.Collections.Generic.List[string]]::new()
      }

      $MessageBox = [pscustomobject]@{
        Opcode = $Script:NSIS_OPCODE_MESSAGE_BOX
        Values = [int[]]@($Script:NSIS_OPCODE_MESSAGE_BOX, (6 -shl 21), 0, 6, 91, 7, 92)
      }
      $MessageResult = Invoke-NSISEntry -State $State -Entry $MessageBox

      $DivideByZero = [pscustomobject]@{
        Opcode = $Script:NSIS_OPCODE_INT_OP
        Values = [int[]]@($Script:NSIS_OPCODE_INT_OP, 0, 0, 3, 3, 0, 0)
      }
      $null = Invoke-NSISEntry -State $State -Entry $DivideByZero
      $IfErrors = [pscustomobject]@{
        Opcode = $Script:NSIS_OPCODE_IF_FLAG
        Values = [int[]]@($Script:NSIS_OPCODE_IF_FLAG, 71, 72, $Script:NSIS_EXEC_FLAG_ERROR, 0, 0, 0)
      }
      $ErrorResult = Invoke-NSISEntry -State $State -Entry $IfErrors

      [pscustomobject]@{
        MessageAddress = $MessageResult.Address
        DivisionResult = $State.Variables[0]
        ErrorAddress   = $ErrorResult.Address
        ErrorAfterTest = $State.ExecFlags[$Script:NSIS_EXEC_FLAG_ERROR]
      }
    }

    $Result.MessageAddress | Should -Be 91
    $Result.DivisionResult | Should -Be '0'
    $Result.ErrorAddress | Should -Be 71
    $Result.ErrorAfterTest | Should -Be 0
  }

  It 'Should model the source-backed x64.nsh System plug-in architecture probes' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $Values = [ordered]@{}
      foreach ($Architecture in @('x86', 'x64', 'arm64')) {
        $State = [pscustomobject]@{
          TargetArchitecture = $Architecture
          Stack              = [System.Collections.Generic.List[string]]::new()
        }

        $State.Stack.Add('kernel32::GetCurrentProcess()p.s')
        $null = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Call'
        $State.Stack.Add('kernel32::IsWow64Process2(ps,*i0s,*i)')
        $null = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Call'
        $State.Stack.Add('|')
        $State.Stack.Add('kernel32::IsWow64Process(p-1,*i0s)')
        $null = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Call'
        $null = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Int64Op'
        $Values[$Architecture] = Pop-NSISStackValue -State $State
      }
      $Values
    }

    $Result.x86 | Should -Be '0'
    [int]$Result.x64 | Should -BeGreaterThan 0
    [int]$Result.arm64 | Should -BeGreaterThan 0
  }

  It 'Should model the nsProcess fresh-install stack contract' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $State = [pscustomobject]@{
        Stack                    = [System.Collections.Generic.List[string]]::new()
        UnknownProcessPredicates = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      }
      $State.Stack.Add('example.exe')
      $Handled = Invoke-NSISProcessPluginCall -State $State -FunctionName '_FindProcess'
      [pscustomobject]@{
        Handled = $Handled
        Result  = Pop-NSISStackValue -State $State
        Process = @($State.UnknownProcessPredicates)[0]
      }
    }

    $Result.Handled | Should -BeTrue
    $Result.Result | Should -Be '603'
    $Result.Process | Should -Be 'example.exe'
  }

  It 'Should model electron-builder System plug-in known-folder register outputs' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $State = [pscustomobject]@{
        Variables = @{}
        Stack     = [System.Collections.Generic.List[string]]::new()
        Metadata  = [ordered]@{ DefaultInstallLocation = $null }
      }

      # multiUser.nsh receives both SHGetKnownFolderPath outputs in direct NSIS
      # registers, then copies the returned pointer string into $0.
      $State.Stack.Add('SHELL32::SHGetKnownFolderPath(g "{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}", i 0, p 0, *p .r2)i.r1')
      $KnownFolderHandled = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Call'
      $State.Stack.Add('KERNEL32::lstrcpynW(w .r0, p r2, i 1024)')
      $CopyHandled = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Call'

      [pscustomobject]@{
        KnownFolderHandled = $KnownFolderHandled
        CopyHandled        = $CopyHandled
        Result             = $State.Variables[1]
        Pointer            = $State.Variables[2]
        Destination        = $State.Variables[0]
        StackCount         = $State.Stack.Count
      }
    }

    $ExpectedPath = '%LocalAppData%\Programs'
    $Result.KnownFolderHandled | Should -BeTrue
    $Result.CopyHandled | Should -BeTrue
    $Result.Result | Should -Be '0'
    $Result.Pointer | Should -Be $ExpectedPath
    $Result.Destination | Should -Be $ExpectedPath
    $Result.StackCount | Should -Be 0
  }

  It 'Should model the source-backed NSIS 3 GetKnownFolderPath opcode' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $FolderId = '{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}'
      $StringsBlock = [Text.Encoding]::ASCII.GetBytes("x`0$FolderId`0")
      $State = [pscustomobject]@{
        Variables     = @{}
        StringsBlock  = $StringsBlock
        LanguageTable = $null
        VersionInfo   = [pscustomobject]@{ Unicode = $false; IsV3 = $true; Type = 3 }
        Metadata      = [ordered]@{ DefaultInstallLocation = $null }
      }
      $Entry = [pscustomobject]@{
        Opcode = $Script:NSIS_OPCODE_GET_OS_INFO
        Raw    = [uint32[]](65, 0, 21, 2, 0, 0, 0)
        Values = [int[]](65, 0, 21, 2, 0, 0, 0)
      }

      $null = Invoke-NSISEntry -State $State -Entry $Entry
      $State.Variables[21]
    }

    $Result | Should -Be '%LocalAppData%\Programs'
  }

  It 'Should resolve stable installer-related Windows known folders' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $WindowsDirectory = '%SystemRoot%'
    $SystemDirectory = '%SystemRoot%\System32'
    $SystemX86Directory = '%SystemRoot%\SysWOW64'
    $ProgramFiles64 = '%ProgramFiles%'
    $ProgramFilesX86 = '%ProgramFiles(x86)%'
    $CommonProgramFiles64 = '%ProgramFiles%\Common Files'
    $CommonProgramFilesX86 = '%ProgramFiles(x86)%\Common Files'
    $UserStartMenu = '%AppData%\Microsoft\Windows\Start Menu'
    $CommonStartMenu = '%ProgramData%\Microsoft\Windows\Start Menu'
    $Cases = [ordered]@{
      '{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}' = '%LocalAppData%'
      '{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}' = '%AppData%'
      '{A520A1A4-1780-4FF6-BD18-167343C5AF16}' = '%UserProfile%\AppData\LocalLow'
      '{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}' = '%ProgramData%'
      '{5E6C858F-0E22-4760-9AFE-EA3317B67173}' = '%UserProfile%'
      '{F38BF404-1D43-42F2-9305-67DE0B28FC23}' = $WindowsDirectory
      '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}' = $SystemDirectory
      '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}' = $SystemX86Directory
      '{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}' = Join-Path $WindowsDirectory 'Fonts'
      '{905E63B6-C1BF-494E-B29C-65B732D3D21A}' = $ProgramFiles64
      '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}' = $ProgramFilesX86
      '{6D809377-6AF0-444B-8957-A3773F02200E}' = $ProgramFiles64
      '{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}' = $CommonProgramFiles64
      '{DE974D24-D9C6-4D3E-BF91-F4455120B917}' = $CommonProgramFilesX86
      '{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}' = $CommonProgramFiles64
      '{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}' = '%LocalAppData%\Programs'
      '{BCBD3057-CA5C-4622-B42D-BC56DB0AE516}' = '%LocalAppData%\Programs\Common'
      '{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}' = $UserStartMenu
      '{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}' = Join-Path $UserStartMenu 'Programs'
      '{B97D20BB-F46A-4C97-BA10-5E3608430854}' = Join-Path $UserStartMenu 'Programs\Startup'
      '{724EF170-A42D-4FEF-9F26-B60E846FBA4F}' = Join-Path $UserStartMenu 'Programs\Administrative Tools'
      '{A4115719-D62E-491D-AA7C-E74B8BE3B067}' = $CommonStartMenu
      '{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}' = Join-Path $CommonStartMenu 'Programs'
      '{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}' = Join-Path $CommonStartMenu 'Programs\Startup'
      '{D0384E7D-BAC3-4797-8F14-CBA229B392B5}' = Join-Path $CommonStartMenu 'Programs\Administrative Tools'
    }

    $Result = & $Module {
      param($Cases)
      $Resolved = [ordered]@{}
      foreach ($Case in $Cases.GetEnumerator()) {
        $Resolved[$Case.Key] = Resolve-NSISKnownFolderPath -FolderId $Case.Key.ToLowerInvariant().Trim('{', '}')
      }
      $Resolved['Unknown'] = Resolve-NSISKnownFolderPath -FolderId '{00000000-0000-0000-0000-000000000000}'
      $Resolved['Invalid'] = Resolve-NSISKnownFolderPath -FolderId 'not-a-guid'
      $Resolved
    } $Cases

    foreach ($Case in $Cases.GetEnumerator()) {
      $Result[$Case.Key] | Should -Be $Case.Value
    }
    $Result.Unknown | Should -BeNullOrEmpty
    $Result.Invalid | Should -BeNullOrEmpty
  }

  It 'Should normalize known-folder profile paths without retaining the host user name' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      [pscustomobject]@{
        Profile  = ConvertTo-NSISManifestPath -Path (Resolve-NSISKnownFolderPath '{5E6C858F-0E22-4760-9AFE-EA3317B67173}')
        LocalLow = ConvertTo-NSISManifestPath -Path (Resolve-NSISKnownFolderPath '{A520A1A4-1780-4FF6-BD18-167343C5AF16}')
      }
    }

    $Result.Profile | Should -Be '%UserProfile%'
    $Result.LocalLow | Should -Be '%UserProfile%\AppData\LocalLow'
  }

  It 'Should preserve temporary NSIS registers through source-backed System Store calls' {
    $Module = Get-Module NSIS | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $State = [pscustomobject]@{
        Variables           = @{ 0 = 'original'; 11 = 'original-r1' }
        Stack               = [System.Collections.Generic.List[string]]::new()
        SystemVariableStack = [System.Collections.Generic.List[object]]::new()
      }

      $State.Stack.Add('S')
      $null = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Store'
      $State.Variables[0] = 'temporary'
      $State.Variables[11] = 'temporary-r1'
      $State.Stack.Add('L')
      $null = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Store'

      $State.Variables[2] = 'general-2'
      $State.Variables[12] = 'high-general-2'
      $State.Stack.Add('p2P2r3R3')
      $null = Invoke-NSISSystemPluginCall -State $State -FunctionName 'Store'

      [pscustomobject]@{
        Register0        = $State.Variables[0]
        RegisterR1       = $State.Variables[11]
        GeneralRegister3 = $State.Variables[3]
        HighRegister3    = $State.Variables[13]
        PrivateStackSize = $State.SystemVariableStack.Count
        PublicStackSize  = $State.Stack.Count
      }
    }

    $Result.Register0 | Should -Be 'original'
    $Result.RegisterR1 | Should -Be 'original-r1'
    $Result.GeneralRegister3 | Should -Be 'high-general-2'
    $Result.HighRegister3 | Should -Be 'general-2'
    $Result.PrivateStackSize | Should -Be 0
    $Result.PublicStackSize | Should -Be 0
  }

  It 'Should classify standard Tauri command-line switches by purpose' {
    $Fixture = Get-InstallerFixture -Name 'Yaak_2026.4.0_x64-setup.exe' -Url 'https://github.com/mountain-loop/yaak/releases/download/v2026.4.0/Yaak_2026.4.0_x64-setup.exe' -Sha256 '026DC0753F4880313B93BBFF848A9CD09A114F87111AAAEF5E4E698C52C8B561'
    $Info = Get-NSISInstallerSwitchInfo -Path $Fixture

    $Info.IsTauri | Should -BeTrue
    $Info.TauriInstallerMode | Should -Be 'currentUser'
    $Info.TauriSwitches.Switch | Should -Contain '/P'
    $Info.TauriSwitches.Switch | Should -Contain '/NS'
    $Info.TauriSwitches.Switch | Should -Contain '/UPDATE'
    $Info.TauriSwitches.Switch | Should -Contain '/R'
    $Info.TauriSwitches.Switch | Should -Contain '/ARGS'
    ($Info.TauriSwitches | Where-Object Switch -EQ '/P').Purpose | Should -Be 'Passive installation with progress'
    ($Info.TauriSwitches | Where-Object Switch -EQ '/R').Purpose | Should -Be 'Run the application after silent or passive installation'
  }
}
