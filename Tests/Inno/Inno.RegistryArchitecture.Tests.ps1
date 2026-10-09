. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InnoTestSetup.ps1')

BeforeAll {
  Import-Module (Join-Path $DumplingsModuleRoot 'Libraries\Installers\InnoScript.psm1')
  Import-InnoPascalScriptDependency

  function New-TestInnoInstruction {
    param($Code, $Operand)
    # Explicit overload selection avoids PowerShell choosing Create<T>(T)
    # instead of the IFPSLib interface overload for functions and types.
    $Type = switch ([string]$Code.OperandType) {
      'InlineFunction' { [IFPSLib.IFunction] }
      'InlineType' { [IFPSLib.Types.IType] }
      'InlineValue' { [IFPSLib.Emit.Operand] }
    }
    # Instruction implements IEnumerable<Operand>; keep it as one instruction.
    return , ([IFPSLib.Emit.Instruction].GetMethod('Create', [type[]]@([IFPSLib.Emit.OpCode], $Type)).Invoke($null, [object[]]@($Code, $Operand)))
  }

  function New-TestInnoFunction {
    param([string]$Name, [switch]$External, [int]$ArgumentCount = 0, [switch]$ReturnsValue)
    $Function = $External ? [IFPSLib.Emit.ExternalFunction]::new() : [IFPSLib.Emit.ScriptFunction]::new()
    $Function.Name = $Name
    $Function.Exported = -not $External
    if ($External) { $Function.Declaration = [IFPSLib.Emit.FDecl.Internal]::new() }
    $Function.Arguments = [Collections.Generic.List[IFPSLib.FunctionArgument]]::new()
    for ($Index = 0; $Index -lt $ArgumentCount; $Index++) {
      $Argument = [IFPSLib.FunctionArgument]::new()
      $Argument.ArgumentType = [IFPSLib.FunctionArgumentType]::In
      $Argument.Type = [IFPSLib.Types.PrimitiveType]::Create[int]()
      $Function.Arguments.Add($Argument)
    }
    if ($ReturnsValue) { $Function.ReturnArgument = [IFPSLib.Types.PrimitiveType]::Create[byte]() }
    return $Function
  }

  function Add-TestInnoRegistryCall {
    param($Function, $Target, $Root = 0x82000002L)
    $Function.Instructions.Add((New-TestInnoInstruction ([IFPSLib.Emit.OpCodes]::Push) ([IFPSLib.Emit.Operand]::Create('Value'))))
    $Function.Instructions.Add((New-TestInnoInstruction ([IFPSLib.Emit.OpCodes]::Push) ([IFPSLib.Emit.Operand]::Create('Software\Fixture'))))
    $Operand = $Root -is [IFPSLib.Emit.Operand] ? $Root : [IFPSLib.Emit.Operand]::Create($Root)
    $Function.Instructions.Add((New-TestInnoInstruction ([IFPSLib.Emit.OpCodes]::Push) ($Operand)))
    $Function.Instructions.Add((New-TestInnoInstruction ([IFPSLib.Emit.OpCodes]::PushType) ([IFPSLib.Types.PrimitiveType]::Create[byte]())))
    $Function.Instructions.Add((New-TestInnoInstruction ([IFPSLib.Emit.OpCodes]::Call) ($Target)))
    for ($Index = 0; $Index -lt 4; $Index++) { $Function.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Pop)) }
  }

  function New-TestInnoProgram {
    param($Startup, [object[]]$AdditionalFunctions = @())
    $Program = [IFPSLib.Script]::new()
    $Program.Functions.Add($Startup)
    foreach ($Function in $AdditionalFunctions) { $Program.Functions.Add($Function) }
    return $Program
  }
}

Describe 'Inno startup registry architecture analysis' -Tag Unit {
  It 'Rejects unsigned and signed explicit 64-bit roots: <Root>' -ForEach @(
    @{ Root = 0x82000002L }
    @{ Root = -2113929214 }
    @{ Root = 0x82000001L }
    @{ Root = 0x02000001L }
    @{ Root = 0x82000010L }
  ) {
    $Registry = New-TestInnoFunction -Name REGDELETEVALUE -External -ArgumentCount 3 -ReturnsValue
    $Startup = New-TestInnoFunction -Name InitializeWizard
    Add-TestInnoRegistryCall -Function $Startup -Target $Registry -Root $Root
    $Startup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret))

    $Result = Get-InnoPascalScriptArchitectureRequirement -Script (New-TestInnoProgram $Startup @($Registry))
    $Result.Requires64BitWindows | Should -BeTrue
    $Result.UnsupportedArchitectures | Should -Be @('x86')
    $Result.Evidence | Should -HaveCount 1
    $Result.Evidence[0].EntryPoint | Should -Be 'InitializeWizard'
    $Result.Evidence[0].Api | Should -Be 'REGDELETEVALUE'
    $Result.ConditionalEvidence | Should -BeNullOrEmpty
  }

  It 'Keeps native, 32-bit, and dual-flag roots compatible: <Root>' -ForEach @(
    @{ Root = 0x80000002L }
    @{ Root = 0x81000002L }
    @{ Root = 0x83000002L }
    @{ Root = 0x01000001L }
  ) {
    $Registry = New-TestInnoFunction -Name REGDELETEVALUE -External -ArgumentCount 3 -ReturnsValue
    $Startup = New-TestInnoFunction -Name InitializeWizard
    Add-TestInnoRegistryCall -Function $Startup -Target $Registry -Root $Root
    $Startup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret))
    $Result = Get-InnoPascalScriptArchitectureRequirement -Script (New-TestInnoProgram $Startup @($Registry))
    $Result.Requires64BitWindows | Should -BeFalse
    $Result.Evidence | Should -BeNullOrEmpty
    $Result.EntryPoints[0].ExecutionCompleted | Should -BeTrue
  }

  It 'Propagates a root argument through a directly called helper' {
    $Registry = New-TestInnoFunction -Name REGDELETEVALUE -External -ArgumentCount 3 -ReturnsValue
    $Helper = New-TestInnoFunction -Name DeleteStartupValue -ArgumentCount 1
    Add-TestInnoRegistryCall -Function $Helper -Target $Registry -Root ([IFPSLib.Emit.Operand]::Create($Helper.CreateArgumentVariable(0)))
    $Helper.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret))
    $Startup = New-TestInnoFunction -Name InitializeWizard
    $Startup.Instructions.Add((New-TestInnoInstruction ([IFPSLib.Emit.OpCodes]::Push) ([IFPSLib.Emit.Operand]::Create(0x82000002L))))
    $Startup.Instructions.Add((New-TestInnoInstruction ([IFPSLib.Emit.OpCodes]::Call) ($Helper)))
    $Startup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Pop))
    $Startup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret))

    $Result = Get-InnoPascalScriptArchitectureRequirement -Script (New-TestInnoProgram $Startup @($Helper, $Registry))
    $Result.Requires64BitWindows | Should -BeTrue
    $Result.Evidence[0].Function | Should -Be 'DeleteStartupValue'
    $Result.Evidence[0].RootKeyHex | Should -Be '0x82000002'
  }

  It 'Does not misclassify invalid roots or reserved flags as a 64-bit requirement' -ForEach @(
    @{ Root = 0x02000000L }
    @{ Root = 0x86000002L }
  ) {
    $Registry = New-TestInnoFunction -Name REGDELETEVALUE -External -ArgumentCount 3 -ReturnsValue
    $Startup = New-TestInnoFunction -Name InitializeWizard
    Add-TestInnoRegistryCall -Function $Startup -Target $Registry -Root $Root
    $Startup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret))
    $Result = Get-InnoPascalScriptArchitectureRequirement -Script (New-TestInnoProgram $Startup @($Registry))
    $Result.Requires64BitWindows | Should -BeFalse
    $Result.EntryPoints[0].ExecutionCompleted | Should -BeFalse
  }

  It 'Follows IsWin64 guards and opposite guards without guessing' -ForEach @(
    @{ Branch = 'JumpZ'; Expected = $false }
    @{ Branch = 'JumpNZ'; Expected = $true }
  ) {
    $Registry = New-TestInnoFunction -Name REGDELETEVALUE -External -ArgumentCount 3 -ReturnsValue
    $IsWin64 = New-TestInnoFunction -Name ISWIN64 -External -ReturnsValue
    $Startup = New-TestInnoFunction -Name InitializeWizard
    $Return = [IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret)
    $Startup.Instructions.Add((New-TestInnoInstruction ([IFPSLib.Emit.OpCodes]::PushType) ([IFPSLib.Types.PrimitiveType]::Create[byte]())))
    $Startup.Instructions.Add((New-TestInnoInstruction ([IFPSLib.Emit.OpCodes]::Call) ($IsWin64)))
    $OpCode = $Branch -eq 'JumpZ' ? [IFPSLib.Emit.OpCodes]::JumpZ : [IFPSLib.Emit.OpCodes]::JumpNZ
    $Startup.Instructions.Add([IFPSLib.Emit.Instruction]::Create($OpCode, $Return, [IFPSLib.Emit.Operand]::Create([IFPSLib.Emit.LocalVariable]::Create(0))))
    Add-TestInnoRegistryCall $Startup $Registry
    $Startup.Instructions.Add($Return)

    $Result = Get-InnoPascalScriptArchitectureRequirement -Script (New-TestInnoProgram $Startup @($Registry, $IsWin64))
    $Result.Requires64BitWindows | Should -Be $Expected
  }

  It 'Does not treat an unreachable or uninstall-only helper as a startup failure' {
    $Registry = New-TestInnoFunction -Name REGDELETEVALUE -External -ArgumentCount 3 -ReturnsValue
    $Unused = New-TestInnoFunction -Name CurUninstallStepChanged
    Add-TestInnoRegistryCall $Unused $Registry
    $Unused.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret))
    $Startup = New-TestInnoFunction -Name InitializeWizard
    $Startup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret))
    Add-TestInnoRegistryCall $Startup $Registry

    $Result = Get-InnoPascalScriptArchitectureRequirement -Script (New-TestInnoProgram $Startup @($Unused, $Registry))
    $Result.Requires64BitWindows | Should -BeFalse
    $Result.Evidence | Should -BeNullOrEmpty
    $Result.ConditionalEvidence | Should -BeNullOrEmpty
  }

  It 'Retains unknown-condition failures as conditional evidence' {
    $Registry = New-TestInnoFunction -Name REGDELETEVALUE -External -ArgumentCount 3 -ReturnsValue
    $Startup = New-TestInnoFunction -Name InitializeWizard
    $Return = [IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret)
    $Startup.Instructions.Add((New-TestInnoInstruction ([IFPSLib.Emit.OpCodes]::PushType) ([IFPSLib.Types.PrimitiveType]::Create[byte]())))
    $Startup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::JumpNZ, $Return, [IFPSLib.Emit.Operand]::Create([IFPSLib.Emit.LocalVariable]::Create(0))))
    Add-TestInnoRegistryCall $Startup $Registry
    $Startup.Instructions.Add($Return)

    $Result = Get-InnoPascalScriptArchitectureRequirement -Script (New-TestInnoProgram $Startup @($Registry))
    $Result.Requires64BitWindows | Should -BeFalse
    $Result.ConditionalEvidence | Should -HaveCount 1
    $Result.ConditionalEvidence[0].Conditional | Should -BeTrue
  }

  It 'Retains failures after opaque host calls without inventing a mandatory path' {
    $Registry = New-TestInnoFunction -Name REGDELETEVALUE -External -ArgumentCount 3 -ReturnsValue
    $Unknown = New-TestInnoFunction -Name EnvironmentDependentAction -External
    $Startup = New-TestInnoFunction -Name InitializeWizard
    $Startup.Instructions.Add((New-TestInnoInstruction ([IFPSLib.Emit.OpCodes]::Call) ($Unknown)))
    Add-TestInnoRegistryCall $Startup $Registry
    $Startup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret))

    $Result = Get-InnoPascalScriptArchitectureRequirement -Script (New-TestInnoProgram $Startup @($Registry, $Unknown))
    $Result.Requires64BitWindows | Should -BeFalse
    $Result.EntryPoints[0].ExecutionCompleted | Should -BeFalse
    $Result.Evidence | Should -BeNullOrEmpty
    $Result.ConditionalEvidence | Should -HaveCount 1
    $Result.ConditionalEvidence[0].Conditional | Should -BeTrue
  }

  It 'Inspects PrepareToInstall and propagates its NeedsRestart argument' {
    $Registry = New-TestInnoFunction -Name REGDELETEVALUE -External -ArgumentCount 3 -ReturnsValue
    $Prepare = New-TestInnoFunction -Name PrepareToInstall -ArgumentCount 1 -ReturnsValue
    $Prepare.ReturnArgument = [IFPSLib.Types.PrimitiveType]::Create[string]()
    $Prepare.Arguments[0].Type = [IFPSLib.Types.PrimitiveType]::Create[byte]()
    $Prepare.Arguments[0].ArgumentType = [IFPSLib.FunctionArgumentType]::Out
    $Return = [IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret)
    $Prepare.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::JumpNZ, $Return, [IFPSLib.Emit.Operand]::Create($Prepare.CreateArgumentVariable(0))))
    Add-TestInnoRegistryCall -Function $Prepare -Target $Registry
    $Prepare.Instructions.Add($Return)

    $Result = Get-InnoPascalScriptArchitectureRequirement -Script (New-TestInnoProgram $Prepare @($Registry))
    $Result.Requires64BitWindows | Should -BeTrue
    $Result.Evidence[0].EntryPoint | Should -Be 'PrepareToInstall'
  }

  It 'Invalidates Out values through SetPtr aliases before exploring a registry fallback' {
    $Query = New-TestInnoFunction -Name REGQUERYSTRINGVALUE -External -ArgumentCount 4 -ReturnsValue
    $Query.Arguments[3].ArgumentType = [IFPSLib.FunctionArgumentType]::Out
    $Registry = New-TestInnoFunction -Name REGDELETEVALUE -External -ArgumentCount 3 -ReturnsValue
    $Lookup = New-TestInnoFunction -Name FindPreviousUninstaller -ReturnsValue
    $Lookup.ReturnArgument = [IFPSLib.Types.PrimitiveType]::Create[string]()
    $ReturnValue = [IFPSLib.Emit.Operand]::Create($Lookup.CreateReturnVariable())
    $Boolean = [IFPSLib.Emit.Operand]::Create([IFPSLib.Emit.LocalVariable]::Create(0))
    $Pointer = [IFPSLib.Emit.Operand]::Create([IFPSLib.Emit.LocalVariable]::Create(1))
    $Lookup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Assign, $ReturnValue, [IFPSLib.Emit.Operand]::Create('')))
    $Lookup.Instructions.Add((New-TestInnoInstruction ([IFPSLib.Emit.OpCodes]::PushType) ([IFPSLib.Types.PrimitiveType]::Create[byte]())))
    $Lookup.Instructions.Add((New-TestInnoInstruction ([IFPSLib.Emit.OpCodes]::PushType) ([IFPSLib.Types.PrimitiveType]::new([IFPSLib.Types.PascalTypeCode]::Pointer))))
    $Lookup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::SetPtr, $Pointer, $ReturnValue))
    foreach ($Value in 'UninstallString', 'Software\Fixture', 0x81000002L) {
      $Lookup.Instructions.Add((New-TestInnoInstruction ([IFPSLib.Emit.OpCodes]::Push) ([IFPSLib.Emit.Operand]::Create($Value))))
    }
    $Lookup.Instructions.Add((New-TestInnoInstruction ([IFPSLib.Emit.OpCodes]::PushVar) $Boolean))
    $Lookup.Instructions.Add((New-TestInnoInstruction ([IFPSLib.Emit.OpCodes]::Call) $Query))
    for ($Index = 0; $Index -lt 5; $Index++) { $Lookup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Pop)) }
    $Return = [IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret)
    # If Out invalidation misses RetVal, its stale empty string would suppress
    # the fallback and hide the conditional 64-bit-view exception.
    $Lookup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Eq, $Boolean, $ReturnValue, [IFPSLib.Emit.Operand]::Create('')))
    $Lookup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::JumpNZ, $Return, $Boolean))
    Add-TestInnoRegistryCall -Function $Lookup -Target $Registry
    $Lookup.Instructions.Add($Return)

    $Result = Get-InnoPascalScriptStaticReturnInfo -Function $Lookup -CheckRegistryArchitecture
    $Result.Requires64BitRegistry | Should -BeFalse
    $Result.RegistryFailures | Should -HaveCount 1
    $Result.ForkCount | Should -Be 1
  }

  It 'Does not promote a later callback when InitializeSetup is unresolved or cancels' -ForEach @(
    @{ Mode = 'Cancels' }
    @{ Mode = 'Unsupported' }
    @{ Mode = 'UnknownReturn' }
  ) {
    $Registry = New-TestInnoFunction -Name REGDELETEVALUE -External -ArgumentCount 3 -ReturnsValue
    $Setup = New-TestInnoFunction -Name InitializeSetup -ReturnsValue
    if ($Mode -eq 'Cancels') {
      $Setup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Assign, [IFPSLib.Emit.Operand]::Create($Setup.CreateReturnVariable()), [IFPSLib.Emit.Operand]::Create([byte]0)))
    } elseif ($Mode -eq 'Unsupported') {
      $Setup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::CallVar, [IFPSLib.Emit.Operand]::Create([IFPSLib.Emit.LocalVariable]::Create(0))))
    }
    $Setup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret))
    $Wizard = New-TestInnoFunction -Name InitializeWizard
    Add-TestInnoRegistryCall $Wizard $Registry
    $Wizard.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret))

    $Result = Get-InnoPascalScriptArchitectureRequirement -Script (New-TestInnoProgram $Setup @($Wizard, $Registry))
    $Result.Requires64BitWindows | Should -BeFalse
    if ($Mode -ne 'Cancels') { $Result.ConditionalEvidence | Should -HaveCount 1 }
  }

  It 'Keeps exception-protected code and exhausted execution budgets unresolved' {
    $Registry = New-TestInnoFunction -Name REGDELETEVALUE -External -ArgumentCount 3 -ReturnsValue
    $Startup = New-TestInnoFunction -Name InitializeWizard
    # PopEH marks exception flow; the narrow interpreter must not assume that
    # an exception from the following registry call escapes its caller.
    $Startup.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::UNKNOWN_POPEH))
    Add-TestInnoRegistryCall $Startup $Registry
    $Result = Get-InnoPascalScriptStaticReturnInfo -Function $Startup -CheckRegistryArchitecture
    $Result.Requires64BitRegistry | Should -BeFalse
    $Result.ExecutionCompleted | Should -BeFalse
    $Budget = Get-InnoPascalScriptStaticReturnInfo -Function $Startup -CheckRegistryArchitecture -ExecutionBudget ([pscustomobject]@{ Remaining = 0 })
    $Budget.Requires64BitRegistry | Should -BeFalse
    $Budget.TruncatedPathCount | Should -Be 1
  }
}

Describe 'Inno registry architecture real regressions' -Tag RealFixture {
  It 'Excludes x86 for CHERRY startup and preserves metadata for authored x64 entries' {
    $Fixture = Get-DumplingsTestFixture -RelativePath 'Installers\Inno\CHERRY.UTILITY\3.12\CHERRY_Utility_Software_x32-3.12.exe' -Uri 'https://www.cherry.de/fileadmin/media/Corporate/Software/CHERRY_Utility_Software_x32-3.12.exe' -Sha256 '2FA52325747EE96B560F8BA8C304FEDC10D4AB75389258BFD8001168AF4BB238'
    $Info = Get-InnoInfo -Path $Fixture
    $Info.DisplayVersion | Should -Be '3.12'
    $Info.ProductCode | Should -Not -BeNullOrEmpty
    $Info.SupportedArchitectures | Should -Be @('x64', 'arm64')
    $Info.UnsupportedArchitectures | Should -Be @('x86')
    $Info.RegistryArchitectureRequirement.Evidence[0].RootKeyHex | Should -Be '0x82000002'
    $Info.ArchitectureRequirementEvidence[0].EntryPoint | Should -Be 'INITIALIZEWIZARD'
    @($Info.Diagnostics | Where-Object Id -EQ 'Inno.Architecture.Required64BitRegistry') | Should -HaveCount 1

    $X64 = Get-InnoInfo -Path $Fixture -Architecture x64 -IncludePascalScriptAnalysis
    $X64.UnsupportedArchitectures | Should -Be @('x86')
    $X64.ArchitectureRequirementEvidence | Should -HaveCount 1
    $X64.PascalScriptInfo.ArchitectureRequirement.Requires64BitWindows | Should -BeTrue
    @($X64.Diagnostics | Where-Object Id -EQ 'Inno.Architecture.Required64BitRegistry') | Should -HaveCount 0
  }

  It 'Does not invent a registry requirement in current Caramba media' {
    $Fixture = Get-DumplingsTestFixture -RelativePath 'Installers\Inno\SergeyMoskalev.CarambaSwitcher\2026.09.24\CarambaSwitcher.2026.09.24.exe' -Uri 'https://cdn.caramba-switcher.com/files/CarambaSwitcher.2026.09.24.exe' -Sha256 '56E177712185BC0FF0BC9D92509D017F786C392617DC8EC7A77EC57036254991'
    $Info = Get-InnoInfo -Path $Fixture
    $Info.DisplayName | Should -Be 'Caramba Switcher'
    $Info.RegistryArchitectureRequirement.Requires64BitWindows | Should -BeFalse
    $Info.UnsupportedArchitectures | Should -BeNullOrEmpty
    $Info.ArchitectureRequirementEvidence | Should -BeNullOrEmpty
    $Info.ConditionalArchitectureRequirementEvidence | Should -BeNullOrEmpty
    $Info.SupportedArchitectures | Should -Contain 'x86'
    @($Info.Diagnostics | Where-Object Id -EQ 'Inno.Architecture.Required64BitRegistry') | Should -HaveCount 0
  }

  It 'Reports the Pro migration fallback as conditional x86 evidence' {
    # The publisher exposes a mutable latest URL. Use the preserved, pinned PR
    # fixture only; CI must not replace it with a different release.
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath 'Installers\Inno\SergeyMoskalev.CarambaSwitcher.Pro\2026.09.26.2\CarambaSwitcherProSetup-latest.exe'
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture -Sha256 'AB3A737478ED11892242A2289ED2CF4190CB55445D34A2EED125FDA1979DFAF3')) {
      Set-ItResult -Skipped -Because 'The pinned Caramba Switcher Pro fixture is unavailable; its latest URL is mutable.'
      return
    }
    $Info = Get-InnoInfo -Path $Fixture -Architecture x86
    $Info.DisplayName | Should -Be 'Caramba Switcher Pro'
    $Info.DisplayVersion | Should -Be '2026.09.26.2'
    $Info.ProductCode | Should -Be '{B7E4B0C2-9B1A-4F3E-8D2A-1C5E7A9F60D3}_is1'
    $Info.RegistryArchitectureRequirement.Requires64BitWindows | Should -BeFalse
    $Info.UnsupportedArchitectures | Should -BeNullOrEmpty
    $Info.SupportedArchitectures | Should -Contain 'x86'
    $Info.ConditionalArchitectureRequirementEvidence | Should -HaveCount 1
    $Evidence = $Info.ConditionalArchitectureRequirementEvidence[0]
    $Evidence.EntryPoint | Should -Be 'PREPARETOINSTALL'
    $Evidence.Function | Should -Be 'CLASSICUNINSTALLERIN'
    $Evidence.Api | Should -Be 'REGQUERYSTRINGVALUE'
    $Evidence.RootKeyHex | Should -Be '0x82000002'
    @($Info.Diagnostics | Where-Object Id -EQ 'Inno.Architecture.Conditional64BitRegistry') | Should -HaveCount 1

    $X64 = Get-InnoInfo -Path $Fixture -Architecture x64 -IncludePascalScriptAnalysis
    $X64.ConditionalArchitectureRequirementEvidence | Should -HaveCount 1
    @($X64.Diagnostics | Where-Object Id -EQ 'Inno.Architecture.Conditional64BitRegistry') | Should -HaveCount 0
  }
}
