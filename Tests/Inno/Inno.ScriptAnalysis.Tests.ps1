. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InnoTestSetup.ps1')

Describe 'Inno Pascal Script analysis' -Tag Unit {
  It 'Should return bounded Pascal Script disassembly on explicit request' {
    $Fixture = Get-InstallerFixture -Name 'winscp-6.5.6-setup.exe' -Url 'https://sourceforge.net/projects/winscp/files/WinSCP/6.5.6/WinSCP-6.5.6-Setup.exe/download' -UseSourceForgeMetaRefresh
    $Info = Get-InnoPascalScriptInfo -Path $Fixture -IncludeDisassembly -MaximumDisassemblyCharacters 2048

    $Info.Present | Should -BeTrue
    $Info.EntryPoint | Should -Be '!MAIN'
    $Info.TypeCount | Should -Be 79
    $Info.FunctionCount | Should -Be 223
    $Info.ScriptFunctionCount | Should -Be 53
    $Info.ExternalFunctionCount | Should -Be 170
    $Info.DllImports | Should -HaveCount 3
    $Info.InstructionCount | Should -Be 8588
    $Info.Types | Should -HaveCount 79
    $Info.GlobalVariables | Should -HaveCount 35
    $Info.Functions | Should -HaveCount 223
    $Info.RuntimeEffects | Should -Not -BeNullOrEmpty
    $Info.RuntimeEffects.Category | Should -Contain 'ScopeOrElevation'
    $Info.RuntimeEffects.Category | Should -Contain 'SilentInteraction'
    $Info.IndirectCallCount | Should -Be 0
    $Info.UnknownOpcodeCount | Should -Be 0
    $Info.Disassembly.Length | Should -Be 2048
    $Info.Disassembly | Should -Match '^\.version 23'
    $Info.DisassemblyTruncated | Should -BeTrue
    $Info.Diagnostics.Message | Should -Contain 'The IFPS disassembly was truncated at 2048 characters.'
  }

  It 'Should resolve a straight-line constant Pascal Script return' {
    InModuleScope Inno {
      Import-InnoPascalScriptDependency
      $Function = [IFPSLib.Emit.ScriptFunction]::new()
      $Function.Name = 'StaticInstallPath'
      $Function.ReturnArgument = [IFPSLib.Types.PrimitiveType]::Create[string]()
      $ReturnVariable = $Function.CreateReturnVariable()
      $Function.Instructions.Add([IFPSLib.Emit.Instruction]::Create(
          [IFPSLib.Emit.OpCodes]::Assign,
          [IFPSLib.Emit.Operand]::Create($ReturnVariable),
          [IFPSLib.Emit.Operand]::Create('C:\StaticPath')
        ))
      $Function.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret))

      $Return = Get-InnoPascalScriptStaticReturnInfo -Function $Function
      $Return.IsResolved | Should -BeTrue
      $Return.Value | Should -Be 'C:\StaticPath'

      $Map = Get-InnoPascalScriptConstantMap -PascalScriptInfo ([pscustomobject]@{
          StaticReturnValues = @([pscustomobject]@{ Function = 'StaticInstallPath'; Value = 'C:\StaticPath' })
        }) -Values @('{code:StaticInstallPath}', '{code:StaticInstallPath|ignored parameter}')
      $Map['code:StaticInstallPath'] | Should -Be 'C:\StaticPath'
      $Map['code:StaticInstallPath|ignored parameter'] | Should -Be 'C:\StaticPath'
    }
  }

  It 'Should merge unknown Pascal Script branches that return the same constant' {
    InModuleScope Inno {
      Import-InnoPascalScriptDependency
      $Function = [IFPSLib.Emit.ScriptFunction]::new()
      $Function.Name = 'ConvergentBranch'
      $Function.ReturnArgument = [IFPSLib.Types.PrimitiveType]::Create[string]()
      $ReturnVariable = $Function.CreateReturnVariable()
      $UnknownCondition = [IFPSLib.Emit.LocalVariable]::Create(0)
      $Return = [IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret)
      $BranchAssignment = [IFPSLib.Emit.Instruction]::Create(
        [IFPSLib.Emit.OpCodes]::Assign,
        [IFPSLib.Emit.Operand]::Create($ReturnVariable),
        [IFPSLib.Emit.Operand]::Create('same value')
      )
      $Function.Instructions.Add([IFPSLib.Emit.Instruction]::Create(
          [IFPSLib.Emit.OpCodes]::JumpNZ,
          $BranchAssignment,
          [IFPSLib.Emit.Operand]::Create($UnknownCondition)
        ))
      $Function.Instructions.Add([IFPSLib.Emit.Instruction]::Create(
          [IFPSLib.Emit.OpCodes]::Assign,
          [IFPSLib.Emit.Operand]::Create($ReturnVariable),
          [IFPSLib.Emit.Operand]::Create('same value')
        ))
      $Function.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Jump, $Return))
      $Function.Instructions.Add($BranchAssignment)
      $Function.Instructions.Add($Return)

      $Result = Get-InnoPascalScriptStaticReturnInfo -Function $Function

      $Result.IsResolved | Should -BeTrue
      $Result.Value | Should -Be 'same value'
      $Result.ExploredPathCount | Should -Be 2
      $Result.ForkCount | Should -Be 1
      $Result.TruncatedPathCount | Should -Be 0
      $Result.BranchPredicates | Should -HaveCount 1
    }
  }

  It 'Should reject divergent Pascal Script branch returns' {
    InModuleScope Inno {
      Import-InnoPascalScriptDependency
      $Function = [IFPSLib.Emit.ScriptFunction]::new()
      $Function.Name = 'DivergentBranch'
      $Function.ReturnArgument = [IFPSLib.Types.PrimitiveType]::Create[string]()
      $ReturnVariable = $Function.CreateReturnVariable()
      $UnknownCondition = [IFPSLib.Emit.LocalVariable]::Create(0)
      $Return = [IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret)
      $BranchAssignment = [IFPSLib.Emit.Instruction]::Create(
        [IFPSLib.Emit.OpCodes]::Assign,
        [IFPSLib.Emit.Operand]::Create($ReturnVariable),
        [IFPSLib.Emit.Operand]::Create('branch value')
      )
      $Function.Instructions.Add([IFPSLib.Emit.Instruction]::Create(
          [IFPSLib.Emit.OpCodes]::JumpZ,
          $BranchAssignment,
          [IFPSLib.Emit.Operand]::Create($UnknownCondition)
        ))
      $Function.Instructions.Add([IFPSLib.Emit.Instruction]::Create(
          [IFPSLib.Emit.OpCodes]::Assign,
          [IFPSLib.Emit.Operand]::Create($ReturnVariable),
          [IFPSLib.Emit.Operand]::Create('fallthrough value')
        ))
      $Function.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Jump, $Return))
      $Function.Instructions.Add($BranchAssignment)
      $Function.Instructions.Add($Return)

      $Result = Get-InnoPascalScriptStaticReturnInfo -Function $Function

      $Result.IsResolved | Should -BeFalse
      $Result.Reason | Should -Be 'Branch paths return different constants'
      $Result.ReturnValues | Should -Contain 'branch value'
      $Result.ReturnValues | Should -Contain 'fallthrough value'
    }
  }

  It 'Should follow a resolved Pascal Script comparison without forking' {
    InModuleScope Inno {
      Import-InnoPascalScriptDependency
      $Function = [IFPSLib.Emit.ScriptFunction]::new()
      $Function.Name = 'ResolvedComparison'
      $Function.ReturnArgument = [IFPSLib.Types.PrimitiveType]::Create[byte]()
      $ReturnVariable = $Function.CreateReturnVariable()
      $Condition = [IFPSLib.Emit.LocalVariable]::Create(0)
      $FalseReturn = [IFPSLib.Emit.Instruction]::Create(
        [IFPSLib.Emit.OpCodes]::Assign,
        [IFPSLib.Emit.Operand]::Create($ReturnVariable),
        [IFPSLib.Emit.Operand]::Create([byte]0)
      )
      $Return = [IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Ret)
      $Function.Instructions.Add([IFPSLib.Emit.Instruction]::Create(
          [IFPSLib.Emit.OpCodes]::Eq,
          [IFPSLib.Emit.Operand]::Create($Condition),
          [IFPSLib.Emit.Operand]::Create(7),
          [IFPSLib.Emit.Operand]::Create(7)
        ))
      $Function.Instructions.Add([IFPSLib.Emit.Instruction]::Create(
          [IFPSLib.Emit.OpCodes]::JumpZ,
          $FalseReturn,
          [IFPSLib.Emit.Operand]::Create($Condition)
        ))
      $Function.Instructions.Add([IFPSLib.Emit.Instruction]::Create(
          [IFPSLib.Emit.OpCodes]::Assign,
          [IFPSLib.Emit.Operand]::Create($ReturnVariable),
          [IFPSLib.Emit.Operand]::Create([byte]1)
        ))
      $Function.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Jump, $Return))
      $Function.Instructions.Add($FalseReturn)
      $Function.Instructions.Add($Return)

      $Result = Get-InnoPascalScriptStaticReturnInfo -Function $Function

      $Result.IsResolved | Should -BeTrue
      $Result.Value | Should -Be 1
      $Result.ForkCount | Should -Be 0
      (Get-InnoBooleanDirectiveInfo -Value 'not ResolvedComparison' -Default $true -StaticReturnValues @{ ResolvedComparison = $true }).Value | Should -BeFalse
    }
  }

  It 'Should bound looping Pascal Script paths' {
    InModuleScope Inno {
      Import-InnoPascalScriptDependency
      $Function = [IFPSLib.Emit.ScriptFunction]::new()
      $Function.Name = 'LoopingReturn'
      $Function.ReturnArgument = [IFPSLib.Types.PrimitiveType]::Create[string]()
      $LoopTarget = [IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Nop)
      $Function.Instructions.Add($LoopTarget)
      $Function.Instructions.Add([IFPSLib.Emit.Instruction]::Create([IFPSLib.Emit.OpCodes]::Jump, $LoopTarget))

      $Result = Get-InnoPascalScriptStaticReturnInfo -Function $Function

      $Result.IsResolved | Should -BeFalse
      $Result.TruncatedPathCount | Should -Be 1
      $Result.Reason | Should -Be 'One or more branch paths exceeded the static-analysis bounds'
    }
  }

  It 'Should verify the pinned IFPS runtime assets' {
    $AssetRoot = Join-Path $Script:DumplingsModuleRoot 'Assets'
    $AssemblyRoot = Join-Path $AssetRoot 'Assemblies'
    $Manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $AssetRoot 'IFPSLibAssets.psd1')
    $Manifest.SourceCommit | Should -Be '5c56d48f5d56da8ada888bff08de80058cf9d531'
    foreach ($Assembly in $Manifest.Assemblies) {
      $Path = Join-Path $AssemblyRoot $Assembly.Name
      (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash | Should -Be $Assembly.Sha256
      [Reflection.AssemblyName]::GetAssemblyName($Path).Version.ToString() | Should -Be $Assembly.Version
    }
  }

  It 'Should reject malformed IFPS entity counts before loading IFPSLib' {
    InModuleScope Inno {
      $Bytes = [byte[]]::new(28)
      [Text.Encoding]::ASCII.GetBytes('IFPS').CopyTo($Bytes, 0)
      [BitConverter]::GetBytes([int]23).CopyTo($Bytes, 4)
      [BitConverter]::GetBytes([int]::MaxValue).CopyTo($Bytes, 8)
      [BitConverter]::GetBytes([int]-1).CopyTo($Bytes, 20)

      { ConvertTo-InnoPascalScriptInfo -Bytes $Bytes } | Should -Throw '*invalid entity count*'
    }
  }
}
