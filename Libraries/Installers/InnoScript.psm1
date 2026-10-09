# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# Internal Inno implementation. See Inno.psm1 for format sources and the binary layout.
# Pass parsed contexts explicitly and keep caller-owned streams local.

# Inno script implementation, imported locally by the public facade.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$INNO_MAX_COMPILED_CODE_SIZE = 16777216

$INNO_MAX_PASCAL_SCRIPT_ENTITY_COUNT = 262144

$INNO_MAX_PASCAL_SCRIPT_DISASSEMBLY_INPUT_SIZE = 1048576

$INNO_DEFAULT_MAX_DISASSEMBLY_CHARACTERS = 4194304

$INNO_MAX_PASCAL_SCRIPT_BRANCH_PATHS = 16

$INNO_MAX_PASCAL_SCRIPT_BRANCH_DEPTH = 8

$INNO_MAX_PASCAL_SCRIPT_WATCHDOG_MULTIPLIER = 4

$INNO_MAX_PASCAL_SCRIPT_STARTUP_INSTRUCTIONS = 16384

$Script:InnoPascalScriptAssetManifest = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot '..\..\Assets\IFPSLibAssets.psd1')

function Import-InnoPascalScriptDependency {
  <#
  .SYNOPSIS
    Load the pinned IFPSLib dependency chain used for compiled Pascal Script analysis.
  .DESCRIPTION
    IFPSLib is loaded only after the caller has validated the bounded IFPS header. The
    dependency remains inside the process-isolated GPL parser and is never loaded by
    PackageModule directly.
  #>
  $AssetRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\Assets')).Path
  $AssemblyRoot = Join-Path $AssetRoot 'Assemblies'
  foreach ($Asset in $Script:InnoPascalScriptAssetManifest.Assemblies) {
    $AssetPath = Join-Path $AssemblyRoot $Asset.Name
    if (-not (Test-Path -LiteralPath $AssetPath -PathType Leaf)) { throw "The pinned IFPS dependency is missing: $AssetPath" }
    $ActualHash = (Get-FileHash -LiteralPath $AssetPath -Algorithm SHA256).Hash
    if ($ActualHash -cne $Asset.Sha256) {
      throw "The pinned IFPS dependency '$($Asset.Name)' failed its SHA-256 integrity check."
    }
    $Assembly = Import-InstallerManagedAssembly -Name $Asset.Name -TypeName $Asset.TypeName
    if ($Assembly.GetName().Version.ToString() -cne $Asset.Version) {
      throw "The loaded IFPS dependency '$($Asset.Name)' has version '$($Assembly.GetName().Version)', expected '$($Asset.Version)'."
    }
  }
}

function Read-InnoPascalScriptHeader {
  <#
  .SYNOPSIS
    Validate the bounded IFPS header without decoding bytecode tables.
  .PARAMETER Bytes
    Raw CompiledCodeText bytes.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

  if ($Bytes.Length -eq 0) {
    return [pscustomobject][ordered]@{
      Present = $false; ByteLength = 0; FileVersion = $null; TypeCount = 0
      FunctionCount = 0; GlobalVariableCount = 0; EntryPointIndex = $null
      ImportSize = 0; AnalysisStatus = 'NotPresent'
    }
  }
  if ($Bytes.Length -gt $INNO_MAX_COMPILED_CODE_SIZE) {
    throw "The compiled Inno Pascal Script exceeds the $INNO_MAX_COMPILED_CODE_SIZE-byte analysis limit."
  }
  if ($Bytes.Length -lt 28 -or [Text.Encoding]::ASCII.GetString($Bytes, 0, 4) -cne 'IFPS') {
    throw 'CompiledCodeText does not contain an IFPS program header.'
  }

  # The IFPS header is six signed little-endian Int32 fields after the magic.
  # Validate counts before IFPSLib constructs any attacker-controlled lists.
  $FileVersion = [BitConverter]::ToInt32($Bytes, 4)
  $TypeCount = [BitConverter]::ToInt32($Bytes, 8)
  $FunctionCount = [BitConverter]::ToInt32($Bytes, 12)
  $VariableCount = [BitConverter]::ToInt32($Bytes, 16)
  $EntryPointIndex = [BitConverter]::ToInt32($Bytes, 20)
  $ImportSize = [BitConverter]::ToInt32($Bytes, 24)
  if ($FileVersion -lt 12 -or $FileVersion -gt 23) { throw "Unsupported IFPS bytecode version: $FileVersion" }
  foreach ($Count in @($TypeCount, $FunctionCount, $VariableCount)) {
    if ($Count -lt 0 -or $Count -gt $INNO_MAX_PASCAL_SCRIPT_ENTITY_COUNT -or $Count -gt $Bytes.Length) {
      throw 'The IFPS header contains an invalid entity count.'
    }
  }
  if (([long]$TypeCount + $FunctionCount + $VariableCount) -gt $INNO_MAX_PASCAL_SCRIPT_ENTITY_COUNT) {
    throw 'The IFPS header exceeds the aggregate entity-count limit.'
  }
  if ($EntryPointIndex -lt -1 -or $EntryPointIndex -ge $FunctionCount) { throw 'The IFPS entry-point index is invalid.' }
  if ($ImportSize -lt 0 -or $ImportSize -gt ($Bytes.Length - 28)) { throw 'The IFPS import-table size is invalid.' }

  return [pscustomobject][ordered]@{
    Present             = $true
    ByteLength          = $Bytes.Length
    FileVersion         = $FileVersion
    TypeCount           = $TypeCount
    FunctionCount       = $FunctionCount
    GlobalVariableCount = $VariableCount
    EntryPointIndex     = $EntryPointIndex
    ImportSize          = $ImportSize
    AnalysisStatus      = 'AvailableOnRequest'
  }
}

function Get-InnoPascalScriptVariableKey {
  <#
  .SYNOPSIS
    Build a stable key for one IFPS variable operand.
  .PARAMETER Operand
    IFPSLib operand expected to refer directly to a variable.
  .PARAMETER References
    Optional path-local SetPtr aliases. Cyclic or excessive alias chains remain unresolved.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][object]$Operand,
    [Collections.Generic.Dictionary[string, string]]$References
  )

  if ([string]$Operand.Type -cne 'Variable') { return $null }
  $Key = '{0}:{1}' -f $Operand.Variable.VarType, $Operand.Variable.Index
  for ($Depth = 0; $null -ne $References -and $References.ContainsKey($Key); $Depth++) {
    if ($Depth -ge 8) { return $null }
    $Key = $References[$Key]
  }
  return $Key
}

function Get-InnoPascalScriptOperandConstant {
  <#
  .SYNOPSIS
    Resolve a JSON-safe immediate or a previously proven variable constant.
  .PARAMETER Operand
    IFPSLib operand to inspect.
  .PARAMETER State
    Path-local variable state keyed by variable kind and index.
  .PARAMETER References
    Optional path-local aliases used to dereference IFPS pointer operands.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][object]$Operand,
    [Parameter(Mandatory)][System.Collections.Generic.Dictionary[string, object]]$State,
    [Collections.Generic.Dictionary[string, string]]$References
  )

  if ([string]$Operand.Type -ceq 'Variable') {
    $Key = Get-InnoPascalScriptVariableKey -Operand $Operand -References $References
    if ($Key -and $State.ContainsKey($Key)) {
      return [pscustomobject]@{ Resolved = $true; Value = $State[$Key] }
    }
    return [pscustomobject]@{ Resolved = $false; Value = $null }
  }
  if ([string]$Operand.Type -cne 'Immediate') {
    return [pscustomobject]@{ Resolved = $false; Value = $null }
  }

  $Value = $Operand.Immediate
  if ($null -eq $Value -or $Value -is [string] -or $Value -is [char] -or $Value -is [bool] -or
    $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or
    $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64] -or
    $Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) {
    return [pscustomobject]@{ Resolved = $true; Value = $Value }
  }
  if ($Value.GetType().IsEnum) {
    return [pscustomobject]@{ Resolved = $true; Value = [string]$Value }
  }
  return [pscustomobject]@{ Resolved = $false; Value = $null }
}

function Copy-InnoPascalScriptConstantState {
  <#
  .SYNOPSIS
    Clone one path-local IFPS constant environment before exploring a branch.
  .PARAMETER State
    Primitive constants keyed by IFPS variable kind and index.
  #>
  [OutputType([System.Collections.Generic.Dictionary[string, object]])]
  param ([Parameter(Mandatory)][System.Collections.Generic.Dictionary[string, object]]$State)

  $Copy = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
  foreach ($Entry in $State.GetEnumerator()) { $Copy[$Entry.Key] = $Entry.Value }
  return $Copy
}

function ConvertTo-InnoPascalScriptBooleanConstant {
  <#
  .SYNOPSIS
    Convert an IFPS primitive into the zero/nonzero condition used by branch opcodes.
  .PARAMETER Value
    A statically proven primitive operand value.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][object]$Value)

  if ($null -eq $Value) { return [pscustomobject]@{ Resolved = $true; Value = $false } }
  if ($Value -is [bool]) { return [pscustomobject]@{ Resolved = $true; Value = [bool]$Value } }
  if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or
    $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64] -or
    $Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) {
    return [pscustomobject]@{ Resolved = $true; Value = $Value -ne 0 }
  }
  return [pscustomobject]@{ Resolved = $false; Value = $null }
}

function Test-InnoPascalScriptConstantEqual {
  <#
  .SYNOPSIS
    Compare two proven IFPS primitive values without coercing string casing.
  .PARAMETER Left
    First primitive value.
  .PARAMETER Right
    Second primitive value.
  #>
  [OutputType([bool])]
  param ([AllowNull()][object]$Left, [AllowNull()][object]$Right)

  if ($null -eq $Left -or $null -eq $Right) { return $null -eq $Left -and $null -eq $Right }
  if ($Left -is [string] -or $Right -is [string] -or $Left -is [char] -or $Right -is [char]) {
    return [string]$Left -ceq [string]$Right
  }
  return $Left -eq $Right
}

function Get-InnoPascalScriptBranchTargetIndex {
  <#
  .SYNOPSIS
    Resolve an IFPSLib branch-target operand to its function-local instruction index.
  .PARAMETER Operand
    Immediate operand expected to contain an IFPSLib Instruction object.
  .PARAMETER InstructionIndex
    Reference-keyed instruction-to-index dictionary for the current function.
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory)][object]$Operand,
    [Parameter(Mandatory)][System.Collections.Generic.Dictionary[object, int]]$InstructionIndex
  )

  if ([string]$Operand.Type -cne 'Immediate' -or $null -eq $Operand.Immediate -or
    -not $InstructionIndex.ContainsKey($Operand.Immediate)) {
    return -1
  }
  return $InstructionIndex[$Operand.Immediate]
}

function Get-InnoPascalScriptStaticReturnInfo {
  <#
  .SYNOPSIS
    Prove a constant IFPS return value across bounded control-flow alternatives.
  .DESCRIPTION
    The evaluator propagates primitive constants through assignments, arithmetic,
    comparisons, and direct branches. Unknown conditions fork isolated paths.
    Calls, exception flow, indexed values, and unknown opcodes make only
    the affected path unresolved. A value is returned only when every terminal
    path completes within the configured bounds and agrees on the same constant.
    The optional startup mode additionally follows direct calls, simple SetPtr aliases,
    and registry root validation on x86. It can continue after an opaque call to collect
    conditional evidence, but cannot prove completion or a mandatory failure on that
    path. It never executes script code or accesses the host registry.
  .PARAMETER Function
    IFPSLib script function to inspect.
  .PARAMETER CheckRegistryArchitecture
    Evaluate startup execution on x86, including bounded direct calls and registry-view failures.
    No registry, DLL, or installer code is executed on the host.
  .PARAMETER Arguments
    Resolved/Value operand results in declaration order for a directly called script function.
  .PARAMETER CallDepth
    Current direct-call depth; recursive or excessively deep paths remain unresolved.
  .PARAMETER ExecutionBudget
    Shared remaining instruction budget across the startup call tree and branch alternatives.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][object]$Function,
    [switch]$CheckRegistryArchitecture,
    [object[]]$Arguments = @(),
    [int]$CallDepth = 0,
    [pscustomobject]$ExecutionBudget = [pscustomobject]@{ Remaining = $INNO_MAX_PASCAL_SCRIPT_STARTUP_INSTRUCTIONS }
  )

  if ($Function.GetType().FullName -cne 'IFPSLib.Emit.ScriptFunction' -or
    (-not $CheckRegistryArchitecture -and $null -eq $Function.ReturnArgument)) {
    return [pscustomobject]@{
      IsResolved = $false; Value = $null; Reason = 'No script return value'; ExploredPathCount = 0
      ForkCount = 0; TruncatedPathCount = 0; BranchPredicates = [string[]]@(); ReturnValues = [object[]]@()
      RegistryFailures = [object[]]@(); Requires64BitRegistry = $false; ExecutionCompleted = $false
    }
  }

  $InstructionCount = $Function.Instructions.Count
  if ($InstructionCount -eq 0) {
    return [pscustomobject]@{
      IsResolved = $false; Value = $null; Reason = 'Return variable is not constant'; ExploredPathCount = 1
      ForkCount = 0; TruncatedPathCount = 0; BranchPredicates = [string[]]@(); ReturnValues = [object[]]@()
      RegistryFailures = [object[]]@(); Requires64BitRegistry = $false; ExecutionCompleted = $true
    }
  }
  $InstructionIndex = [System.Collections.Generic.Dictionary[object, int]]::new([System.Collections.Generic.ReferenceEqualityComparer]::Instance)
  for ($Index = 0; $Index -lt $InstructionCount; $Index++) { $InstructionIndex[$Function.Instructions[$Index]] = $Index }
  $PathWatchdog = [Math]::Max($InstructionCount * $INNO_MAX_PASCAL_SCRIPT_WATCHDOG_MULTIPLIER, 1)
  $AggregateWatchdog = $PathWatchdog * $INNO_MAX_PASCAL_SCRIPT_BRANCH_PATHS
  $ReturnKey = 'Argument:0'
  $Queue = [System.Collections.Generic.Queue[object]]::new()
  $InitialState = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
  # IFPS reserves Argument:0 for a return value only in non-void functions.
  for ($Index = 0; $Index -lt $Arguments.Count; $Index++) {
    if ($Arguments[$Index].Resolved) {
      $InitialState['Argument:{0}' -f ($Index + [int]($null -ne $Function.ReturnArgument))] = $Arguments[$Index].Value
    }
  }
  $Queue.Enqueue([pscustomobject]@{
      Position = 0; Steps = 0; Depth = 0; State = $InitialState; JumpFlagResolved = $false; JumpFlag = $false
      Predicates = [System.Collections.Generic.List[string]]::new()
      Stack = [System.Collections.Generic.List[object]]::new()
      References = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
      UnresolvedCallReason = $null
    })
  $TerminalPaths = [System.Collections.Generic.List[object]]::new()
  $BranchPredicates = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $CreatedPathCount = 1
  $ForkCount = 0
  $TotalSteps = 0
  $RegistryFailures = [System.Collections.Generic.List[object]]::new()

  while ($Queue.Count -gt 0) {
    $Path = $Queue.Dequeue()
    $PathTerminated = $false
    while ($Path.Position -ge 0 -and $Path.Position -lt $InstructionCount) {
      $Instruction = $Function.Instructions[$Path.Position]
      $Code = [string]$Instruction.OpCode.Code
      $Path.Steps++
      $TotalSteps++
      if ($CheckRegistryArchitecture) { $ExecutionBudget.Remaining-- }
      if ($Path.Steps -gt $PathWatchdog -or $TotalSteps -gt $AggregateWatchdog -or
        ($CheckRegistryArchitecture -and ($ExecutionBudget.Remaining -lt 0 -or $CallDepth -gt 8))) {
        $TerminalPaths.Add([pscustomobject]@{
            Resolved = $false; Value = $null; Reason = 'Bounded branch execution budget was exhausted'
            Truncated = $true; Predicates = [string[]]$Path.Predicates.ToArray()
          })
        $PathTerminated = $true
        break
      }

      $NextPosition = $Path.Position + 1
      $ForkTargets = $null
      $ForkReason = $null
      switch ($Code) {
        'Assign' {
          $Destination = Get-InnoPascalScriptVariableKey -Operand $Instruction.Operands[0] -References $Path.References
          if (-not $Destination) {
            $TerminalPaths.Add([pscustomobject]@{ Resolved = $false; Value = $null; Reason = 'Indirect assignment'; Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray() })
            $PathTerminated = $true
            break
          }
          $Source = Get-InnoPascalScriptOperandConstant -Operand $Instruction.Operands[1] -State $Path.State -References $Path.References
          if ($Source.Resolved) { $Path.State[$Destination] = $Source.Value } else { $null = $Path.State.Remove($Destination) }
        }
        { $_ -in @('Add', 'Sub', 'Mul', 'Div', 'Mod', 'Shl', 'Shr', 'And', 'Or', 'Xor') } {
          $Destination = Get-InnoPascalScriptVariableKey -Operand $Instruction.Operands[0] -References $Path.References
          $Right = Get-InnoPascalScriptOperandConstant -Operand $Instruction.Operands[1] -State $Path.State -References $Path.References
          if (-not $Destination -or -not $Path.State.ContainsKey($Destination) -or -not $Right.Resolved) {
            if ($Destination) { $null = $Path.State.Remove($Destination) }
            break
          }
          try {
            $LeftValue = $Path.State[$Destination]
            $Path.State[$Destination] = switch ($Code) {
              'Add' { $LeftValue -is [string] -or $Right.Value -is [string] ? ([string]$LeftValue + [string]$Right.Value) : ($LeftValue + $Right.Value) }
              'Sub' { $LeftValue - $Right.Value }
              'Mul' { $LeftValue * $Right.Value }
              'Div' { $LeftValue / $Right.Value }
              'Mod' { $LeftValue % $Right.Value }
              'Shl' { [long]$LeftValue -shl [int]$Right.Value }
              'Shr' { [long]$LeftValue -shr [int]$Right.Value }
              'And' { $LeftValue -is [bool] -and $Right.Value -is [bool] ? ($LeftValue -and $Right.Value) : ([long]$LeftValue -band [long]$Right.Value) }
              'Or' { $LeftValue -is [bool] -and $Right.Value -is [bool] ? ($LeftValue -or $Right.Value) : ([long]$LeftValue -bor [long]$Right.Value) }
              'Xor' { $LeftValue -is [bool] -and $Right.Value -is [bool] ? ($LeftValue -xor $Right.Value) : ([long]$LeftValue -bxor [long]$Right.Value) }
            }
          } catch {
            $null = $Path.State.Remove($Destination)
          }
        }
        { $_ -in @('Ge', 'Le', 'Gt', 'Lt', 'Ne', 'Eq') } {
          $Destination = Get-InnoPascalScriptVariableKey -Operand $Instruction.Operands[0] -References $Path.References
          $Left = Get-InnoPascalScriptOperandConstant -Operand $Instruction.Operands[1] -State $Path.State -References $Path.References
          $Right = Get-InnoPascalScriptOperandConstant -Operand $Instruction.Operands[2] -State $Path.State -References $Path.References
          if (-not $Destination -or -not $Left.Resolved -or -not $Right.Resolved) {
            if ($Destination) { $null = $Path.State.Remove($Destination) }
            break
          }
          try {
            $Path.State[$Destination] = switch ($Code) {
              'Ge' { $Left.Value -ge $Right.Value }
              'Le' { $Left.Value -le $Right.Value }
              'Gt' { $Left.Value -gt $Right.Value }
              'Lt' { $Left.Value -lt $Right.Value }
              'Ne' { -not (Test-InnoPascalScriptConstantEqual -Left $Left.Value -Right $Right.Value) }
              'Eq' { Test-InnoPascalScriptConstantEqual -Left $Left.Value -Right $Right.Value }
            }
          } catch {
            $null = $Path.State.Remove($Destination)
          }
        }
        { $_ -in @('Neg', 'Not', 'Inc', 'Dec', 'SetZ') } {
          $Destination = Get-InnoPascalScriptVariableKey -Operand $Instruction.Operands[0] -References $Path.References
          if (-not $Destination -or -not $Path.State.ContainsKey($Destination)) {
            if ($Destination) { $null = $Path.State.Remove($Destination) }
            break
          }
          try {
            $CurrentValue = $Path.State[$Destination]
            $Path.State[$Destination] = switch ($Code) {
              'Neg' { - $CurrentValue }
              'Not' { $CurrentValue -is [bool] ? (-not $CurrentValue) : (-bnot [long]$CurrentValue) }
              'Inc' { $CurrentValue + 1 }
              'Dec' { $CurrentValue - 1 }
              'SetZ' {
                $Condition = ConvertTo-InnoPascalScriptBooleanConstant -Value $CurrentValue
                if (-not $Condition.Resolved) { throw 'Unsupported zero comparison' }
                -not $Condition.Value
              }
            }
          } catch {
            $null = $Path.State.Remove($Destination)
          }
        }
        { $_ -in @('SetFlagNZ', 'SetFlagZ') } {
          $Operand = Get-InnoPascalScriptOperandConstant -Operand $Instruction.Operands[0] -State $Path.State -References $Path.References
          if ($Operand.Resolved) {
            $Condition = ConvertTo-InnoPascalScriptBooleanConstant -Value $Operand.Value
            $Path.JumpFlagResolved = $Condition.Resolved
            if ($Condition.Resolved) { $Path.JumpFlag = $Code -ceq 'SetFlagNZ' ? $Condition.Value : -not $Condition.Value }
          } else {
            $Path.JumpFlagResolved = $false
          }
        }
        'Jump' {
          $Target = Get-InnoPascalScriptBranchTargetIndex -Operand $Instruction.Operands[0] -InstructionIndex $InstructionIndex
          if ($Target -lt 0) {
            $TerminalPaths.Add([pscustomobject]@{ Resolved = $false; Value = $null; Reason = 'Invalid direct branch target'; Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray() })
            $PathTerminated = $true
          } else {
            $NextPosition = $Target
          }
        }
        { $_ -in @('JumpNZ', 'JumpZ') } {
          $Target = Get-InnoPascalScriptBranchTargetIndex -Operand $Instruction.Operands[0] -InstructionIndex $InstructionIndex
          $Operand = Get-InnoPascalScriptOperandConstant -Operand $Instruction.Operands[1] -State $Path.State -References $Path.References
          if ($Target -lt 0) {
            $TerminalPaths.Add([pscustomobject]@{ Resolved = $false; Value = $null; Reason = 'Invalid conditional branch target'; Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray() })
            $PathTerminated = $true
          } elseif ($Operand.Resolved) {
            $Condition = ConvertTo-InnoPascalScriptBooleanConstant -Value $Operand.Value
            if ($Condition.Resolved) {
              $ShouldJump = $Code -ceq 'JumpNZ' ? $Condition.Value : -not $Condition.Value
              if ($ShouldJump) { $NextPosition = $Target }
            } else {
              $ForkTargets = [int[]]@($Target, $NextPosition)
            }
          } else {
            $ForkTargets = [int[]]@($Target, $NextPosition)
          }
          $ForkReason = "$Code at IFPS instruction $($Path.Position)"
        }
        'JumpF' {
          $Target = Get-InnoPascalScriptBranchTargetIndex -Operand $Instruction.Operands[0] -InstructionIndex $InstructionIndex
          if ($Target -lt 0) {
            $TerminalPaths.Add([pscustomobject]@{ Resolved = $false; Value = $null; Reason = 'Invalid flag branch target'; Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray() })
            $PathTerminated = $true
          } elseif ($Path.JumpFlagResolved) {
            if ($Path.JumpFlag) { $NextPosition = $Target }
          } else {
            $ForkTargets = [int[]]@($Target, $NextPosition)
          }
          $ForkReason = "JumpF at IFPS instruction $($Path.Position)"
        }
        'Ret' {
          if ($Path.UnresolvedCallReason) {
            $TerminalPaths.Add([pscustomobject]@{ Resolved = $false; Value = $null; Reason = $Path.UnresolvedCallReason; Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray() })
          } elseif ($CheckRegistryArchitecture -and $null -eq $Function.ReturnArgument) {
            $TerminalPaths.Add([pscustomobject]@{ Resolved = $true; Value = $null; Reason = $null; Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray() })
          } elseif ($Path.State.ContainsKey($ReturnKey)) {
            $TerminalPaths.Add([pscustomobject]@{ Resolved = $true; Value = $Path.State[$ReturnKey]; Reason = $null; Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray() })
          } else {
            $TerminalPaths.Add([pscustomobject]@{ Resolved = $false; Value = $null; Reason = 'Return variable is not constant'; Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray() })
          }
          $PathTerminated = $true
        }
        'SetStackType' {
          # Historical IFPS reinitializes the selected variable with the new
          # type, so any value proven before this instruction is no longer valid.
          $Destination = Get-InnoPascalScriptVariableKey -Operand $Instruction.Operands[1]
          if ($Destination) {
            $null = $Path.State.Remove($Destination)
            $null = $Path.References.Remove($Destination)
          }
        }
        'SetPtr' {
          if (-not $CheckRegistryArchitecture) {
            $TerminalPaths.Add([pscustomobject]@{ Resolved = $false; Value = $null; Reason = 'Unsupported opcode: SetPtr'; Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray() })
            $PathTerminated = $true
            break
          }
          # UniPs cm_sp copies an existing pointer target or binds a variable's
          # address. Preserve the alias so an Out argument invalidates its target,
          # including RetVal, instead of leaving a stale constant behind.
          $Destination = Get-InnoPascalScriptVariableKey -Operand $Instruction.Operands[0]
          $Source = Get-InnoPascalScriptVariableKey -Operand $Instruction.Operands[1] -References $Path.References
          if (-not $Destination -or -not $Source -or $Destination -eq $Source) {
            $TerminalPaths.Add([pscustomobject]@{ Resolved = $false; Value = $null; Reason = 'Unsupported pointer binding'; Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray() })
            $PathTerminated = $true
          } else {
            $null = $Path.State.Remove($Destination)
            $Path.References[$Destination] = $Source
          }
        }
        { $_ -in @('Push', 'PushVar', 'PushType', 'Pop') } {
          if (-not $CheckRegistryArchitecture) { break }
          if ($Code -eq 'Pop') {
            if ($Path.Stack.Count -eq 0) {
              $PathTerminated = $true
              $TerminalPaths.Add([pscustomobject]@{ Resolved = $false; Value = $null; Reason = 'Invalid IFPS stack pop'; Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray() })
            } else {
              $Key = 'Local:{0}' -f $Path.Stack.Count
              $null = $Path.State.Remove($Key)
              $null = $Path.References.Remove($Key)
              $Path.Stack.RemoveAt($Path.Stack.Count - 1)
            }
          } elseif ($Code -eq 'PushVar') {
            # Preserve the original operand: a function writes its result through
            # this stack reference, not through a copy of the caller's variable.
            $Path.Stack.Add($Instruction.Operands[0])
          } else {
            # IFPSLib uses one-based local indexes (Var1), while Create takes
            # a zero-based stack slot. Keep the state key in decoded index units.
            $Key = 'Local:{0}' -f ($Path.Stack.Count + 1)
            $null = $Path.State.Remove($Key)
            $null = $Path.References.Remove($Key)
            if ($Code -eq 'Push') {
              $Pushed = Get-InnoPascalScriptOperandConstant -Operand $Instruction.Operands[0] -State $Path.State -References $Path.References
              if ($Pushed.Resolved) { $Path.State[$Key] = $Pushed.Value }
            }
            $Path.Stack.Add([IFPSLib.Emit.Operand]::Create([IFPSLib.Emit.LocalVariable]::Create($Path.Stack.Count)))
          }
        }
        'Nop' { }
        'Call' {
          if (-not $CheckRegistryArchitecture) {
            $PathTerminated = $true
            $TerminalPaths.Add([pscustomobject]@{ Resolved = $false; Value = $null; Reason = 'Unsupported opcode: Call'; Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray() })
            break
          }
          $Target = $Instruction.Operands[0].Immediate
          $HasReturn = $null -ne $Target.ReturnArgument
          $ArgumentCount = $Target.Arguments.Count
          if ($Path.Stack.Count -lt $ArgumentCount + [int]$HasReturn) {
            $PathTerminated = $true
            $TerminalPaths.Add([pscustomobject]@{ Resolved = $false; Value = $null; Reason = 'Invalid IFPS call stack'; Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray() })
            break
          }
          # Pascal Script pushes arguments in reverse declaration order, then
          # the result reference. RootKey is the first declared registry argument.
          $CallArguments = [System.Collections.Generic.List[object]]::new()
          for ($Index = 0; $Index -lt $ArgumentCount; $Index++) {
            $CallArguments.Add((Get-InnoPascalScriptOperandConstant -Operand $Path.Stack[$Path.Stack.Count - 1 - [int]$HasReturn - $Index] -State $Path.State -References $Path.References))
          }
          $ResultKey = $HasReturn ? (Get-InnoPascalScriptVariableKey -Operand $Path.Stack[$Path.Stack.Count - 1] -References $Path.References) : $null
          $CallResult = [pscustomobject]@{ IsResolved = $false; Value = $null }
          $FailureReason = $null
          if ($Target.GetType().FullName -ceq 'IFPSLib.Emit.ScriptFunction') {
            $CallResult = Get-InnoPascalScriptStaticReturnInfo -Function $Target -CheckRegistryArchitecture `
              -Arguments $CallArguments.ToArray() -CallDepth ($CallDepth + 1) -ExecutionBudget $ExecutionBudget
            foreach ($Failure in $CallResult.RegistryFailures) { $RegistryFailures.Add($Failure) }
            if ($CallResult.Requires64BitRegistry) { $FailureReason = 'Requires64BitRegistry' }
            elseif ($CallResult.TruncatedPathCount -gt 0) { $FailureReason = 'Direct call exceeded static-analysis bounds' }
            elseif (-not $CallResult.ExecutionCompleted) { $Path.UnresolvedCallReason = 'Direct call execution is unresolved' }
            # A callee can mutate globals or output arguments. Do not carry
            # previously proven values through those side effects.
            foreach ($Key in [string[]]@($Path.State.Keys)) {
              if ($Key.StartsWith('Global:', [StringComparison]::Ordinal)) { $null = $Path.State.Remove($Key) }
            }
          } elseif ($Target.Declaration.GetType().FullName -ceq 'IFPSLib.Emit.FDecl.Internal') {
            switch -Regex ([string]$Target.Name) {
              '^(?i:ISWIN64|IS64BITINSTALLMODE)$' { $CallResult = [pscustomobject]@{ IsResolved = $true; Value = $false } }
              '^(?i:LOG)$' { }
              '^(?i:REG(?:KEYEXISTS|VALUEEXISTS|DELETEKEYINCLUDINGSUBKEYS|DELETEKEYIFEMPTY|DELETEVALUE|GETSUBKEYNAMES|GETVALUENAMES|QUERY(?:STRING|MULTISTRING|DWORD|BINARY)VALUE|WRITE(?:STRING|EXPANDSTRING|MULTISTRING|DWORD|BINARY)VALUE))$' {
                if ($ArgumentCount -eq 0 -or -not $CallArguments[0].Resolved) {
                  $FailureReason = 'Registry RootKey is unresolved'
                  break
                }
                try {
                  # Signed Pascal integers and unsigned Cardinal constants encode
                  # the same 32-bit root. CrackCodeRootKey gives the 32-bit flag
                  # precedence and validates the predefined handle first.
                  $Root = [long]$CallArguments[0].Value
                  if ($Root -lt [int]::MinValue -or $Root -gt [uint32]::MaxValue) { throw 'Invalid RootKey width' }
                  $Root = $Root -band 0xFFFFFFFFL
                  $BaseRoot = $Root -band 0xFCFFFFFFL
                  if ($BaseRoot -ne 1 -and (($Root -band 0x80000000L) -eq 0 -or ($Root -band 0x7C000000L) -ne 0)) {
                    throw 'Invalid RootKey handle or reserved flags'
                  }
                  if (($Root -band 0x01000000L) -eq 0 -and ($Root -band 0x02000000L) -ne 0) {
                    $RegistryFailures.Add([pscustomobject][ordered]@{
                        Field = 'PascalScript'; Function = [string]$Function.Name; Offset = [uint32]$Instruction.Offset
                        Api = [string]$Target.Name; RootKeyValue = $Root; RootKeyHex = '0x{0:X8}' -f $Root
                        Architecture = 'x86'; Reason = 'CrackCodeRootKey rejects a 64-bit registry view on 32-bit Windows'
                      })
                    $FailureReason = 'Requires64BitRegistry'
                  }
                } catch { $FailureReason = 'Registry RootKey is invalid or nonnumeric' }
              }
              default { $Path.UnresolvedCallReason = 'External call execution is unresolved' }
            }
          } else { $Path.UnresolvedCallReason = 'External call execution is unresolved' }
          # An opaque call may throw or mutate state. Continue only to recover
          # conditional hazards; it must never establish a required architecture.
          if ($Path.UnresolvedCallReason) {
            foreach ($Key in [string[]]@($Path.State.Keys)) {
              if ($Key.StartsWith('Global:', [StringComparison]::Ordinal)) { $null = $Path.State.Remove($Key) }
            }
            if ($FailureReason -eq 'Requires64BitRegistry') { $FailureReason = 'Conditional64BitRegistry' }
          }
          for ($Index = 0; $Index -lt $ArgumentCount; $Index++) {
            if ([string]$Target.Arguments[$Index].ArgumentType -ne 'In') {
              $Key = Get-InnoPascalScriptVariableKey -Operand $Path.Stack[$Path.Stack.Count - 1 - [int]$HasReturn - $Index] -References $Path.References
              if ($Key) { $null = $Path.State.Remove($Key) }
            }
          }
          if ($ResultKey) {
            if ($CallResult.IsResolved) { $Path.State[$ResultKey] = $CallResult.Value }
            else { $null = $Path.State.Remove($ResultKey) }
          }
          if ($FailureReason) {
            $TerminalPaths.Add([pscustomobject]@{ Resolved = $false; Value = $null; Reason = $FailureReason; Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray() })
            $PathTerminated = $true
          }
        }
        default {
          $TerminalPaths.Add([pscustomobject]@{ Resolved = $false; Value = $null; Reason = "Unsupported opcode: $Code"; Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray() })
          $PathTerminated = $true
        }
      }

      if ($PathTerminated) { break }
      if ($null -ne $ForkTargets) {
        $Targets = [int[]]@($ForkTargets | Select-Object -Unique)
        if ($Targets.Count -gt 1 -and $Path.Depth -lt $INNO_MAX_PASCAL_SCRIPT_BRANCH_DEPTH -and
          $CreatedPathCount + $Targets.Count - 1 -le $INNO_MAX_PASCAL_SCRIPT_BRANCH_PATHS) {
          $CreatedPathCount += $Targets.Count - 1
          $ForkCount++
          $null = $BranchPredicates.Add($ForkReason)
          foreach ($Target in $Targets) {
            $Predicates = [System.Collections.Generic.List[string]]::new()
            $Predicates.AddRange([string[]]$Path.Predicates.ToArray())
            $Predicates.Add("$ForkReason -> $Target")
            $Queue.Enqueue([pscustomobject]@{
                Position = $Target; Steps = $Path.Steps; Depth = $Path.Depth + 1
                State = Copy-InnoPascalScriptConstantState -State $Path.State
                JumpFlagResolved = $Path.JumpFlagResolved; JumpFlag = $Path.JumpFlag; Predicates = $Predicates
                Stack = [System.Collections.Generic.List[object]]::new($Path.Stack)
                References = [Collections.Generic.Dictionary[string, string]]::new($Path.References, [StringComparer]::Ordinal)
                UnresolvedCallReason = $Path.UnresolvedCallReason
              })
          }
        } else {
          $TerminalPaths.Add([pscustomobject]@{
              Resolved = $false; Value = $null; Reason = 'Branch exploration reached the configured path or depth limit'
              Truncated = $true; Predicates = [string[]]$Path.Predicates.ToArray()
            })
        }
        $PathTerminated = $true
        break
      }
      $Path.Position = $NextPosition
    }

    if (-not $PathTerminated) {
      $TerminalPaths.Add([pscustomobject]@{
          Resolved = $Path.State.ContainsKey($ReturnKey); Value = $Path.State.ContainsKey($ReturnKey) ? $Path.State[$ReturnKey] : $null
          Reason = $CheckRegistryArchitecture ? 'Function did not return' : ($Path.State.ContainsKey($ReturnKey) ? $null : 'Return variable is not constant')
          Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray()
        })
    }
  }

  $ResolvedPaths = @($TerminalPaths | Where-Object Resolved)
  $TruncatedPathCount = @($TerminalPaths | Where-Object Truncated).Count
  $IsResolved = $TerminalPaths.Count -gt 0 -and $ResolvedPaths.Count -eq $TerminalPaths.Count
  $Value = $IsResolved ? $ResolvedPaths[0].Value : $null
  if ($IsResolved) {
    foreach ($ResolvedPath in $ResolvedPaths | Select-Object -Skip 1) {
      if (-not (Test-InnoPascalScriptConstantEqual -Left $Value -Right $ResolvedPath.Value)) {
        $IsResolved = $false
        $Value = $null
        break
      }
    }
  }
  $Reason = if ($IsResolved) {
    $null
  } elseif ($TruncatedPathCount -gt 0) {
    'One or more branch paths exceeded the static-analysis bounds'
  } elseif ($ResolvedPaths.Count -eq $TerminalPaths.Count -and $ResolvedPaths.Count -gt 1) {
    'Branch paths return different constants'
  } else {
    [string](@($TerminalPaths | Where-Object { -not $_.Resolved } | Select-Object -First 1).Reason)
  }
  return [pscustomobject]@{
    IsResolved = $IsResolved; Value = $Value; Reason = $Reason; ExploredPathCount = $CreatedPathCount
    ForkCount = $ForkCount; TruncatedPathCount = $TruncatedPathCount
    BranchPredicates = [string[]]@($BranchPredicates | Sort-Object)
    ReturnValues = [object[]]@($ResolvedPaths.Value)
    RegistryFailures = [object[]]$RegistryFailures.ToArray()
    Requires64BitRegistry = $TerminalPaths.Count -gt 0 -and @($TerminalPaths | Where-Object Reason -NE 'Requires64BitRegistry').Count -eq 0
    ExecutionCompleted = $TerminalPaths.Count -gt 0 -and @($TerminalPaths | Where-Object { $_.Truncated -or $_.Reason -notin @($null, 'Return variable is not constant') }).Count -eq 0
  }
}

function Get-InnoPascalScriptArchitectureRequirement {
  <#
  .SYNOPSIS
    Detect proven and conditional x86 pre-install failures from 64-bit registry roots.
  .DESCRIPTION
    Runs only a bounded abstract interpretation of IFPS startup callbacks. Unknown
    state forks; opaque calls retain later failures as conditional evidence. Exception
    flow and exhausted bounds cannot exclude an architecture. Unreachable helpers
    and uninstall callbacks are not entry points. PrepareToInstall is inspected as
    well as initialization because migration code can fail before file copying.
  .PARAMETER Bytes
    Bounded decoded IFPS bytecode, not the complete installer. Registry-free programs
    retain the inexpensive header-only path without loading the managed decoder.
  .PARAMETER Script
    Already parsed IFPSLib program; caller retains ownership. Avoids decoding twice
    when detailed Pascal Script evidence has already been requested.
  .OUTPUTS
    Requires64BitWindows, UnsupportedArchitectures, proven Evidence, conditional
    evidence, and per-entry-point bounded analysis outcomes. No host effects occur.
  #>
  [OutputType([pscustomobject])]
  [CmdletBinding(DefaultParameterSetName = 'Bytes')]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Bytes')][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory, ParameterSetName = 'Script')][object]$Script
  )

  $Evidence = [Collections.Generic.List[object]]::new()
  $ConditionalEvidence = [Collections.Generic.List[object]]::new()
  $Outcomes = [Collections.Generic.List[object]]::new()
  $Status = 'NoRegistryImports'
  if ($PSCmdlet.ParameterSetName -eq 'Bytes') {
    $Header = Read-InnoPascalScriptHeader -Bytes $Bytes
    if (-not $Header.Present) { $Status = 'NotPresent' }
    else {
      # Import names are byte strings in the decoded IFPS program. This is only
      # a cheap negative filter; positive identification uses typed declarations.
      foreach ($Prefix in 'REG', 'Reg', 'reg') {
        if (@(Find-BinaryPattern -Bytes $Bytes -Pattern ([Text.Encoding]::ASCII.GetBytes($Prefix)) -Maximum 1).Count) {
          Import-InnoPascalScriptDependency
          $Script = [IFPSLib.Script]::Load($Bytes)
          break
        }
      }
    }
  }
  if ($null -ne $Script) {
    $HasRegistryImport = $false
    foreach ($Function in $Script.Functions) {
      if ($Function.GetType().FullName -ceq 'IFPSLib.Emit.ExternalFunction' -and
        $Function.Declaration.GetType().FullName -ceq 'IFPSLib.Emit.FDecl.Internal' -and $Function.Name -match '^(?i:REG)') {
        $HasRegistryImport = $true
        break
      }
    }
    if ($HasRegistryImport) {
      $Status = 'Analyzed'
      $Budget = [pscustomobject]@{ Remaining = $INNO_MAX_PASCAL_SCRIPT_STARTUP_INSTRUCTIONS }
      $EarlierCallbackUnresolved = $false
      $Roots = [Collections.Generic.List[object]]::new()
      if ($null -ne $Script.EntryPoint) { $Roots.Add($Script.EntryPoint) }
      foreach ($Name in 'INITIALIZESETUP', 'INITIALIZEWIZARD', 'PREPARETOINSTALL') {
        foreach ($Function in $Script.Functions) {
          if ($Function.Exported -and $Function.Name -ieq $Name -and -not $Roots.Contains($Function)) { $Roots.Add($Function) }
        }
      }
      foreach ($Function in $Roots) {
        # Setup.WizardForm supplies False through the NeedsRestart Out parameter.
        $Arguments = $Function.Name -ieq 'PREPARETOINSTALL' ? @([pscustomobject]@{ Resolved = $true; Value = $false }) : @()
        $Result = Get-InnoPascalScriptStaticReturnInfo -Function $Function -CheckRegistryArchitecture -Arguments $Arguments -ExecutionBudget $Budget
        $Outcomes.Add([pscustomobject]@{
            EntryPoint = [string]$Function.Name; ExecutionCompleted = $Result.ExecutionCompleted
            Requires64BitRegistry = $Result.Requires64BitRegistry; Reason = $Result.Reason
            ExploredPathCount = $Result.ExploredPathCount; TruncatedPathCount = $Result.TruncatedPathCount
          })
        # Every possible path must fail, and earlier startup callbacks must have
        # completed. Otherwise a failure is conditional evidence, not admission policy.
        $Proven = $Result.Requires64BitRegistry -and -not $EarlierCallbackUnresolved
        $Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($Failure in $Result.RegistryFailures) {
          $Key = '{0}:{1}:{2}' -f $Failure.Function, $Failure.Offset, $Failure.RootKeyValue
          if (-not $Seen.Add($Key)) { continue }
          $Record = [pscustomobject][ordered]@{
            Field = $Failure.Field; EntryPoint = [string]$Function.Name; Function = $Failure.Function
            Offset = $Failure.Offset; Api = $Failure.Api; RootKeyValue = $Failure.RootKeyValue
            RootKeyHex = $Failure.RootKeyHex; Architecture = 'x86'; Reason = $Failure.Reason
            Conditional = -not $Proven
          }
          if ($Proven) { $Evidence.Add($Record) } else { $ConditionalEvidence.Add($Record) }
        }
        if ($Proven) { break }
        if (-not $Result.ExecutionCompleted -or ($Function.Name -ieq 'INITIALIZESETUP' -and -not $Result.IsResolved)) {
          $EarlierCallbackUnresolved = $true
        }
        if ($Function.Name -ieq 'INITIALIZESETUP' -and $Result.IsResolved -and $Result.Value -eq $false) { break }
      }
    }
  }
  return [pscustomobject][ordered]@{
    AnalysisStatus = $Status; Requires64BitWindows = $Evidence.Count -gt 0
    UnsupportedArchitectures = $Evidence.Count -gt 0 ? [string[]]@('x86') : [string[]]@()
    Evidence = [object[]]$Evidence.ToArray(); ConditionalEvidence = [object[]]$ConditionalEvidence.ToArray()
    EntryPoints = [object[]]$Outcomes.ToArray()
  }
}

function Get-InnoPascalScriptEffectCategory {
  <#
  .SYNOPSIS
    Classify manifest-relevant Inno runtime calls without executing them.
  .PARAMETER Target
    IFPS function or host-call name.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Target)

  switch -Regex ($Target.ToUpperInvariant()) {
    '^REG(?:WRITE|DELETE|CREATE)' { return 'RegistryWrite' }
    '^REG(?:QUERY|KEYEXISTS|VALUEEXISTS)' { return 'RegistryRead' }
    '^(?:EXEC|SHELLEXEC|EXECASORIGINALUSER|SHELLEXECASORIGINALUSER)' { return 'ProcessLaunch' }
    '^(?:WIZARDSILENT|SUPPRESSIBLEMSGBOX|MSGBOX)' { return 'SilentInteraction' }
    '^(?:ISADMIN|ISADMININSTALLMODE|ISPOWERUSERLOGGEDON|GETPREVIOUSPRIVILEGES)' { return 'ScopeOrElevation' }
    '^(?:RESTARTREPLACE|FORCERESTART|NEEDSRESTART)' { return 'Restart' }
    '^(?:DOWNLOADTEMPORARYFILE|DOWNLOADTEMPORARYFILESIZE|ISSIGVERIFY)' { return 'NetworkOrSignature' }
    '^(?:DELAYDELETEFILE|DELETEFILE|DELTREE|RENAMEFILE|FILECOPY|FILESEARCH)' { return 'FileSystemWrite' }
    default { return $null }
  }
}

function Get-InnoPascalScriptReturnMap {
  <#
  .SYNOPSIS
    Index statically proven primitive Pascal Script returns by function name.
  .PARAMETER PascalScriptInfo
    Detailed result from ConvertTo-InnoPascalScriptInfo.
  #>
  [OutputType([System.Collections.IDictionary])]
  param ([AllowNull()][pscustomobject]$PascalScriptInfo)

  $Map = [ordered]@{}
  if ($null -eq $PascalScriptInfo -or $null -eq $PascalScriptInfo.PSObject.Properties['StaticReturnValues']) {
    return $Map
  }
  foreach ($Return in @($PascalScriptInfo.StaticReturnValues)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$Return.Function)) {
      $Value = $Return.Value
      if ([string]$Return.ReturnType -ieq 'BOOLEAN') {
        $Boolean = ConvertTo-InnoPascalScriptBooleanConstant -Value $Value
        if ($Boolean.Resolved) { $Value = $Boolean.Value }
      }
      $Map[[string]$Return.Function] = $Value
    }
  }
  return $Map
}

function Get-InnoPascalScriptConstantMap {
  <#
  .SYNOPSIS
    Map header {code:Function} constants to statically proven string returns.
  .DESCRIPTION
    Only functions whose complete bounded control-flow graph resolves to one
    constant string return are accepted. The map is limited to constants actually
    present in the supplied header strings, including parameterized spellings.
  .PARAMETER PascalScriptInfo
    Detailed result from ConvertTo-InnoPascalScriptInfo.
  .PARAMETER Values
    Serialized setup-header values that may contain Pascal Script constants.
  #>
  [OutputType([System.Collections.IDictionary])]
  param (
    [AllowNull()][pscustomobject]$PascalScriptInfo,
    [Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Values
  )

  $Map = [ordered]@{}
  if ($null -eq $PascalScriptInfo -or
    $null -eq $PascalScriptInfo.PSObject.Properties['StaticReturnValues']) {
    return $Map
  }

  $Returns = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Return in (Get-InnoPascalScriptReturnMap -PascalScriptInfo $PascalScriptInfo).GetEnumerator()) {
    if ($Return.Value -is [string]) { $Returns[[string]$Return.Key] = [string]$Return.Value }
  }
  if ($Returns.Count -eq 0) { return $Map }

  foreach ($Value in $Values) {
    if ([string]::IsNullOrEmpty($Value)) { continue }
    foreach ($Match in [regex]::Matches($Value, '\{code:(?<Function>[^|}]+)(?:\|[^}]*)?\}', 'IgnoreCase,CultureInvariant')) {
      $FunctionName = $Match.Groups['Function'].Value
      if ($Returns.ContainsKey($FunctionName)) {
        # Get-InnoStaticStringInfo expects map keys without the surrounding braces.
        $Map[$Match.Value.Substring(1, $Match.Value.Length - 2)] = $Returns[$FunctionName]
      }
    }
  }
  return $Map
}

function ConvertTo-InnoPascalScriptInfo {
  <#
  .SYNOPSIS
    Parse bounded IFPS bytecode into JSON-safe structural evidence.
  .PARAMETER Bytes
    Raw CompiledCodeText bytes. The caller retains ownership of the array.
  .PARAMETER IncludeDisassembly
    Include IFPSLib's textual instruction disassembly in the result.
  .PARAMETER MaximumDisassemblyCharacters
    Maximum characters retained from the optional disassembly.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
    [switch]$IncludeDisassembly,
    [ValidateRange(1024, 16777216)][int]$MaximumDisassemblyCharacters = $INNO_DEFAULT_MAX_DISASSEMBLY_CHARACTERS
  )

  $Header = Read-InnoPascalScriptHeader -Bytes $Bytes
  if (-not $Header.Present) {
    return [pscustomobject][ordered]@{
      Present = $false; AnalysisStatus = 'Absent'; ByteLength = 0; FileVersion = $null; EntryPoint = $null
      TypeCount = 0; FunctionCount = 0; ScriptFunctionCount = 0; ExternalFunctionCount = 0
      GlobalVariableCount = 0; InstructionCount = 0; IndirectCallCount = 0
      UnknownOpcodeCount = 0; UsesExtendedType = $false
      StaticReturnExploredPathCount = 0; StaticReturnForkCount = 0; StaticReturnTruncatedPathCount = 0
      ScriptFunctions = [string[]]@(); ExportedFunctions = [string[]]@()
      ExternalFunctions = [pscustomobject[]]@(); DllImports = [pscustomobject[]]@()
      Types = [pscustomobject[]]@(); GlobalVariables = [pscustomobject[]]@()
      Functions = [pscustomobject[]]@(); StringConstants = [string[]]@()
      RuntimeEffects = [pscustomobject[]]@(); StaticReturnValues = [pscustomobject[]]@()
      Disassembly = $null; DisassemblyTruncated = $false; Diagnostics = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]@()) -Source 'Inno' -Kind Incomplete -Areas Metadata)
      Parser = 'IFPSTools.NET IFPSLib'; ParserVersion = $null
    }
  }
  Import-InnoPascalScriptDependency
  $PascalScript = [IFPSLib.Script]::Load($Bytes)
  $ScriptFunctions = [Collections.Generic.List[string]]::new()
  $ExportedFunctions = [Collections.Generic.List[string]]::new()
  $ExternalFunctions = [Collections.Generic.List[pscustomobject]]::new()
  $DllImports = [Collections.Generic.List[pscustomobject]]::new()
  $TypeDetails = [Collections.Generic.List[pscustomobject]]::new()
  $GlobalDetails = [Collections.Generic.List[pscustomobject]]::new()
  $FunctionDetails = [Collections.Generic.List[pscustomobject]]::new()
  $RuntimeEffects = [Collections.Generic.List[pscustomobject]]::new()
  $StaticReturnValues = [Collections.Generic.List[pscustomobject]]::new()
  $StringConstants = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $InstructionCount = 0
  $IndirectCallCount = 0
  $UnknownOpcodeCount = 0
  $StaticReturnExploredPathCount = 0
  $StaticReturnForkCount = 0
  $StaticReturnTruncatedPathCount = 0

  for ($TypeIndex = 0; $TypeIndex -lt $PascalScript.Types.Count; $TypeIndex++) {
    $Type = $PascalScript.Types[$TypeIndex]
    $TypeDetails.Add([pscustomobject][ordered]@{
        Index       = $TypeIndex
        Name        = [string]$Type.Name
        BaseType    = [string]$Type.BaseType
        Exported    = [bool]$Type.Exported
        Declaration = [string]$Type.ToString()
        Attributes  = [string[]]@($Type.Attributes | ForEach-Object { [string]$_.ToString() })
      })
  }
  for ($GlobalIndex = 0; $GlobalIndex -lt $PascalScript.GlobalVariables.Count; $GlobalIndex++) {
    $Global = $PascalScript.GlobalVariables[$GlobalIndex]
    $GlobalDetails.Add([pscustomobject][ordered]@{
        Index    = $GlobalIndex
        Name     = [string]$Global.Name
        Type     = $null -ne $Global.Type ? [string]$Global.Type.Name : $null
        Exported = [bool]$Global.Exported
      })
  }

  for ($FunctionIndex = 0; $FunctionIndex -lt $PascalScript.Functions.Count; $FunctionIndex++) {
    $Function = $PascalScript.Functions[$FunctionIndex]
    $FunctionType = $Function.GetType().FullName
    $FunctionKind = 'Unknown'
    $FunctionInstructionCount = 0
    $Calls = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $FunctionConstants = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $StaticReturnInfo = [pscustomobject]@{
      IsResolved = $false; Value = $null; Reason = 'External function'; ExploredPathCount = 0
      ForkCount = 0; TruncatedPathCount = 0; BranchPredicates = [string[]]@(); ReturnValues = [object[]]@()
    }
    if ($FunctionType -ceq 'IFPSLib.Emit.ScriptFunction') {
      $FunctionKind = 'Script'
      $ScriptFunctions.Add([string]$Function.Name)
      $FunctionInstructionCount = $Function.Instructions.Count
      $InstructionCount += $FunctionInstructionCount
      $StaticReturnInfo = Get-InnoPascalScriptStaticReturnInfo -Function $Function
      $StaticReturnExploredPathCount += $StaticReturnInfo.ExploredPathCount
      $StaticReturnForkCount += $StaticReturnInfo.ForkCount
      $StaticReturnTruncatedPathCount += $StaticReturnInfo.TruncatedPathCount
      if ($StaticReturnInfo.IsResolved) {
        $StaticReturnValues.Add([pscustomobject]@{
            Function = [string]$Function.Name; ReturnType = [string]$Function.ReturnArgument.Name; Value = $StaticReturnInfo.Value
            ExploredPathCount = $StaticReturnInfo.ExploredPathCount; ForkCount = $StaticReturnInfo.ForkCount
            BranchPredicates = $StaticReturnInfo.BranchPredicates
          })
      }

      foreach ($Instruction in $Function.Instructions) {
        $Code = [string]$Instruction.OpCode.Code
        if ($Code.StartsWith('UNKNOWN', [StringComparison]::Ordinal)) { $UnknownOpcodeCount++ }
        if ($Code -ceq 'CallVar') { $IndirectCallCount++ }
        if ($Code -ceq 'Call' -and $Instruction.Operands.Count -gt 0) {
          $Target = $Instruction.Operands[0].Immediate
          $TargetName = $null -ne $Target ? [string]$Target.Name : $null
          if (-not [string]::IsNullOrWhiteSpace($TargetName)) {
            $null = $Calls.Add($TargetName)
            $Category = Get-InnoPascalScriptEffectCategory -Target $TargetName
            if ($Category) {
              $RuntimeEffects.Add([pscustomobject][ordered]@{
                  Function = [string]$Function.Name
                  Offset   = [uint32]$Instruction.Offset
                  Target   = $TargetName
                  Category = $Category
                })
            }
          }
        }
        foreach ($Operand in $Instruction.Operands) {
          if ([string]$Operand.Type -ceq 'Immediate' -and $Operand.Immediate -is [string]) {
            $null = $FunctionConstants.Add([string]$Operand.Immediate)
            $null = $StringConstants.Add([string]$Operand.Immediate)
          }
        }
      }
    } elseif ($FunctionType -ceq 'IFPSLib.Emit.ExternalFunction') {
      $FunctionKind = 'External'
      $Declaration = $Function.Declaration
      $DeclarationType = $Declaration.GetType().FullName
      $Kind = switch ($DeclarationType) {
        'IFPSLib.Emit.FDecl.DLL' { 'DLL' }
        'IFPSLib.Emit.FDecl.Class' { 'Class' }
        'IFPSLib.Emit.FDecl.COM' { 'COM' }
        'IFPSLib.Emit.FDecl.Internal' { 'Internal' }
        default { 'Unknown' }
      }
      $External = [pscustomobject][ordered]@{
        Name                      = [string]$Function.Name
        Kind                      = $Kind
        Exported                  = [bool]$Function.Exported
        Declaration               = [string]$Declaration.ToString()
        DllName                   = $Kind -eq 'DLL' ? [string]$Declaration.DllName : $null
        ProcedureName             = $Kind -eq 'DLL' ? [string]$Declaration.ProcedureName : $null
        CallingConvention         = $Kind -in @('DLL', 'Class', 'COM') ? [string]$Declaration.CallingConvention : $null
        DelayLoad                 = $Kind -eq 'DLL' ? [bool]$Declaration.DelayLoad : $false
        LoadWithAlteredSearchPath = $Kind -eq 'DLL' ? [bool]$Declaration.LoadWithAlteredSearchPath : $false
        ClassName                 = $Kind -eq 'Class' ? [string]$Declaration.ClassName : $null
        MemberName                = $Kind -eq 'Class' ? [string]$Declaration.FunctionName : $null
        VTableIndex               = $Kind -eq 'COM' ? [uint32]$Declaration.VTableIndex : $null
      }
      $ExternalFunctions.Add($External)
      if ($Kind -eq 'DLL') { $DllImports.Add($External) }
    }
    if ($Function.Exported) { $ExportedFunctions.Add([string]$Function.Name) }

    $ArgumentDetails = [Collections.Generic.List[pscustomobject]]::new()
    if ($null -ne $Function.Arguments) {
      for ($ArgumentIndex = 0; $ArgumentIndex -lt $Function.Arguments.Count; $ArgumentIndex++) {
        $Argument = $Function.Arguments[$ArgumentIndex]
        $ArgumentDetails.Add([pscustomobject][ordered]@{
            Index     = $ArgumentIndex
            Name      = [string]$Argument.Name
            Direction = [string]$Argument.ArgumentType
            Type      = $null -ne $Argument.Type ? [string]$Argument.Type.Name : $null
          })
      }
    }
    $FunctionDetails.Add([pscustomobject][ordered]@{
        Index                          = $FunctionIndex
        Name                           = [string]$Function.Name
        Kind                           = $FunctionKind
        Exported                       = [bool]$Function.Exported
        ReturnType                     = $null -ne $Function.ReturnArgument ? [string]$Function.ReturnArgument.Name : $null
        Arguments                      = [pscustomobject[]]$ArgumentDetails.ToArray()
        Attributes                     = [string[]]@($Function.Attributes | ForEach-Object { [string]$_.ToString() })
        InstructionCount               = $FunctionInstructionCount
        Calls                          = [string[]]@($Calls)
        StringConstants                = [string[]]@($FunctionConstants)
        StaticReturnResolved           = [bool]$StaticReturnInfo.IsResolved
        StaticReturnValue              = $StaticReturnInfo.Value
        StaticReturnReason             = [string]$StaticReturnInfo.Reason
        StaticReturnExploredPathCount  = [int]$StaticReturnInfo.ExploredPathCount
        StaticReturnForkCount          = [int]$StaticReturnInfo.ForkCount
        StaticReturnTruncatedPathCount = [int]$StaticReturnInfo.TruncatedPathCount
        StaticReturnBranchPredicates   = [string[]]$StaticReturnInfo.BranchPredicates
      })
  }

  $UsesExtendedType = @($PascalScript.Types | Where-Object { [string]$_.BaseType -ceq 'Extended' }).Count -gt 0
  $Warnings = [Collections.Generic.List[object]]::new()
  if ($UsesExtendedType) {
    $Warnings.Add('The IFPS program uses Extended values. IFPSLib decodes them as x86 80-bit values; scripts compiled for a non-x86 runtime may use a 64-bit representation.')
  }
  if ($IndirectCallCount -gt 0) {
    $Warnings.Add("The IFPS program contains $IndirectCallCount indirect function call(s); their targets and side effects cannot be resolved statically.")
  }
  if ($UnknownOpcodeCount -gt 0) {
    $Warnings.Add("IFPSLib decoded $UnknownOpcodeCount unknown opcode(s); affected control flow remains unresolved.")
  }

  $Disassembly = $null
  $DisassemblyTruncated = $false
  if ($IncludeDisassembly) {
    if ($Bytes.Length -gt $INNO_MAX_PASCAL_SCRIPT_DISASSEMBLY_INPUT_SIZE) {
      throw "Text disassembly is limited to IFPS inputs no larger than $INNO_MAX_PASCAL_SCRIPT_DISASSEMBLY_INPUT_SIZE bytes."
    }
    $Disassembly = $PascalScript.Disassemble()
    if ($Disassembly.Length -gt $MaximumDisassemblyCharacters) {
      $Disassembly = $Disassembly.Substring(0, $MaximumDisassemblyCharacters)
      $DisassemblyTruncated = $true
      $Warnings.Add("The IFPS disassembly was truncated at $MaximumDisassemblyCharacters characters.")
    }
  }

  return [pscustomobject][ordered]@{
    Present                        = $true
    AnalysisStatus                 = 'Analyzed'
    ByteLength                     = $Bytes.Length
    FileVersion                    = $PascalScript.FileVersion
    EntryPoint                     = $null -ne $PascalScript.EntryPoint ? [string]$PascalScript.EntryPoint.Name : $null
    TypeCount                      = $PascalScript.Types.Count
    FunctionCount                  = $PascalScript.Functions.Count
    ScriptFunctionCount            = $ScriptFunctions.Count
    ExternalFunctionCount          = $ExternalFunctions.Count
    GlobalVariableCount            = $PascalScript.GlobalVariables.Count
    InstructionCount               = $InstructionCount
    IndirectCallCount              = $IndirectCallCount
    UnknownOpcodeCount             = $UnknownOpcodeCount
    UsesExtendedType               = $UsesExtendedType
    StaticReturnExploredPathCount  = $StaticReturnExploredPathCount
    StaticReturnForkCount          = $StaticReturnForkCount
    StaticReturnTruncatedPathCount = $StaticReturnTruncatedPathCount
    ScriptFunctions                = [string[]]$ScriptFunctions.ToArray()
    ExportedFunctions              = [string[]]$ExportedFunctions.ToArray()
    ExternalFunctions              = [pscustomobject[]]$ExternalFunctions.ToArray()
    DllImports                     = [pscustomobject[]]$DllImports.ToArray()
    Types                          = [pscustomobject[]]$TypeDetails.ToArray()
    GlobalVariables                = [pscustomobject[]]$GlobalDetails.ToArray()
    Functions                      = [pscustomobject[]]$FunctionDetails.ToArray()
    StringConstants                = [string[]]@($StringConstants)
    RuntimeEffects                 = [pscustomobject[]]$RuntimeEffects.ToArray()
    ArchitectureRequirement        = Get-InnoPascalScriptArchitectureRequirement -Script $PascalScript
    StaticReturnValues             = [pscustomobject[]]$StaticReturnValues.ToArray()
    Disassembly                    = $Disassembly
    DisassemblyTruncated           = $DisassemblyTruncated
    Diagnostics                    = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings.ToArray()) -Source 'Inno' -Kind Incomplete -Areas Metadata)
    Parser                         = 'IFPSTools.NET IFPSLib'
    ParserVersion                  = [IFPSLib.Script].Assembly.GetName().Version.ToString()
  }
}

Export-ModuleMember -Function Import-InnoPascalScriptDependency, Read-InnoPascalScriptHeader, Get-InnoPascalScriptVariableKey, Get-InnoPascalScriptOperandConstant, Copy-InnoPascalScriptConstantState, ConvertTo-InnoPascalScriptBooleanConstant, Test-InnoPascalScriptConstantEqual, Get-InnoPascalScriptBranchTargetIndex, Get-InnoPascalScriptStaticReturnInfo, Get-InnoPascalScriptArchitectureRequirement, Get-InnoPascalScriptEffectCategory, Get-InnoPascalScriptReturnMap, Get-InnoPascalScriptConstantMap, ConvertTo-InnoPascalScriptInfo
