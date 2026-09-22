# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# Internal Inno implementation. See Inno.psm1 for format sources and the binary layout.
# Parsed operation contexts are passed explicitly; no caller-owned stream is retained globally.

# Inno Script layer. Internal modules are imported locally; public commands stay in the facade.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$INNO_MAX_COMPILED_CODE_SIZE = 16777216

$INNO_MAX_PASCAL_SCRIPT_ENTITY_COUNT = 262144

$INNO_MAX_PASCAL_SCRIPT_DISASSEMBLY_INPUT_SIZE = 1048576

$INNO_DEFAULT_MAX_DISASSEMBLY_CHARACTERS = 4194304

$INNO_MAX_PASCAL_SCRIPT_BRANCH_PATHS = 16

$INNO_MAX_PASCAL_SCRIPT_BRANCH_DEPTH = 8

$INNO_MAX_PASCAL_SCRIPT_WATCHDOG_MULTIPLIER = 4

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
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][object]$Operand)

  if ([string]$Operand.Type -cne 'Variable') { return $null }
  return '{0}:{1}' -f $Operand.Variable.VarType, $Operand.Variable.Index
}

function Get-InnoPascalScriptOperandConstant {
  <#
  .SYNOPSIS
    Resolve a JSON-safe immediate or a previously proven variable constant.
  .PARAMETER Operand
    IFPSLib operand to inspect.
  .PARAMETER State
    Path-local variable state keyed by variable kind and index.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][object]$Operand,
    [Parameter(Mandatory)][System.Collections.Generic.Dictionary[string, object]]$State
  )

  if ([string]$Operand.Type -ceq 'Variable') {
    $Key = Get-InnoPascalScriptVariableKey -Operand $Operand
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
    Calls, exception flow, pointers, indexed values, and unknown opcodes make only
    the affected path unresolved. A value is returned only when every terminal
    path completes within the configured bounds and agrees on the same constant.
  .PARAMETER Function
    IFPSLib script function to inspect.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][object]$Function)

  if ($Function.GetType().FullName -cne 'IFPSLib.Emit.ScriptFunction' -or $null -eq $Function.ReturnArgument) {
    return [pscustomobject]@{
      IsResolved = $false; Value = $null; Reason = 'No script return value'; ExploredPathCount = 0
      ForkCount = 0; TruncatedPathCount = 0; BranchPredicates = [string[]]@(); ReturnValues = [object[]]@()
    }
  }

  $InstructionCount = $Function.Instructions.Count
  if ($InstructionCount -eq 0) {
    return [pscustomobject]@{
      IsResolved = $false; Value = $null; Reason = 'Return variable is not constant'; ExploredPathCount = 1
      ForkCount = 0; TruncatedPathCount = 0; BranchPredicates = [string[]]@(); ReturnValues = [object[]]@()
    }
  }
  $InstructionIndex = [System.Collections.Generic.Dictionary[object, int]]::new([System.Collections.Generic.ReferenceEqualityComparer]::Instance)
  for ($Index = 0; $Index -lt $InstructionCount; $Index++) { $InstructionIndex[$Function.Instructions[$Index]] = $Index }
  $PathWatchdog = [Math]::Max($InstructionCount * $INNO_MAX_PASCAL_SCRIPT_WATCHDOG_MULTIPLIER, 1)
  $AggregateWatchdog = $PathWatchdog * $INNO_MAX_PASCAL_SCRIPT_BRANCH_PATHS
  $ReturnKey = 'Argument:0'
  $Queue = [System.Collections.Generic.Queue[object]]::new()
  $InitialState = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
  $Queue.Enqueue([pscustomobject]@{
      Position = 0; Steps = 0; Depth = 0; State = $InitialState; JumpFlagResolved = $false; JumpFlag = $false
      Predicates = [System.Collections.Generic.List[string]]::new()
    })
  $TerminalPaths = [System.Collections.Generic.List[object]]::new()
  $BranchPredicates = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $CreatedPathCount = 1
  $ForkCount = 0
  $TotalSteps = 0

  while ($Queue.Count -gt 0) {
    $Path = $Queue.Dequeue()
    $PathTerminated = $false
    while ($Path.Position -ge 0 -and $Path.Position -lt $InstructionCount) {
      $Instruction = $Function.Instructions[$Path.Position]
      $Code = [string]$Instruction.OpCode.Code
      $Path.Steps++
      $TotalSteps++
      if ($Path.Steps -gt $PathWatchdog -or $TotalSteps -gt $AggregateWatchdog) {
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
          $Destination = Get-InnoPascalScriptVariableKey -Operand $Instruction.Operands[0]
          if (-not $Destination) {
            $TerminalPaths.Add([pscustomobject]@{ Resolved = $false; Value = $null; Reason = 'Indirect assignment'; Truncated = $false; Predicates = [string[]]$Path.Predicates.ToArray() })
            $PathTerminated = $true
            break
          }
          $Source = Get-InnoPascalScriptOperandConstant -Operand $Instruction.Operands[1] -State $Path.State
          if ($Source.Resolved) { $Path.State[$Destination] = $Source.Value } else { $null = $Path.State.Remove($Destination) }
        }
        { $_ -in @('Add', 'Sub', 'Mul', 'Div', 'Mod', 'Shl', 'Shr', 'And', 'Or', 'Xor') } {
          $Destination = Get-InnoPascalScriptVariableKey -Operand $Instruction.Operands[0]
          $Right = Get-InnoPascalScriptOperandConstant -Operand $Instruction.Operands[1] -State $Path.State
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
          $Destination = Get-InnoPascalScriptVariableKey -Operand $Instruction.Operands[0]
          $Left = Get-InnoPascalScriptOperandConstant -Operand $Instruction.Operands[1] -State $Path.State
          $Right = Get-InnoPascalScriptOperandConstant -Operand $Instruction.Operands[2] -State $Path.State
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
          $Destination = Get-InnoPascalScriptVariableKey -Operand $Instruction.Operands[0]
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
          $Operand = Get-InnoPascalScriptOperandConstant -Operand $Instruction.Operands[0] -State $Path.State
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
          $Operand = Get-InnoPascalScriptOperandConstant -Operand $Instruction.Operands[1] -State $Path.State
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
          if ($Path.State.ContainsKey($ReturnKey)) {
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
          if ($Destination) { $null = $Path.State.Remove($Destination) }
        }
        { $_ -in @('Push', 'PushVar', 'PushType', 'Pop', 'Nop') } { }
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
          Reason = $Path.State.ContainsKey($ReturnKey) ? $null : 'Return variable is not constant'
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
    StaticReturnValues             = [pscustomobject[]]$StaticReturnValues.ToArray()
    Disassembly                    = $Disassembly
    DisassemblyTruncated           = $DisassemblyTruncated
    Diagnostics                    = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings.ToArray()) -Source 'Inno' -Kind Incomplete -Areas Metadata)
    Parser                         = 'IFPSTools.NET IFPSLib'
    ParserVersion                  = [IFPSLib.Script].Assembly.GetName().Version.ToString()
  }
}

Export-ModuleMember -Function Import-InnoPascalScriptDependency, Read-InnoPascalScriptHeader, Get-InnoPascalScriptVariableKey, Get-InnoPascalScriptOperandConstant, Copy-InnoPascalScriptConstantState, ConvertTo-InnoPascalScriptBooleanConstant, Test-InnoPascalScriptConstantEqual, Get-InnoPascalScriptBranchTargetIndex, Get-InnoPascalScriptStaticReturnInfo, Get-InnoPascalScriptEffectCategory, Get-InnoPascalScriptReturnMap, Get-InnoPascalScriptConstantMap, ConvertTo-InnoPascalScriptInfo
