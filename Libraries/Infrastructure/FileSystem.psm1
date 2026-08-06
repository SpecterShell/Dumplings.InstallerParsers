# SPDX-License-Identifier: MIT

function Resolve-InstallerFileSystemPath {
  <#
  .SYNOPSIS
    Resolve a filesystem path against PowerShell's current provider location
  .PARAMETER Path
    Existing or prospective filesystem path to resolve.
  .PARAMETER AllowNonexistent
    Allow the final path component to be absent, as required for extraction destinations.
  .PARAMETER PathType
    Optional existing-item type constraint.
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [switch]$AllowNonexistent,
    [ValidateSet('Any', 'Leaf', 'Container')][string]$PathType = 'Any'
  )

  process {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'The filesystem path is empty.' }

    if ($AllowNonexistent) {
      $Provider = $null
      $Drive = $null
      $ResolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $Path, [ref]$Provider, [ref]$Drive)
      if ($Provider.Name -ne 'FileSystem') { throw "The path is not in the FileSystem provider: $Path" }
    } else {
      $Item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
      if ($Item.PSProvider.Name -ne 'FileSystem') { throw "The path is not in the FileSystem provider: $Path" }
      $ResolvedPath = $Item.FullName
      if ($PathType -eq 'Leaf' -and -not $Item.PSIsContainer) { return $ResolvedPath }
      if ($PathType -eq 'Container' -and $Item.PSIsContainer) { return $ResolvedPath }
      if ($PathType -ne 'Any') { throw "The path is not a $($PathType.ToLowerInvariant()) filesystem item: $Path" }
    }

    return [IO.Path]::GetFullPath($ResolvedPath)
  }
}

function Resolve-SafeExtractionPath {
  <#
  .SYNOPSIS
    Resolve a relative payload path without allowing extraction-root escape
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][string]$RelativePath
  )
  if ([string]::IsNullOrWhiteSpace($RelativePath) -or $RelativePath.IndexOf([char]0) -ge 0) { throw 'The payload path is empty or invalid.' }
  $Normalized = $RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar).Replace('\', [IO.Path]::DirectorySeparatorChar)
  if ([IO.Path]::IsPathRooted($Normalized) -or $Normalized -match '^[A-Za-z]:') { throw "The payload path is rooted: $RelativePath" }
  # Resolve with PowerShell semantics before using System.IO. The process-wide
  # .NET current directory can differ from the runspace's current location.
  $ResolvedDestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  $Root = $ResolvedDestinationPath.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  $Output = [IO.Path]::GetFullPath([IO.Path]::Combine($Root, $Normalized.TrimStart([IO.Path]::DirectorySeparatorChar)))
  if (-not $Output.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase)) { throw "The payload path escapes the destination: $RelativePath" }
  return $Output
}

Export-ModuleMember -Function Resolve-InstallerFileSystemPath, Resolve-SafeExtractionPath
