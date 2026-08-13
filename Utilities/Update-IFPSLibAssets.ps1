# License: GPL-3.0-or-later. See ..\LICENSE.
<#
.SYNOPSIS
  Rebuild and verify the pinned IFPSLib runtime assets.
.DESCRIPTION
  Checks out the exact source revision recorded in IFPSLibAssets.psd1, builds
  IFPSLib for .NET Standard 2.0, verifies assembly identity and SHA-256, and
  optionally replaces the redistributed copies. The script never executes an
  installer or IFPS bytecode.
.PARAMETER SourcePath
  Existing clean IFPSTools.NET checkout. When omitted, a temporary clone is used.
.PARAMETER Install
  Replace the verified assemblies and upstream license in their categorized asset directories.
#>
[CmdletBinding()]
param (
  [string]$SourcePath,
  [switch]$Install
)

$ErrorActionPreference = 'Stop'
$ModuleRoot = Split-Path -Parent $PSScriptRoot
$AssetRoot = Join-Path $ModuleRoot 'Assets'
$AssemblyRoot = Join-Path $AssetRoot 'Assemblies'
$LicenseRoot = Join-Path $AssetRoot 'Licenses'
$ManifestPath = Join-Path $AssetRoot 'IFPSLibAssets.psd1'
$Manifest = Import-PowerShellDataFile -LiteralPath $ManifestPath
$TemporaryRoot = $null

try {
  if ([string]::IsNullOrWhiteSpace($SourcePath)) {
    $TemporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('Dumplings-IFPSLib-{0}' -f [Guid]::NewGuid().ToString('N'))
    & git clone --quiet --no-checkout $Manifest.SourceRepository $TemporaryRoot
    if ($LASTEXITCODE -ne 0) { throw 'Failed to clone the pinned IFPSTools.NET source.' }
    $SourcePath = $TemporaryRoot
  }

  $SourcePath = (Resolve-Path -LiteralPath $SourcePath).Path
  if ($TemporaryRoot) {
    & git -C $SourcePath checkout --quiet --detach $Manifest.SourceCommit
    if ($LASTEXITCODE -ne 0) { throw "Failed to check out IFPSTools.NET commit '$($Manifest.SourceCommit)'." }
  }
  $Head = (& git -C $SourcePath rev-parse HEAD).Trim()
  if ($LASTEXITCODE -ne 0 -or $Head -cne $Manifest.SourceCommit) {
    throw "The IFPSTools.NET checkout is at '$Head', not '$($Manifest.SourceCommit)'."
  }

  $ProjectPath = Join-Path $SourcePath 'IFPSLib\IFPSLib.csproj'
  & dotnet build $ProjectPath --configuration Release --nologo
  if ($LASTEXITCODE -ne 0) { throw 'The pinned IFPSLib build failed.' }
  $OutputRoot = Join-Path $SourcePath 'IFPSLib\bin\Release\netstandard2.0'
  $Assets = Get-Content -LiteralPath (Join-Path $SourcePath 'IFPSLib\obj\project.assets.json') -Raw | ConvertFrom-Json -AsHashtable
  $Target = $Assets.targets[($Assets.targets.Keys | Select-Object -First 1)]

  foreach ($Assembly in $Manifest.Assemblies) {
    $BuiltPath = Join-Path $OutputRoot $Assembly.Name
    if (-not (Test-Path -LiteralPath $BuiltPath -PathType Leaf)) {
      # PackageReference assemblies are not copied into a netstandard library's
      # output directory. Resolve the exact restored runtime asset recorded by
      # project.assets.json instead of assuming a user-specific NuGet path.
      foreach ($LibraryEntry in $Target.GetEnumerator()) {
        $RelativeAsset = @($LibraryEntry.Value.runtime.Keys; $LibraryEntry.Value.compile.Keys) |
          Where-Object { [IO.Path]::GetFileName($_) -ceq $Assembly.Name } |
          Select-Object -First 1
        if (-not $RelativeAsset) { continue }
        $PackagePath = $Assets.libraries[$LibraryEntry.Key].path
        foreach ($PackageRoot in $Assets.packageFolders.Keys) {
          $Candidate = Join-Path (Join-Path $PackageRoot $PackagePath) $RelativeAsset
          if (Test-Path -LiteralPath $Candidate -PathType Leaf) {
            $BuiltPath = $Candidate
            break
          }
        }
        if (Test-Path -LiteralPath $BuiltPath -PathType Leaf) { break }
      }
    }
    if (-not (Test-Path -LiteralPath $BuiltPath -PathType Leaf)) { throw "The build did not produce '$($Assembly.Name)'." }
    $Identity = [Reflection.AssemblyName]::GetAssemblyName($BuiltPath)
    if ($Identity.Version.ToString() -cne $Assembly.Version) {
      throw "Assembly '$($Assembly.Name)' has version '$($Identity.Version)', expected '$($Assembly.Version)'."
    }
    $Hash = (Get-FileHash -LiteralPath $BuiltPath -Algorithm SHA256).Hash
    if ($Hash -cne $Assembly.Sha256) {
      throw "Assembly '$($Assembly.Name)' has SHA-256 '$Hash', expected '$($Assembly.Sha256)'. Review the toolchain or update the pinned metadata deliberately."
    }
    if ($Install) {
      $null = New-Item -Path $AssemblyRoot -ItemType Directory -Force
      Copy-Item -LiteralPath $BuiltPath -Destination (Join-Path $AssemblyRoot $Assembly.Name) -Force
    }
  }

  $LicensePath = Join-Path $SourcePath 'LICENSE.txt'
  if ($Install) {
    $null = New-Item -Path $LicenseRoot -ItemType Directory -Force
    Copy-Item -LiteralPath $LicensePath -Destination (Join-Path $LicenseRoot 'IFPSTools.NET.txt') -Force
  }
  [pscustomobject]@{
    SourceCommit = $Head
    DotNetSdk    = (& dotnet --version).Trim()
    Installed    = [bool]$Install
    Assemblies   = [string[]]@($Manifest.Assemblies.Name)
  }
} finally {
  if ($TemporaryRoot -and (Test-Path -LiteralPath $TemporaryRoot)) {
    Remove-Item -LiteralPath $TemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}
