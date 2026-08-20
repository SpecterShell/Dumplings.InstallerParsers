. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $ModuleRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
  Import-Module (Join-Path $ModuleRoot 'Libraries\Infrastructure\InstallerDiagnostics.psm1') -Force
}

Describe 'Installer parser diagnostic contract' {
  It 'does not expose legacy parser diagnostic collection properties' {
    $Files = Get-ChildItem -LiteralPath (Join-Path $ModuleRoot 'Libraries\Installers') -Filter '*.psm1' -File -Recurse
    $LegacyPropertyPattern = '(?m)^\s*["'']?(?:Warnings|Notices|WrapperWarnings|AppsAndFeaturesNotices|BlockingIssues)["'']?\s*='

    foreach ($File in $Files) {
      [IO.File]::ReadAllText($File.FullName) | Should -Not -Match $LegacyPropertyPattern -Because "$($File.FullName) must expose Diagnostics instead"
    }
  }

  It 'returns context-neutral diagnostics from the shared constructor' {
    $Diagnostic = New-InstallerDiagnostic -Id 'Test.ParserEvidence' -Source Test -Message 'Parser evidence.' -Kind Incomplete -Areas Metadata

    $Diagnostic.Scenario | Should -BeNullOrEmpty
    $Diagnostic.Level | Should -BeNullOrEmpty
    $Diagnostic.IsBlocking | Should -BeNullOrEmpty
  }
}
