BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'NSIS.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Inno.psm1') -Force

  $Script:FixtureDirectory = Join-Path $env:TEMP 'DumplingsInstallerParsersTests'
  $null = New-Item -Path $Script:FixtureDirectory -ItemType Directory -Force

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url,

      [switch]$UseSourceForgeMetaRefresh
    )

    $FixturePath = Join-Path $Script:FixtureDirectory $Name
    if (Test-Path -LiteralPath $FixturePath) { return $FixturePath }

    if ($UseSourceForgeMetaRefresh) {
      $Page = Invoke-WebRequest -Uri $Url
      $MetaRefresh = [regex]::Match($Page.Content, 'url=([^"&]+(?:&amp;[^"<]+)*)')
      if (-not $MetaRefresh.Success) { throw "Failed to resolve the SourceForge download URL for $Url" }
      $Url = [System.Web.HttpUtility]::HtmlDecode($MetaRefresh.Groups[1].Value)
    }

    Invoke-WebRequest -Uri $Url -OutFile $FixturePath
    return $FixturePath
  }
}

Describe 'NSIS parser' {
  It 'Should read static metadata from the AList installer' {
    $Fixture = Get-InstallerFixture -Name 'alist-desktop_3.60.0_x64-setup.exe' -Url 'https://github.com/AlistGo/desktop-release/releases/download/v3.60.0/alist-desktop_3.60.0_x64-setup.exe'
    $Info = Get-NSISInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be 'alist-desktop'
    $Info.DisplayVersion | Should -Be '3.60.0'
    $Info.ProductCode | Should -Be 'alist-desktop'
  }

  It 'Should read wrapped uninstall metadata from the GCompris installer' {
    $Fixture = Get-InstallerFixture -Name 'gcompris-teachers-26.1-win64-gcc.exe' -Url 'https://download.kde.org/stable/gcompris/qt/windows/gcompris-teachers-26.1-win64-gcc.exe'
    $Info = Get-NSISInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be 'GCompris Teachers tool'
    $Info.DisplayVersion | Should -Be '26.1'
    $Info.Publisher | Should -Be 'GCompris team'
  }

  It 'Should read raw DEFLATE uninstall metadata from the Dolphin installer' {
    $Fixture = Get-InstallerFixture -Name 'dolphin-release_26.04-7555-windows-cl-msvc2022-x86_64.exe' -Url 'https://cdn.kde.org/ci-builds/system/dolphin/release-26.04/windows/dolphin-release_26.04-7555-windows-cl-msvc2022-x86_64.exe'
    $Info = Get-NSISInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be 'Dolphin'
    $Info.DisplayVersion | Should -Be '26.04.0'
    $Info.ProductCode | Should -Be 'Dolphin'
    $Info.Publisher | Should -Be 'KDE e.V.'
  }
}

Describe 'Inno parser' {
  It 'Should read static metadata from the WinSCP installer' {
    $Fixture = Get-InstallerFixture -Name 'winscp-6.5.6-setup.exe' -Url 'https://sourceforge.net/projects/winscp/files/WinSCP/6.5.6/WinSCP-6.5.6-Setup.exe/download' -UseSourceForgeMetaRefresh
    $Info = Get-InnoInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Inno'
    $Info.DisplayName | Should -Be 'WinSCP 6.5.6'
    $Info.DisplayVersion | Should -Be '6.5.6'
    $Info.ProductCode | Should -Be 'winscp3'
  }

  It 'Should extract BK5WIN.EXE statically from the BankLink Books installer' {
    $Fixture = Get-InstallerFixture -Name 'BankLinkBooks.exe' -Url 'https://download.myob.com/BankLinkBooks.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'myob-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = Expand-InnoInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'BK5WIN.EXE'
      $Extracted | Should -HaveCount 1
      (Get-Item $Extracted[0].FullName).VersionInfo.FileVersion | Should -Be '5.55.3.7499'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract the English VUSC launch file statically from the VUSC installer' {
    $Fixture = Get-InstallerFixture -Name 'VUSC_setup_709.zip' -Url 'https://www.ok2kkw.com/vusc/vusc4win/VUSC_setup_709.zip'
    $ArchivePath = Join-Path $Script:FixtureDirectory 'vusc-archive'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'vusc-expanded'
    Remove-Item -Path $ArchivePath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      Expand-Archive -Path $Fixture -DestinationPath $ArchivePath -Force
      $NestedInstaller = Get-ChildItem -Path $ArchivePath -Filter '*.exe' -Recurse | Select-Object -First 1
      $Extracted = Expand-InnoInstaller -Path $NestedInstaller.FullName -DestinationPath $ExpandedPath -Name 'VUSC.exe' -Language 'en'

      $Extracted | Should -HaveCount 1
      (Get-FileHash -Path $Extracted[0].FullName -Algorithm SHA256).Hash | Should -Be '021A05A497BBCE1EE604CC223E7BB813171F198B3B27AE3C90A50EBD0F6DFEAE'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
      Remove-Item -Path $ArchivePath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}
