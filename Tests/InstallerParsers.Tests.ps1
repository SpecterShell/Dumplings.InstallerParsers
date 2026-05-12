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
  It 'Should keep NSIS blocks as byte arrays for fast entry parsing' {
    $Fixture = Get-InstallerFixture -Name 'alist-desktop_3.60.0_x64-setup.exe' -Url 'https://github.com/AlistGo/desktop-release/releases/download/v3.60.0/alist-desktop_3.60.0_x64-setup.exe'
    $Module = Get-Module NSIS
    $Result = & $Module {
      param($Fixture)

      $HeaderData = Get-NSISHeaderData -Path $Fixture
      $BlockHeaders = Get-NSISBlockHeaders -HeaderBytes $HeaderData.HeaderBytes -Is64Bit $HeaderData.PEInfo.Is64Bit
      $EntryBlock = Get-NSISBlockBytes -HeaderBytes $HeaderData.HeaderBytes -BlockHeaders $BlockHeaders -Index 2

      [pscustomobject]@{
        IsByteArray = $EntryBlock -is [byte[]]
        Length      = $EntryBlock.Length
      }
    } $Fixture

    $Result.IsByteArray | Should -BeTrue
    $Result.Length | Should -BeGreaterThan 0
  }

  It 'Should recover uninstall metadata from WriteRegStr entries' {
    $Module = Get-Module NSIS
    $Result = & $Module {
      $StringBytes = [System.Collections.Generic.List[byte]]::new()

      function Add-TestString {
        param([string]$Text)

        $Offset = [int]($StringBytes.Count / 2)
        $StringBytes.AddRange([System.Text.Encoding]::Unicode.GetBytes($Text + [char]0))
        return $Offset
      }

      $KeyOffset = Add-TestString 'Software\Microsoft\Windows\CurrentVersion\Uninstall\CCFLink'
      $NameOffset = Add-TestString 'DisplayVersion'
      $ValueOffset = Add-TestString '7.7.0-Release.80131'
      $HklmRawValue = [uint32]$Script:NSIS_REG_ROOT_HKLM
      $HklmSignedValue = [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes($HklmRawValue), 0)

      $State = [pscustomobject]@{
        Entries          = @(
          [pscustomobject]@{
            Opcode = $Script:NSIS_OPCODE_WRITE_REG_STR
            Raw    = [uint32[]]@($Script:NSIS_OPCODE_WRITE_REG_STR, $HklmRawValue, $KeyOffset, $NameOffset, $ValueOffset, 1, 1)
            Values = [int[]]@($Script:NSIS_OPCODE_WRITE_REG_STR, $HklmSignedValue, $KeyOffset, $NameOffset, $ValueOffset, 1, 1)
          }
        )
        StringsBlock     = $StringBytes.ToArray()
        VersionInfo      = [pscustomobject]@{
          Unicode = $true
          IsV3    = $true
        }
        Variables        = @{}
        Registry         = @{}
        ShellVarContext  = 'HKLM'
        Metadata         = [ordered]@{
          DisplayVersion         = $null
          DisplayName            = $null
          Publisher              = $null
          ProductCode            = $null
          DefaultInstallLocation = $null
          Scope                  = $null
          RegistryValues         = @{}
        }
      }

      Add-NSISDirectUninstallWrites -State $State
      [pscustomobject]@{
        DisplayVersion = $State.Metadata.DisplayVersion
        ProductCode    = $State.Metadata.ProductCode
        Scope          = $State.Metadata.Scope
      }
    }

    $Result.DisplayVersion | Should -Be '7.7.0-Release.80131'
    $Result.ProductCode | Should -Be 'CCFLink'
    $Result.Scope | Should -Be 'machine'
  }

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
