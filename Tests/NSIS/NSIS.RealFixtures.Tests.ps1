. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\NSISTestSetup.ps1')

Describe 'NSIS real installer fixtures' -Tag 'RealFixture', 'Network' {
  It 'Should read static metadata from the AList installer' {
    $Fixture = Get-InstallerFixture -Name 'alist-desktop_3.60.0_x64-setup.exe' -Url 'https://github.com/AlistGo/desktop-release/releases/download/v3.60.0/alist-desktop_3.60.0_x64-setup.exe'
    $Info = Get-NSISInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be 'alist-desktop'
    $Info.DisplayVersion | Should -Be '3.60.0'
    $Info.ProductCode | Should -Be 'alist-desktop'
    $Info.IsPortable | Should -BeFalse
    $Info.PortableEvidence | Should -BeNullOrEmpty
    @($Info.AppsAndFeaturesEntries).Count | Should -Be 1
    $Info.HasLocalizedAppsAndFeaturesEntries | Should -BeFalse
    @($Info.Diagnostics | Where-Object Kind -EQ Information) | Should -BeNullOrEmpty
  }

  It 'Should follow the elevated UserInfo branch in the Fluent Bit CPack installer' {
    $Fixture = Get-InstallerFixture -Name 'fluent-bit-5.1.0-win64.exe' `
      -Url 'https://packages.fluentbit.io/windows/fluent-bit-5.1.0-win64.exe' `
      -Sha256 'F929A7C3D3C886035135B9DD15FE42615D0259AF8CDED0370C02DDAEC41C17B1'

    $Info = Get-NSISInfo -Path $Fixture -Architecture x64
    $RequestedUserInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope user

    $Info.RequestedExecutionLevel | Should -Be 'requireAdministrator'
    $Info.SupportedScopes | Should -Be @('machine')
    $Info.Scope | Should -Be 'machine'
    $Info.ProductCode | Should -Be 'fluent-bit'
    $Info.DisplayName | Should -Be 'fluent-bit'
    $Info.DisplayVersion | Should -Be '5.1.0'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\fluent-bit'
    @($Info.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be @('HKLM')
    @($Info.Diagnostics | Where-Object Kind -NE Information) | Should -BeNullOrEmpty

    $RequestedUserInfo.Scope | Should -Be 'machine'
    @($RequestedUserInfo.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be @('HKLM')
    $RequestedUserInfo.Diagnostics.Message | Should -Contain "The requested 'user' scope did not resolve to matching uninstall registry evidence; the parser observed 'machine' scope instead."
  }

  It 'Should resolve architecture-specific ARP identities from the BitComet installer' {
    $Fixture = Get-InstallerFixture -Name 'BitComet_2.21_setup.exe' -Url 'https://download.bitcomet.com/achive/BitComet_2.21_setup.exe' -Sha256 '2BB0AC769FE8B75B1B1B8CA42FA55D29D94AAF68480611538DBB4395D05082D2'

    $X86Info = Get-NSISInfo -Path $Fixture -Architecture x86
    $X64Info = Get-NSISInfo -Path $Fixture -Architecture x64

    $X86Info.ProductCode | Should -Be 'BitComet'
    $X86Info.DefaultInstallLocation | Should -Be '%ProgramFiles(x86)%\BitComet'
    $X86Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $X86Info.AppsAndFeaturesEntries.ProductCode | Should -Contain 'BitComet'
    $X86Info.ParserVersionInfo.HasComponentPage | Should -BeTrue

    $X64Info.ProductCode | Should -Be 'BitComet_x64'
    $X64Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\BitComet'
    $X64Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $X64Info.AppsAndFeaturesEntries.ProductCode | Should -Contain 'BitComet_x64'
  }

  It 'Should retain Yuanfudao ARP writes when resolving its x64 runtime branch' {
    $Fixture = Get-InstallerFixture -Name 'yuanfudao-student-7.27.0.22424-installer-x64.exe' `
      -Url 'https://apphub.fbcontent.cn/ape-gallery/app/yuanfudao-student-7.27.0.22424-installer-x64.exe' `
      -Sha256 '4ECC35BB89473DA3C4C227BF6B6480493A73CFC293ABF05BB4CE483EDC279B66'

    $Info = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope machine

    $Info.ProductCode | Should -Be 'tutor-electron-student'
    $Info.DisplayName | Should -Be '猿辅导'
    $Info.DisplayVersion | Should -Be '7.27.0.22424'
    $Info.Publisher | Should -Be '北京贞观雨科技有限公司'
    $Info.Scope | Should -Be 'machine'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.AppsAndFeaturesEntries.ProductCode | Should -Contain 'tutor-electron-student'
    @($Info.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be @('HKLM')
    @($Info.Diagnostics | Where-Object Kind -NE Information) | Should -BeNullOrEmpty
  }

  It 'Should select BeeDrive machine ARP writes when dormant user writes are also compiled' {
    $Fixture = Get-InstallerFixture -Name 'BeeDrive-2.0.3-20301-x64.exe' `
      -Url 'https://global.synologydownload.com/download/Utility/BeeDrive/2.0.3-20301/Windows/x86_64/BeeDrive-2.0.3-20301-x64.exe' `
      -Sha256 '253353785A303A704CDA2F4C906AFF1F0986BD5E6A84BCD788826477A41C7A0D'

    $Info = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope machine

    $Info.ProductCode | Should -Be '986aaad0-133f-5ad2-87e6-59ea820cbbad'
    $Info.DisplayName | Should -Be 'BeeDrive 2.0.3-20301'
    $Info.DisplayVersion | Should -Be '2.0.3-20301'
    $Info.Publisher | Should -Be 'Synology'
    $Info.Scope | Should -Be 'machine'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.AppsAndFeaturesEntries.ProductCode | Should -Contain '986aaad0-133f-5ad2-87e6-59ea820cbbad'
    @($Info.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be @('HKLM')
    @($Info.Diagnostics | Where-Object Kind -NE Information) | Should -BeNullOrEmpty
  }

  It 'Should resolve scope-specific ARP identities from the DBeaver installer' {
    $Fixture = Get-InstallerFixture -Name 'dbeaver-ce-26.1.3-windows-x86_64.exe' -Url 'https://github.com/dbeaver/dbeaver/releases/download/26.1.3/dbeaver-ce-26.1.3-windows-x86_64.exe' -Sha256 'DF3E522E3DBD4E6A7F91DCD8E422A0BE13220D2E895A681B5B6732ADB518297D'

    $UserInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope user
    $MachineInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope machine

    $UserInfo.HasScopeRuntimeCheck | Should -BeTrue
    $UserInfo.SupportedScopes | Should -Contain 'user'
    $UserInfo.SupportedScopes | Should -Contain 'machine'
    $UserInfo.ProductCode | Should -Be 'DBeaver (current user)'
    $UserInfo.DisplayName | Should -Be 'DBeaver 26.1.3 (current user)'
    $UserInfo.Scope | Should -Be 'user'
    $UserInfo.DefaultInstallLocation | Should -Be '%LocalAppData%\DBeaver'
    $UserInfo.AppsAndFeaturesEntries.ProductCode | Should -Contain 'DBeaver (current user)'

    $MachineInfo.ProductCode | Should -Be 'DBeaver'
    $MachineInfo.DisplayName | Should -Be 'DBeaver 26.1.3'
    $MachineInfo.Scope | Should -Be 'machine'
    $MachineInfo.DefaultInstallLocation | Should -Be '%ProgramFiles%\DBeaver'
    $MachineInfo.AppsAndFeaturesEntries.ProductCode | Should -Contain 'DBeaver'
    @($MachineInfo.Diagnostics | Where-Object Kind -NE Information) | Should -BeNullOrEmpty
  }

  It 'Should resolve Registry plug-in ARP writes for both MultiCommander architectures and scopes' {
    $Fixtures = @(
      [pscustomobject]@{
        Architecture = 'x86'
        ProductCode  = 'MultiCommander Win32'
        RelativePath = 'Installers\NSIS\MathiasSvensson.MultiCommander\16.2.0.3205\MultiCommander_x86.exe'
        Uri          = 'https://multicommander.com/files/updates/MultiCommander_win32_(16.2.0.3205).exe'
        Sha256       = 'ABE4966B39E303F504914169EDC220A021536660645FA1779B2323098FBD7833'
      },
      [pscustomobject]@{
        Architecture = 'x64'
        ProductCode  = 'MultiCommander x64'
        RelativePath = 'Installers\NSIS\MathiasSvensson.MultiCommander\16.2.0.3205\MultiCommander_x64.exe'
        Uri          = 'https://multicommander.com/files/updates/MultiCommander_x64_(16.2.0.3205).exe'
        Sha256       = 'CD24CE9C6E17189CD618FF7AB4DD77BE4587DA947294169E15D797C342AFEEE9'
      }
    )

    foreach ($FixtureInfo in $Fixtures) {
      $Fixture = Get-DumplingsTestFixture -RelativePath $FixtureInfo.RelativePath -Uri $FixtureInfo.Uri -Sha256 $FixtureInfo.Sha256
      foreach ($Scope in 'user', 'machine') {
        $InstallMode = $Scope -eq 'user' ? 'User' : 'All'
        $Info = Get-NSISInfo -Path $Fixture -Architecture $FixtureInfo.Architecture -Scope $Scope -CommandLine ('"' + $Fixture + '" /S /InstallMode=' + $InstallMode)

        $Info.ProductCode | Should -Be $FixtureInfo.ProductCode
        $Info.DisplayVersion | Should -Be '16.2.0.3205'
        $Info.Publisher | Should -Be 'Mathias Svensson'
        $Info.Scope | Should -Be $Scope
        $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
        $Info.AppsAndFeaturesEntries.ProductCode | Should -Contain $FixtureInfo.ProductCode
        @($Info.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be $(if ($Scope -eq 'user') { @('HKCU') } else { @('HKLM') })
        @($Info.Diagnostics | Where-Object Kind -NE Information) | Should -BeNullOrEmpty
      }
    }
  }

  It 'Should resolve both current electron-builder scopes from the WorkBuddy installer' {
    $Fixture = Get-InstallerFixture -Name 'WorkBuddy-win32-x64-user-5.3.5.34189228-8044e898.exe' -Url 'https://download.codebuddy.cn/workbuddy/saas/win32-x64-user/WorkBuddy-win32-x64-user-5.3.5.34189228-8044e898.exe' -Sha256 '3064D6E873BD74169E62EA2E480382C120125E6B8F99155649EC2389C3CBFAFF'

    $UserInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope user
    $MachineInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope machine

    $UserInfo.SupportedScopes | Should -Contain 'user'
    $UserInfo.SupportedScopes | Should -Contain 'machine'
    $UserInfo.ProductCode | Should -Be 'BFD312E9-1019-4F57-9F44-F86246833B50'
    $UserInfo.Scope | Should -Be 'user'
    $UserInfo.DefaultInstallLocation | Should -Be '%LocalAppData%\Programs\WorkBuddy'
    $UserInfo.UninstallString | Should -Be '"%LocalAppData%\Programs\WorkBuddy\Uninstall WorkBuddy.exe" /currentuser'
    @($UserInfo.RegistryWrites | Where-Object IsUninstallKey).Root | Should -Contain 'HKCU'
    @($UserInfo.Diagnostics | Where-Object Kind -NE Information) | Should -BeNullOrEmpty

    $MachineInfo.ProductCode | Should -Be 'BFD312E9-1019-4F57-9F44-F86246833B50'
    $MachineInfo.Scope | Should -Be 'machine'
    $MachineInfo.DefaultInstallLocation | Should -Be '%ProgramFiles%\WorkBuddy'
    $MachineInfo.UninstallString | Should -Be '"%ProgramFiles%\WorkBuddy\Uninstall WorkBuddy.exe" /allusers'
    @($MachineInfo.RegistryWrites | Where-Object IsUninstallKey).Root | Should -Contain 'HKLM'
    @($MachineInfo.Diagnostics | Where-Object Kind -NE Information) | Should -BeNullOrEmpty
  }

  It 'Should recover one explicit scoped ARP identity after custom AionUi hooks stop section simulation' {
    $Fixture = Get-InstallerFixture -Name 'AionUi-2.1.42-win-x64.exe' -Url 'https://github.com/iOfficeAI/AionUi/releases/download/v2.1.42/AionUi-2.1.42-win-x64.exe'

    $UserInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope user
    $MachineInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope machine

    foreach ($Info in @($UserInfo, $MachineInfo)) {
      $Info.ProductCode | Should -Be 'f3bfde38-8429-545c-a4e9-a078d87dee6c'
      $Info.DisplayName | Should -Be 'AionUi'
      $Info.DisplayVersion | Should -Be '2.1.42'
      $Info.Publisher | Should -Be 'AionUi'
      $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
      $Info.AppsAndFeaturesEntries.ProductCode | Should -Contain 'f3bfde38-8429-545c-a4e9-a078d87dee6c'
      $Info.UninstallString | Should -BeNullOrEmpty
      $Info.QuietUninstallString | Should -BeNullOrEmpty
      $Info.UnresolvedFields | Should -Contain 'UninstallString'
      $Info.UnresolvedFields | Should -Contain 'QuietUninstallString'
      @($Info.Diagnostics | Where-Object Kind -NE Information) | Should -BeNullOrEmpty
    }

    $UserInfo.Scope | Should -Be 'user'
    $UserInfo.DefaultInstallLocation | Should -Be '%LocalAppData%\Programs\AionUi'
    @($UserInfo.RegistryWrites | Where-Object IsUninstallKey).Count | Should -BeGreaterThan 0
    @($UserInfo.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be @('HKCU')

    $MachineInfo.Scope | Should -Be 'machine'
    $MachineInfo.DefaultInstallLocation | Should -Be '%ProgramFiles%\AionUi'
    @($MachineInfo.RegistryWrites | Where-Object IsUninstallKey).Count | Should -BeGreaterThan 0
    @($MachineInfo.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be @('HKLM')
  }

  It 'Should retain the selected RivonClaw scope after later sections change ambient shell context' {
    $Fixture = Get-InstallerFixture -Name 'TK-Copilot.Setup.1.8.82.exe' -Url 'https://github.com/gaoyangz77/rivonclaw/releases/download/v1.8.82/TK-Copilot.Setup.1.8.82.exe' -Sha256 '02AD6F71BCE64307EB3EBAE25041503D690E0C64FFAD4D209BF791B91A684824'

    $UserInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope user
    $MachineInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope machine

    foreach ($Info in @($UserInfo, $MachineInfo)) {
      $Info.ProductCode | Should -Be '51492edb-6d67-582c-a781-6b48bbf5f3bf'
      $Info.DisplayName | Should -Be 'TK Copilot'
      $Info.DisplayVersion | Should -Be '1.8.82'
      $Info.SupportedScopes | Should -Contain 'user'
      $Info.SupportedScopes | Should -Contain 'machine'
      $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
      @($Info.Diagnostics | Where-Object Kind -NE Information) | Should -BeNullOrEmpty
    }

    $UserInfo.Scope | Should -Be 'user'
    $UserInfo.DefaultInstallLocation | Should -Be '%LocalAppData%\Programs\TK Copilot'
    @($UserInfo.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be @('HKCU')

    $MachineInfo.Scope | Should -Be 'machine'
    $MachineInfo.DefaultInstallLocation | Should -Be '%ProgramFiles%\TK Copilot'
    @($MachineInfo.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be @('HKLM')
  }

  It 'Should identify the three standard Tauri NSIS install modes from compiled evidence' {
    $Readest = Get-InstallerFixture -Name 'Readest_0.11.20_x64-setup.exe' -Url 'https://github.com/readest/readest/releases/download/v0.11.20/Readest_0.11.20_x64-setup.exe' -Sha256 'DF8C9E2763CC9EC3E453CCE6320DF442798D115F9127C0C6BA831B800CBDB7DD'
    $Yaak = Get-InstallerFixture -Name 'Yaak_2026.4.0_x64-setup.exe' -Url 'https://github.com/mountain-loop/yaak/releases/download/v2026.4.0/Yaak_2026.4.0_x64-setup.exe' -Sha256 '026DC0753F4880313B93BBFF848A9CD09A114F87111AAAEF5E4E698C52C8B561'
    $ClashVerge = Get-InstallerFixture -Name 'Clash.Verge_2.5.2_x64-setup.exe' -Url 'https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v2.5.2/Clash.Verge_2.5.2_x64-setup.exe' -Sha256 'BA42F00B1082E352352080170FE86AE411BCC854CB13F1B8BEBC9025E8A7CBF4'

    $BothInfo = Get-NSISInfo -Path $Readest -Scope user
    $UserInfo = Get-NSISInfo -Path $Yaak
    $MachineInfo = Get-NSISInfo -Path $ClashVerge
    $MachineMismatchInfo = Get-NSISInfo -Path $ClashVerge -Scope user

    $BothInfo.IsTauri | Should -BeTrue
    $BothInfo.TauriInstallerMode | Should -Be 'both'
    $BothInfo.RequestedExecutionLevel | Should -Be 'highestAvailable'
    $BothInfo.SupportedScopes | Should -Be @('user', 'machine')
    $BothInfo.Scope | Should -Be 'user'
    $BothInfo.DefaultInstallLocation | Should -Be '%LocalAppData%\Programs\Readest'

    $UserInfo.IsTauri | Should -BeTrue
    $UserInfo.TauriInstallerMode | Should -Be 'currentUser'
    $UserInfo.RequestedExecutionLevel | Should -Be 'asInvoker'
    $UserInfo.SupportedScopes | Should -Be @('user')
    $UserInfo.DefaultInstallLocation | Should -Be '%LocalAppData%\Yaak'

    $MachineInfo.IsTauri | Should -BeTrue
    $MachineInfo.TauriInstallerMode | Should -Be 'perMachine'
    $MachineInfo.RequestedExecutionLevel | Should -Be 'requireAdministrator'
    $MachineInfo.SupportedScopes | Should -Be @('machine')
    $MachineInfo.DefaultInstallLocation | Should -Be '%ProgramFiles%\Clash Verge'
    @($MachineMismatchInfo.Diagnostics | Where-Object Id -EQ 'NSIS.Tauri.ScopeMismatch').Count | Should -Be 1
  }

  It 'Should not treat an empty branch-merge scope as a Tauri scope mismatch' {
    $Fixture = Get-InstallerFixture -Name 'Reader-v1.4.3-windows-x64-setup.exe' `
      -Url 'https://github.com/hadc188/reader/releases/download/v1.4.3/Reader-v1.4.3-windows-x64-setup.exe' `
      -Sha256 'A1ACF58663DDE433165C344129871972AB60721F9E9CA77A103EEE4BF64DE382'

    $Info = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope user

    $Info.IsTauri | Should -BeTrue
    $Info.TauriInstallerMode | Should -Be 'currentUser'
    $Info.Scope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user')
    @($Info.Diagnostics | Where-Object Id -EQ 'NSIS.Tauri.ScopeMismatch') | Should -BeNullOrEmpty
  }

  It 'Should resolve the equality-guarded machine scope in the TranslatorX Tauri installer' {
    $Fixture = Get-InstallerFixture -Name 'TranslatorX_26.1.1_x64-setup.exe' `
      -Url 'https://github.com/pgiralt/translatorx-releases/releases/download/v26.1.1/TranslatorX_26.1.1_x64-setup.exe' `
      -Sha256 'FC1AA93FA0C746AE28E0AD8DDAEBADF1968FBB6A305470140AE8542460968EF4'

    $UserInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope user
    $MachineInfo = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope machine

    foreach ($Info in @($UserInfo, $MachineInfo)) {
      $Info.IsTauri | Should -BeTrue
      $Info.TauriInstallerMode | Should -Be 'both'
      $Info.SupportedScopes | Should -Be @('user', 'machine')
      $Info.ProductCode | Should -Be 'TranslatorX'
      @($Info.Diagnostics | Where-Object Kind -NE Information) | Should -BeNullOrEmpty
    }

    $UserInfo.Scope | Should -Be 'user'
    $UserInfo.DefaultInstallLocation | Should -Be '%LocalAppData%\TranslatorX'
    @($UserInfo.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be @('HKCU')

    $MachineInfo.Scope | Should -Be 'machine'
    $MachineInfo.DefaultInstallLocation | Should -Be '%ProgramFiles%\TranslatorX'
    @($MachineInfo.RegistryWrites | Where-Object IsUninstallKey).Root | Select-Object -Unique | Should -Be @('HKLM')
  }

  It 'Should read static metadata from a dual-scope BongoCat NSIS installer' {
    $Fixture = Get-InstallerFixture -Name 'BongoCat_1.1.0_x64-setup.exe' -Url 'https://github.com/ayangweb/BongoCat/releases/download/v1.1.0/BongoCat_1.1.0_x64-setup.exe'
    $Info = Get-NSISInfo -Path $Fixture
    $IsElectronBuilder = Test-ElectronBuilder -Path $Fixture

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be 'BongoCat'
    $Info.DisplayVersion | Should -Be '1.1.0'
    $Info.ProductCode | Should -Be 'BongoCat'
    $Info.Publisher | Should -Be 'ayangweb'
    $IsElectronBuilder | Should -BeFalse
  }

  It 'Should extract a selected executable after skipping earlier solid BongoCat records' {
    $Fixture = Get-InstallerFixture -Name 'BongoCat_1.1.0_x64-setup.exe' -Url 'https://github.com/ayangweb/BongoCat/releases/download/v1.1.0/BongoCat_1.1.0_x64-setup.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'nsis-expanded-bongocat'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = @(Expand-NSISInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'bongo-cat.exe' -MaximumExpandedBytes 33554432 -CollisionAction Rename)
      $Asset = @(Expand-NSISInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'assets\models\gamepad\resources\cover.png' -MaximumExpandedBytes 1048576 -CollisionAction Rename)

      $Extracted | Should -HaveCount 1
      $Extracted[0].VersionInfo.FileVersion | Should -Be '1.1.0'
      $Asset | Should -HaveCount 1
      [IO.Path]::GetRelativePath($ExpandedPath, $Asset[0].FullName) | Should -Be 'assets\models\gamepad\resources\cover.png'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should read static metadata from a dual-scope RedPanda C++ NSIS installer' {
    $Fixture = Get-InstallerFixture -Name 'RedPanda.C++.3.4.win64.MinGW64_11.5.0.Setup.exe' -Url 'https://sourceforge.net/projects/redpanda-cpp/files/v3.4/RedPanda.C++.3.4.win64.MinGW64_11.5.0.Setup.exe/download' -UseSourceForgeMetaRefresh
    $Info = Get-NSISInfo -Path $Fixture
    $IsElectronBuilder = Test-ElectronBuilder -Path $Fixture

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be 'Red Panda C++ (x64)'
    $Info.DisplayVersion | Should -Be '3.4'
    $Info.ProductCode | Should -Be 'RedPanda-C++'
    $Info.Publisher | Should -Be 'Roy Qu (royqh1979@gmail.com)'
    $IsElectronBuilder | Should -BeFalse
  }

  It 'Should read CCFLink metadata and reject nested command switches' {
    $Fixture = Get-InstallerFixture -Name 'CCFLink_v7.7.0.80131.exe' -Url 'https://exclusive-app-cdn.dingtalk.com/CCFLink_v7.7.0.80131.exe'
    $Info = Get-NSISInfo -Path $Fixture
    $SwitchInfo = Get-NSISInstallerSwitchInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be 'CCFLink'
    $Info.DisplayVersion | Should -Be '7.7.0-Release.80131'
    $Info.ProductCode | Should -Be 'CCFLink'
    $Info.Scope | Should -Be 'machine'
    $SwitchInfo.AdditionalSwitches | Should -BeNullOrEmpty
    $SwitchInfo.RejectedSwitchCandidates.Switch | Should -Contain '/IM'
  }

  It 'Should detect the electron-builder Bitwarden portable launcher' {
    $Fixture = Get-InstallerFixture `
      -Name 'Bitwarden-Portable-2026.6.1.exe' `
      -Url 'https://github.com/bitwarden/clients/releases/download/desktop-v2026.6.1/Bitwarden-Portable-2026.6.1.exe' `
      -Sha256 'ECE0E69AE6907564364A8E4B99FB8CB95BE23DC418201871CFA69B11967DAC53'
    $Info = Get-NSISInfo -Path $Fixture
    $ElectronBuilderInfo = Get-ElectronBuilderNSISInfo -Path $Fixture

    $Info.IsPortable | Should -BeTrue
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
    $Info.DefaultInstallLocation | Should -BeNullOrEmpty
    $Info.PortableEvidence | Should -Contain 'EnvironmentVariable:PORTABLE_EXECUTABLE_DIR'
    $Info.PortableEvidence | Should -Contain 'EnvironmentVariable:PORTABLE_EXECUTABLE_FILE'
    $Info.PortableEvidence | Should -Contain 'EnvironmentVariable:PORTABLE_EXECUTABLE_APP_FILENAME'
    $Info.PortableEvidence | Should -Contain 'NoAppsAndFeaturesEntry'
    @($Info.Diagnostics | Where-Object Kind -NE Information) | Should -HaveCount 1
    $Info.Diagnostics.Message | Should -Match 'portable launcher'
    $ElectronBuilderInfo.IsElectronBuilder | Should -BeTrue
    $ElectronBuilderInfo.IsPortable | Should -BeTrue
    $ElectronBuilderInfo.Evidence.PortableEvidence | Should -Contain 'NoAppsAndFeaturesEntry'
  }

  It 'Should repair Tencent Meeting paths after its custom directory page' {
    $Fixture = Get-InstallerFixture `
      -Name 'TencentMeeting_0300000000_3.44.10.457_x86_64.publish.exe' `
      -Url 'https://updatecdn.meeting.qq.com/cos/a2bf9c01f76b1df44383ab2f529bec13/TencentMeeting_0300000000_3.44.10.457_x86_64.publish.exe' `
      -Sha256 '91C02F0877B83052B4D2C0C20736ED1CA6DBC64F5FB09DA3911A5DE91A51BD93'
    $Info = Get-NSISInfo -Path $Fixture -Architecture x64
    $InstallRoot = '%ProgramFiles%\Tencent\WeMeet'

    $Info.ProductCode | Should -Be 'WeMeet'
    $Info.DisplayName | Should -Be 'Tencent Meeting'
    $Info.DisplayVersion | Should -Be '3.44.10.457'
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles%\Tencent\WeMeet\3.44.10.457'
    $Info.UninstallString | Should -Be "`"$InstallRoot\3.44.10.457\WeMeetUninstall.exe`""
    $Info.DisplayIcon | Should -Be "`"$InstallRoot\WeMeetApp.exe`""
    $Info.Scope | Should -Be 'machine'
    @($Info.Diagnostics | Where-Object Kind -NE Information) | Should -BeNullOrEmpty
  }

  It 'Should resolve GoTo electron-builder uninstall commands from StrCpy assignments' {
    $Fixture = Get-InstallerFixture `
      -Name 'GoToSetup-4.19.1.exe' `
      -Url 'https://goto-desktop.goto.com/GoToSetup-4.19.1.exe' `
      -Sha256 '6EF77AB5904A7FEDDA696F54AA346BDE535537D85D9F09DC8A6C321CEE1BDF41'
    $Info = Get-NSISInfo -Path $Fixture
    $InstallRoot = '%LocalAppData%\Programs\goto'

    $Info.ProductCode | Should -Be 'b5746384-3503-4fbf-824a-0a42d1bd0639'
    $Info.DisplayName | Should -Be 'GoTo 4.19.1'
    $Info.DisplayVersion | Should -Be '4.19.1'
    $Info.DefaultInstallLocation | Should -Be '%LocalAppData%\Programs\goto'
    $Info.UninstallString | Should -Be "`"$InstallRoot\Uninstall GoTo.exe`" /currentuser"
    $Info.QuietUninstallString | Should -Be "`"$InstallRoot\Uninstall GoTo.exe`" /currentuser /S"
    $Info.DisplayIcon | Should -Be "$InstallRoot\GoTo.exe,0"
    $Info.Scope | Should -Be 'user'
    @($Info.Diagnostics | Where-Object Kind -NE Information) | Should -BeNullOrEmpty
  }

  It 'Should read NetEase UU Remote metadata from a vendor LZMA2 NSIS header' {
    $Fixture = Get-InstallerFixture -Name 'UURemote_Setup_4.34.0.8979.exe' `
      -Url 'https://a56.gdl.netease.com/UURemote_Setup_4.34.0.8979_0723104500_gwqd.exe' `
      -Sha256 '237EB74939A62935AE3E2B1FD43C484D634CCD96FB1094BA764C8CB64065DC9A'
    $Info = Get-NSISInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be 'UU远程'
    $Info.DisplayVersion | Should -Be '4.34.0.8979'
    $Info.ProductCode | Should -Be 'GameViewer'
    $Info.Publisher | Should -Be 'Netease'
    $Info.Scope | Should -Be 'user'
    $Info.ParserVersionInfo.HasComponentPage | Should -BeFalse
    $Info.ParserVersionInfo.UnresolvedProcessPredicates | Should -Contain 'GameViewer.exe'
    @($Info.Diagnostics | Where-Object Kind -NE Information) | Should -BeNullOrEmpty
  }

  It 'Should validate a vendor-replaced first-header signature through NSIS stub and CRC evidence' {
    $Fixture = Get-InstallerFixture -Name '115br_v36.0.1.exe' `
      -Url 'https://down.115.com/client/win/115br_v36.0.1.exe' `
      -Sha256 'CE016B4A56FAC2CAF6DBC09009782D744F98C75B928CB42DE07A4BFD7E78A719'
    $Info = Get-NSISInfo -Path $Fixture -Architecture x86

    $Info.InstallerType | Should -Be 'Nullsoft'
    $Info.DisplayName | Should -Be '115浏览器'
    $Info.Scope | Should -Be 'user'
    $Info.ParserVersionInfo.FirstHeaderSignatureRoute | Should -Be 'validated-custom-nsis-stub'
    $Info.ParserVersionInfo.FirstHeaderSignature | Should -Be '450819A7653F0D988381E4AD3F731726'
    $Info.ParserVersionInfo.StubManifestIdentity | Should -Be 'Nullsoft.NSIS.exehead'
    $Info.ParserVersionInfo.StubCompilerVersion | Should -Be '2.46.5-Unicode'
    $Info.ParserVersionInfo.ExtensionOperandSampleTruncated | Should -BeTrue
    @($Info.ParserVersionInfo.IgnoredExtensionOperands).Count | Should -BeLessOrEqual 128
    @($Info.Diagnostics | Where-Object Kind -NE Information) | Should -BeNullOrEmpty
  }

  It 'Should terminate vivo NSISBI drive enumeration without treating compiler padding as extensions' {
    $Fixture = Get-InstallerFixture -Name 'vivo-OfficeKit-6.7.3.0.exe' `
      -Url 'https://pcsuite-api-static.vivo.com/upgrade-pre/pcsuite_upgrade_v6.7.3.0-cn_1783682219434.exe' `
      -Sha256 'FE2DBCBA4CC3728FDEB76DC7B6A2EE107B977B9C9D3807C54EDD419F88FCF559'
    $Info = Get-NSISInfo -Path $Fixture -Architecture x64 -Scope machine

    $Info.ProductCode | Should -Be 'pcsuite'
    $Info.DisplayName | Should -Be 'vivo办公套件'
    $Info.DisplayVersion | Should -Be '6.7.3.0'
    $Info.Scope | Should -Be 'machine'
    $Info.ParserVersionInfo.IsNsisBi | Should -BeTrue
    $Info.ParserVersionInfo.IgnoredExtensionOperandCount | Should -Be 0
    $Info.Diagnostics.Message | Should -Not -Match 'execution budget|vendor-extension operand'
    @($Info.Diagnostics | Where-Object Kind -NE Information) | Should -BeNullOrEmpty
  }
}
