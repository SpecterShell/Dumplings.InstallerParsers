# License: GPL-2.0. See Modules\InstallerParsers\LICENSE.GPL2.
#
# Advanced Installer does not preserve its commercial edition in generated
# media. Profiles therefore describe serialized bootstrapper ABIs, not the
# Free, Professional, Enterprise, or Architect authoring license.
@{
  CatalogVersion         = 2

  FooterRoutes           = @{
    'footer-v1' = @{
      Magic                    = 'ADVINSTSFX'
      MagicOffset              = 64
      MinimumSize              = 74
      ExternalFileCountOffset  = 0
      EmbeddedCatalogEndOffset = 4
      EmbeddedFileCountOffset  = 8
      StructureVersionOffset   = 12
      PhysicalFooterOffset     = 16
      CatalogOffsetOffset      = 20
      PayloadOffsetOffset      = 24
      BootstrapperIdOffset     = 28
      BootstrapperIdLength     = 32
      FlagsOffset              = 60
      MaximumFileCount         = 65536
    }
  }

  CatalogRoutes          = @{
    'catalog-v0-ansi'    = @{
      FixedRecordSize     = 20
      SelectorTypeOffset  = 0
      SelectorGroupOffset = 4
      PayloadSizeOffset   = 8
      PayloadOffsetOffset = 12
      NameLengthOffset    = 16
      TransformFlagOffset = -1
      NameEncoding        = 'Windows-1252'
      NameLengthUnit      = 1
      TransformRoute      = 'payload-v0'
    }
    'catalog-v0-unicode' = @{
      FixedRecordSize     = 20
      SelectorTypeOffset  = 0
      SelectorGroupOffset = 4
      PayloadSizeOffset   = 8
      PayloadOffsetOffset = 12
      NameLengthOffset    = 16
      TransformFlagOffset = -1
      NameEncoding        = 'UTF-16LE'
      NameLengthUnit      = 2
      TransformRoute      = 'payload-v0'
    }
    'catalog-v1-unicode' = @{
      FixedRecordSize     = 24
      SelectorTypeOffset  = 0
      SelectorGroupOffset = 4
      TransformFlagOffset = 8
      PayloadSizeOffset   = 12
      PayloadOffsetOffset = 16
      NameLengthOffset    = 20
      NameEncoding        = 'UTF-16LE'
      NameLengthUnit      = 2
      TransformRoute      = 'payload-v1'
    }
  }

  ExternalResourceRoutes = @{
    'external-v1-ansi'    = @{
      FixedRecordSize  = 8
      RoleOffset       = 0
      NameLengthOffset = 4
      NameEncoding     = 'Windows-1252'
      NameLengthUnit   = 1
    }
    'external-v1-unicode' = @{
      FixedRecordSize  = 8
      RoleOffset       = 0
      NameLengthOffset = 4
      NameEncoding     = 'UTF-16LE'
      NameLengthUnit   = 2
    }
  }

  ConfigurationRoutes    = @{
    'ini-ansi-v1'    = @{ CharacterMode = 'Ansi' }
    'ini-unicode-v1' = @{ CharacterMode = 'Unicode' }
    'ini-auto-v1'    = @{ CharacterMode = 'Unknown' }
  }

  TransformRoutes        = @{
    'payload-v0' = @{
      PlainFlag           = 0
      XorHeaderFlag       = -1
      XorHeaderLength     = 0
      UnsupportedIsOpaque = $true
    }
    'payload-v1' = @{
      PlainFlag           = 0
      XorHeaderFlag       = 2
      XorHeaderLength     = 512
      UnsupportedIsOpaque = $true
    }
  }

  PayloadRoutes          = @{
    'selector-v1' = @{
      ConfigurationSelector = @(0, 3)
      DirectMsiSelector     = @(1, 0)
      ArchiveMsiSelector    = @(3, 7)
      MsixPackageSelector   = @(1, 18)
      ExternalRoleSelectors = @{
        '3' = @(0, 3)
        '6' = @(3, 6)
        '7' = @(3, 7)
      }
    }
  }

  # The native Unicode bootstrapper was introduced in Advanced Installer 6.4.
  # Exact release attribution still requires explicit compiled evidence, such
  # as the selected MSI SummaryInformation.CreatingApp value.
  Profiles               = @(
    @{
      Id                       = 'classic-ansi-v0'
      FormatGeneration         = 'ClassicAnsi'
      BuilderVersionRange      = '1.4-6.3.x'
      MinimumBuilderVersion    = '1.4'
      MaximumBuilderVersion    = '6.3.9999'
      CharacterMode            = 'Ansi'
      StructureVersions        = @(100)
      FooterRoute              = 'footer-v1'
      CatalogRoute             = 'catalog-v0-ansi'
      ExternalResourceRoute    = 'external-v1-ansi'
      ConfigurationRoute       = 'ini-ansi-v1'
      PayloadRoute             = 'selector-v1'
      TransformRoute           = 'payload-v0'
      BootstrapperIdRoute      = 'ascii-guid-v4-n'
      SupportedMediaModes      = @('EmbeddedMsi', 'EmbeddedArchive', 'ExternalResources', 'PrerequisiteBootstrapper', 'WebInstaller')
      Capabilities             = @('LzmaArchive', 'CustomExeMetadata', 'Prerequisites', 'OnlineMainPackage')
      ValidationStatus         = 'PartiallyValidated'
      ValidatedBuilderVersions = @('6.3')
      ValidationNotes          = 'The 6.3 boundary is validated with controlled media. Releases 1.4 through 6.2 remain catalog-compatible hypotheses until an official generated EXE fixture validates their footer and catalog.'
      Supported                = $true
    }
    @{
      Id                       = 'classic-unicode-v0'
      FormatGeneration         = 'ClassicUnicode'
      BuilderVersionRange      = '6.4-8.5.x'
      MinimumBuilderVersion    = '6.4'
      MaximumBuilderVersion    = '8.5.9999'
      CharacterMode            = 'Unicode'
      StructureVersions        = @(100)
      FooterRoute              = 'footer-v1'
      CatalogRoute             = 'catalog-v0-unicode'
      ExternalResourceRoute    = 'external-v1-unicode'
      ConfigurationRoute       = 'ini-unicode-v1'
      PayloadRoute             = 'selector-v1'
      TransformRoute           = 'payload-v0'
      BootstrapperIdRoute      = 'ascii-guid-v4-n'
      SupportedMediaModes      = @('EmbeddedMsi', 'EmbeddedArchive', 'ExternalResources', 'PrerequisiteBootstrapper', 'WebInstaller', 'MsiMsixPlatformSelection')
      Capabilities             = @('UnicodeBootstrapper', 'MixedX86X64', 'LzmaArchive', 'CustomExeMetadata', 'Prerequisites', 'OnlineMainPackage')
      ValidationStatus         = 'Validated'
      ValidatedBuilderVersions = @('6.4')
      ValidationNotes          = 'Controlled 6.4 embedded and external media validate this route.'
      Supported                = $true
    }
    @{
      Id                       = 'classic-unicode-v1'
      FormatGeneration         = 'ClassicUnicode'
      BuilderVersionRange      = '8.6-23.9'
      MinimumBuilderVersion    = '8.6'
      MaximumBuilderVersion    = '23.9.9999'
      CharacterMode            = 'Unicode'
      StructureVersions        = @(100)
      FooterRoute              = 'footer-v1'
      CatalogRoute             = 'catalog-v1-unicode'
      ExternalResourceRoute    = 'external-v1-unicode'
      ConfigurationRoute       = 'ini-unicode-v1'
      PayloadRoute             = 'selector-v1'
      TransformRoute           = 'payload-v1'
      BootstrapperIdRoute      = 'ascii-guid-v4-n'
      SupportedMediaModes      = @('EmbeddedMsi', 'EmbeddedArchive', 'ExternalResources', 'PrerequisiteBootstrapper', 'WebInstaller', 'MsiMsixPlatformSelection')
      Capabilities             = @('UnicodeBootstrapper', 'MixedX86X64', 'LzmaArchive', 'AesArchive', 'Arm64Payload', 'CustomExeMetadata', 'Prerequisites', 'OnlineMainPackage')
      ValidationStatus         = 'Validated'
      ValidatedBuilderVersions = @('8.6', '10.3', '23.9')
      ValidationNotes          = 'Controlled 8.6 and 23.9 media plus Advanced Installer 10.3 vendor media validate this route.'
      Supported                = $true
    }
  )

  CompatibilityProfile   = @{
    Id                       = 'classic-compatible-v1'
    FormatGeneration         = 'ClassicCompatible'
    BuilderVersionRange      = 'Unknown Advanced Installer release'
    CharacterMode            = 'Unknown'
    StructureVersions        = @()
    FooterRoute              = 'footer-v1'
    CatalogRoute             = 'catalog-v1-unicode'
    ExternalResourceRoute    = 'external-v1-unicode'
    ConfigurationRoute       = 'ini-auto-v1'
    PayloadRoute             = 'selector-v1'
    TransformRoute           = 'payload-v1'
    BootstrapperIdRoute      = 'ascii-guid-v4-n'
    SupportedMediaModes      = @()
    Capabilities             = @()
    ValidationStatus         = 'Fallback'
    ValidatedBuilderVersions = @()
    ValidationNotes          = 'A future layout is accepted only after complete structural validation; no release attribution is inferred.'
    Supported                = $true
    IsFallback               = $true
  }
}
