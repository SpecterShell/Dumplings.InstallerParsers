# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# Format source: https://github.com/qtproject/installer-framework
#
# The catalog selects source-backed parsing routes and capabilities. Commercial
# and open-source builders emit the same structures, so no edition is inferred.
@{
  CatalogVersion        = 1
  Profiles              = @(
    @{
      Id                           = 'ifw-1.x-legacy'
      MinimumVersion               = '1.2.0'
      MaximumVersionExclusive      = '2.0.0'
      FormatGeneration             = 'LegacyComponentIndex'
      FrameworkVersionRange        = '1.2-1.x'
      TrailerRoute                 = 'legacy-component-index-v1'
      MetadataRoute                = 'rcc-meta-resources-v1'
      PackageIndexRoute            = 'component-index-v1'
      PayloadRoute                 = 'legacy-7z-v1'
      ConfigRoute                  = 'legacy-config-v1'
      InterfaceRoute               = 'gui-launcher-v1'
      VersionEvidenceRoute         = 'embedded-ifw-string-legacy'
      SupportsProductUuid          = $false
      SupportsCommandLineInterface = $false
      SupportsLibArchive           = $false
    }
    @{
      Id                           = 'ifw-2.x-3.1-binary-content'
      MinimumVersion               = '2.0.0'
      MaximumVersionExclusive      = '3.1.2'
      FormatGeneration             = 'BinaryContent'
      FrameworkVersionRange        = '2.0-3.1.1'
      TrailerRoute                 = 'resource-collections-v1'
      MetadataRoute                = 'rcc-and-resource-collections-v1'
      PackageIndexRoute            = 'resource-collection-v1'
      PayloadRoute                 = 'legacy-7z-v1'
      ConfigRoute                  = 'modern-config-v1'
      InterfaceRoute               = 'gui-launcher-v1'
      VersionEvidenceRoute         = 'embedded-ifw-string-v1'
      SupportsProductUuid          = $true
      SupportsCommandLineInterface = $false
      SupportsLibArchive           = $false
    }
    @{
      Id                           = 'ifw-3.1.2-3.x-binary-content'
      MinimumVersion               = '3.1.2'
      MaximumVersionExclusive      = '4.0.0'
      FormatGeneration             = 'BinaryContent'
      FrameworkVersionRange        = '3.1.2-3.x'
      TrailerRoute                 = 'resource-collections-v1'
      MetadataRoute                = 'rcc-and-resource-collections-v1'
      PackageIndexRoute            = 'resource-collection-v1'
      PayloadRoute                 = 'legacy-7z-v1'
      ConfigRoute                  = 'modern-config-v1'
      InterfaceRoute               = 'gui-launcher-v1'
      VersionEvidenceRoute         = 'embedded-ifw-and-pe-version-v1'
      SupportsProductUuid          = $true
      SupportsCommandLineInterface = $false
      SupportsLibArchive           = $false
    }
    @{
      Id                           = 'ifw-4.0-4.1-cli'
      MinimumVersion               = '4.0.0'
      MaximumVersionExclusive      = '4.2.0'
      FormatGeneration             = 'BinaryContent'
      FrameworkVersionRange        = '4.0-4.1'
      TrailerRoute                 = 'resource-collections-v1'
      MetadataRoute                = 'rcc-and-resource-collections-v1'
      PackageIndexRoute            = 'resource-collection-v1'
      PayloadRoute                 = 'legacy-7z-v1'
      ConfigRoute                  = 'modern-config-cli-v1'
      InterfaceRoute               = 'cli-capable-launcher-v1'
      VersionEvidenceRoute         = 'embedded-ifw-and-pe-version-v1'
      SupportsProductUuid          = $true
      SupportsCommandLineInterface = $true
      SupportsLibArchive           = $false
    }
    @{
      Id                           = 'ifw-4.2-current-libarchive'
      MinimumVersion               = '4.2.0'
      MaximumVersionExclusive      = '4.12.0'
      FormatGeneration             = 'BinaryContent'
      FrameworkVersionRange        = '4.2-4.11'
      TrailerRoute                 = 'resource-collections-v1'
      MetadataRoute                = 'rcc-and-resource-collections-v1'
      PackageIndexRoute            = 'resource-collection-v1'
      PayloadRoute                 = 'libarchive-v1'
      ConfigRoute                  = 'modern-config-cli-v1'
      InterfaceRoute               = 'cli-capable-launcher-v1'
      VersionEvidenceRoute         = 'embedded-ifw-and-pe-version-v1'
      SupportsProductUuid          = $true
      SupportsCommandLineInterface = $true
      SupportsLibArchive           = $true
    }
  )
  CompatibilityProfiles = @{
    Legacy = @{
      Id                           = 'ifw-legacy-compatible'
      FormatGeneration             = 'LegacyComponentIndex'
      FrameworkVersionRange        = '1.2-1.x'
      TrailerRoute                 = 'legacy-component-index-v1'
      MetadataRoute                = 'rcc-meta-resources-v1'
      PackageIndexRoute            = 'component-index-v1'
      PayloadRoute                 = 'legacy-7z-v1'
      ConfigRoute                  = 'legacy-config-v1'
      InterfaceRoute               = 'gui-launcher-v1'
      VersionEvidenceRoute         = 'structural-only'
      SupportsProductUuid          = $false
      SupportsCommandLineInterface = $false
      SupportsLibArchive           = $false
      IsFallback                   = $true
    }
    Modern = @{
      Id                           = 'ifw-modern-compatible'
      FormatGeneration             = 'BinaryContent'
      FrameworkVersionRange        = '2.0 or later'
      TrailerRoute                 = 'resource-collections-v1'
      MetadataRoute                = 'rcc-and-resource-collections-v1'
      PackageIndexRoute            = 'resource-collection-v1'
      PayloadRoute                 = 'libarchive-v1'
      ConfigRoute                  = 'modern-config-cli-v1'
      InterfaceRoute               = 'cli-capable-launcher-v1'
      VersionEvidenceRoute         = 'structural-only'
      SupportsProductUuid          = $true
      SupportsCommandLineInterface = $true
      SupportsLibArchive           = $true
      IsFallback                   = $true
    }
  }
}
