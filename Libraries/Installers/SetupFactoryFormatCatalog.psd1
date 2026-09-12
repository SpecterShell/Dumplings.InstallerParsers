# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# Format sources: sfextract and defactory. Release identity is deliberately
# separate from the physical archive profile because projects can replace the
# outer launcher's version resource.
@{
  CatalogVersion = 1
  Profiles       = @{
    Classic4    = @{
      Id               = 'setup-factory-4'
      FormatGeneration = 'Classic4'
      ReleaseRange     = '4.x and one observed early 5.x runtime'
      RuntimeMajors    = @(4, 5)
      RuntimeProducts  = @('^Indigo Rose Corporation Setup$', '^Setup Factory 5\.0 Runtime Module setup32$')
      RuntimeFiles     = @('^(?:irsetup|setup|setup32)\.exe$')
      HeaderRoute      = 'classic-count-in-signature'
      MetadataRoute    = 'irdat-v4'
      PayloadRoute     = 'pkware-implode-v4'
      IsSupported      = $true
      SupportsMetadata = $true
    }
    Legacy5     = @{
      Id               = 'setup-factory-5'
      FormatGeneration = 'Legacy5'
      ReleaseRange     = '5.x'
      RuntimeMajors    = @(5)
      RuntimeProducts  = @('^Setup Factory 5\.0 Runtime Module setup32$')
      RuntimeFiles     = @('^setup32\.exe$')
      HeaderRoute      = 'legacy-u32-count'
      MetadataRoute    = 'irdat-v5'
      PayloadRoute     = 'pkware-implode-v5'
      IsSupported      = $true
      SupportsMetadata = $true
    }
    Legacy6     = @{
      Id               = 'setup-factory-6'
      FormatGeneration = 'Legacy6'
      ReleaseRange     = '6.x'
      RuntimeMajors    = @(6)
      RuntimeProducts  = @('^Setup Factory 6\.0 Runtime Module$')
      RuntimeFiles     = @('^SUF60Runtime\.exe$')
      HeaderRoute      = 'legacy-u32-count'
      MetadataRoute    = 'irdat-v6'
      PayloadRoute     = 'pkware-implode-v6'
      IsSupported      = $true
      SupportsMetadata = $true
    }
    Modern7     = @{
      Id               = 'setup-factory-7'
      FormatGeneration = 'Modern7'
      ReleaseRange     = '7.x'
      RuntimeMajors    = @(7)
      RuntimeProducts  = @('^Setup Factory 7\.0 Runtime$')
      RuntimeFiles     = @('^suf70_rt\.exe$')
      HeaderRoute      = 'single-signature-runtime-u32'
      MetadataRoute    = 'irdat-v7'
      PayloadRoute     = 'pkware-implode-v7'
      IsSupported      = $true
      SupportsMetadata = $true
    }
    Modern8Plus = @{
      Id               = 'setup-factory-8-plus'
      FormatGeneration = 'Modern8Plus'
      ReleaseRange     = '8.x-10.x'
      RuntimeMajors    = @(8, 9, 10)
      RuntimeProducts  = @('^Setup Factory 8\.0 Runtime$', '^Setup Factory Runtime$')
      RuntimeFiles     = @('^suf80_rt\.exe$', '^suf_rt\.exe$')
      HeaderRoute      = 'doubled-signature-runtime-i64'
      MetadataRoute    = 'irdat-v8-plus'
      PayloadRoute     = 'lzma-pkware-v8-plus'
      IsSupported      = $true
      SupportsMetadata = $true
    }
  }
}
