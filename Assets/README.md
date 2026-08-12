# InstallerParsers Assets

InstallerParsers uses the same purpose-based asset layout as PackageModule while
remaining independently consumable under its own file-specific licenses.

- `Assemblies` contains pinned third-party managed assemblies loaded at runtime.
- `Licenses` contains complete upstream license and dependency notice texts.
- `Source` contains auditable C# compiled in process with `Add-Type`, grouped by
  shared infrastructure or installer family.
- `IFPSLibAssets.psd1` pins the IFPS source revision, assembly versions, and
  hashes used by the Inno parser.
- `THIRD-PARTY-NOTICES.md` records source attribution and redistribution terms.

Load assets through their owning PowerShell module. Runtime code must not depend
on recursive asset discovery or the caller's current directory.
