# Third-Party Notices

## sfextract

Source: <https://github.com/CybercentreCanada/sfextract>

License: MIT.

Setup Factory overlay, entry-table, compression-marker, and script-record behavior was studied for the GPL Setup Factory parser. No Python code or executable is included or required.

## SFUnpacker

Source: <https://github.com/Puyodead1/SFUnpacker>

License: LGPL-3.0-or-later.

Setup Factory 9 format behavior was studied as an additional independent reference. SFUnpacker is not included or required at runtime.

## blast / zlib

Source: <https://github.com/madler/zlib/tree/master/contrib/blast>

License: zlib.

The Setup Factory 7 PKWARE implode decoder in
`Assets/Source/SetupFactory/PkwareBlast.cs` is an altered, bounded C#
implementation derived from the public `blast` algorithm. It validates headers,
Huffman codes, back-references, end markers, and expanded-output limits. No
external decoder is invoked.

## SharpCompress

Source: <https://github.com/adamhathcock/sharpcompress>

Version: 0.39.0. License: MIT.

The raw NSIS BZip2 decoder in `Assets/Source/NSIS/NsisBZip2Stream.cs`
adapts SharpCompress's Apache Ant-derived BZip2 decoder under Apache-2.0. Its
stream framing was changed to match the NSIS `Source/bzip2` implementation;
standard BZip2 headers and CRC fields are not accepted or synthesized.

## ZstdSharp.Port

Source: <https://github.com/oleg-st/ZstdSharp>

Version: 0.8.4. License: MIT.

## IFPSTools.NET / IFPSLib

Source: <https://github.com/Wack0/IFPSTools.NET>

Commit: `5c56d48f5d56da8ada888bff08de80058cf9d531`. License: MIT.

The pinned `IFPSLib.dll` is built from this revision and is used to read and
disassemble the `CompiledCodeText` Pascal Script program in Inno Setup headers.
Only structural bytecode evidence is consumed; the assembler and compiler tools
are not included. The upstream license is distributed as
`Assets/Licenses/IFPSTools.NET.txt`.

IFPSLib's pinned `NativeMemoryArray` 1.2.0 and `SharpFloatLibrary` 1.0.4 runtime
dependencies are distributed beside it. Their complete notices are in
`Assets/Licenses/IFPSLibDependencies.txt`.

`Assets/IFPSLibAssets.psd1` records the source revision, assembly versions, and
SHA-256 values. `Utilities/Update-IFPSLibAssets.ps1` rebuilds that revision and
checks the redistributed files without running an installer or bytecode.
