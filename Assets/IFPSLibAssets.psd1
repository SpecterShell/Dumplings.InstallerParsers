# License: GPL-3.0-or-later. This metadata describes redistributed MIT/BSD assets.
@{
  SourceRepository = 'https://github.com/Wack0/IFPSTools.NET.git'
  SourceCommit     = '5c56d48f5d56da8ada888bff08de80058cf9d531'
  TestedDotNetSdk  = '10.0.302'
  Assemblies       = @(
    @{
      Name     = 'NativeMemoryArray.dll'
      TypeName = 'Cysharp.Collections.ThrowHelper'
      Version  = '1.2.0.0'
      Sha256   = '85B19183F5C78CBF78428FE5D5217CDAC58D82CDF6CBEA313952A9DDC3C9758E'
    }
    @{
      Name     = 'SharpFloat.dll'
      TypeName = 'SharpFloat.FloatingPoint.ExtF80'
      Version  = '1.0.4.0'
      Sha256   = 'EE8289EC20C8BB836739FBE9EB357928E34AD20A0F72EDD3897A5F56CEEED7D8'
    }
    @{
      Name     = 'IFPSLib.dll'
      TypeName = 'IFPSLib.Script'
      Version  = '1.0.0.0'
      Sha256   = 'B3EACCBD2BE80BFD1491379CD3B3911FB976EAAB8D5851552E5BE07A0475B0F9'
    }
  )
}
