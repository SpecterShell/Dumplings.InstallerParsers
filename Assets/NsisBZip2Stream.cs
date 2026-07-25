// SPDX-License-Identifier: Apache-2.0
//
// This decoder is adapted from SharpCompress's Apache Ant-derived BZip2
// implementation. It is specialized for the raw BZip2 framing emitted by
// NSIS Source/bzip2/compress.c and intentionally does not accept standard
// BZh streams.
//
// NSIS raw BZip2 stream (bit fields are MSB-first):
//
// +----------------------+ record-relative offset 0
// | Marker 0x31          | 1 byte
// +----------------------+
// | origPtr              | 24-bit unsigned big-endian
// +----------------------+
// | Mapping/Huffman/MTF  | variable bit stream
// +----------------------+
// | Next 0x31 or 0x17    | byte-aligned block/end marker
// +----------------------+
//
// Standard BZip2's BZh header, six-byte block signatures, randomization bit,
// block CRC, end signature, and combined CRC are absent. NSIS fixes the
// maximum block allocation to compression level 9 (900,000 bytes).
//
// References:
// - https://github.com/kichik/nsis/tree/master/Source/bzip2
// - https://github.com/adamhathcock/sharpcompress/tree/master/src/SharpCompress/Compressors/BZip2
//
// SharpCompress / Apache Ant BZip2 decoder notices:
//
// Copyright 2001,2004-2005 The Apache Software Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This package is based on work by Keiron Liddle, Aftex Software.
using System;
using System.IO;

namespace Dumplings.InstallerParsers.NSIS
{
internal class BZip2Constants
{
    public const int baseBlockSize = 100000;
    public const int MAX_ALPHA_SIZE = 258;
    public const int MAX_CODE_LEN = 23;
    public const int RUNA = 0;
    public const int RUNB = 1;
    public const int N_GROUPS = 6;
    public const int G_SIZE = 50;
    public const int N_ITERS = 4;
    public const int MAX_SELECTORS = (2 + (900000 / G_SIZE));
    public const int NUM_OVERSHOOT_BYTES = 20;

    public static int[] rNums =
    {
        619,
        720,
        127,
        481,
        931,
        816,
        813,
        233,
        566,
        247,
        985,
        724,
        205,
        454,
        863,
        491,
        741,
        242,
        949,
        214,
        733,
        859,
        335,
        708,
        621,
        574,
        73,
        654,
        730,
        472,
        419,
        436,
        278,
        496,
        867,
        210,
        399,
        680,
        480,
        51,
        878,
        465,
        811,
        169,
        869,
        675,
        611,
        697,
        867,
        561,
        862,
        687,
        507,
        283,
        482,
        129,
        807,
        591,
        733,
        623,
        150,
        238,
        59,
        379,
        684,
        877,
        625,
        169,
        643,
        105,
        170,
        607,
        520,
        932,
        727,
        476,
        693,
        425,
        174,
        647,
        73,
        122,
        335,
        530,
        442,
        853,
        695,
        249,
        445,
        515,
        909,
        545,
        703,
        919,
        874,
        474,
        882,
        500,
        594,
        612,
        641,
        801,
        220,
        162,
        819,
        984,
        589,
        513,
        495,
        799,
        161,
        604,
        958,
        533,
        221,
        400,
        386,
        867,
        600,
        782,
        382,
        596,
        414,
        171,
        516,
        375,
        682,
        485,
        911,
        276,
        98,
        553,
        163,
        354,
        666,
        933,
        424,
        341,
        533,
        870,
        227,
        730,
        475,
        186,
        263,
        647,
        537,
        686,
        600,
        224,
        469,
        68,
        770,
        919,
        190,
        373,
        294,
        822,
        808,
        206,
        184,
        943,
        795,
        384,
        383,
        461,
        404,
        758,
        839,
        887,
        715,
        67,
        618,
        276,
        204,
        918,
        873,
        777,
        604,
        560,
        951,
        160,
        578,
        722,
        79,
        804,
        96,
        409,
        713,
        940,
        652,
        934,
        970,
        447,
        318,
        353,
        859,
        672,
        112,
        785,
        645,
        863,
        803,
        350,
        139,
        93,
        354,
        99,
        820,
        908,
        609,
        772,
        154,
        274,
        580,
        184,
        79,
        626,
        630,
        742,
        653,
        282,
        762,
        623,
        680,
        81,
        927,
        626,
        789,
        125,
        411,
        521,
        938,
        300,
        821,
        78,
        343,
        175,
        128,
        250,
        170,
        774,
        972,
        275,
        999,
        639,
        495,
        78,
        352,
        126,
        857,
        956,
        358,
        619,
        580,
        124,
        737,
        594,
        701,
        612,
        669,
        112,
        134,
        694,
        363,
        992,
        809,
        743,
        168,
        974,
        944,
        375,
        748,
        52,
        600,
        747,
        642,
        182,
        862,
        81,
        344,
        805,
        988,
        739,
        511,
        655,
        814,
        334,
        249,
        515,
        897,
        955,
        664,
        981,
        649,
        113,
        974,
        459,
        893,
        228,
        433,
        837,
        553,
        268,
        926,
        240,
        102,
        654,
        459,
        51,
        686,
        754,
        806,
        760,
        493,
        403,
        415,
        394,
        687,
        700,
        946,
        670,
        656,
        610,
        738,
        392,
        760,
        799,
        887,
        653,
        978,
        321,
        576,
        617,
        626,
        502,
        894,
        679,
        243,
        440,
        680,
        879,
        194,
        572,
        640,
        724,
        926,
        56,
        204,
        700,
        707,
        151,
        457,
        449,
        797,
        195,
        791,
        558,
        945,
        679,
        297,
        59,
        87,
        824,
        713,
        663,
        412,
        693,
        342,
        606,
        134,
        108,
        571,
        364,
        631,
        212,
        174,
        643,
        304,
        329,
        343,
        97,
        430,
        751,
        497,
        314,
        983,
        374,
        822,
        928,
        140,
        206,
        73,
        263,
        980,
        736,
        876,
        478,
        430,
        305,
        170,
        514,
        364,
        692,
        829,
        82,
        855,
        953,
        676,
        246,
        369,
        970,
        294,
        750,
        807,
        827,
        150,
        790,
        288,
        923,
        804,
        378,
        215,
        828,
        592,
        281,
        565,
        555,
        710,
        82,
        896,
        831,
        547,
        261,
        524,
        462,
        293,
        465,
        502,
        56,
        661,
        821,
        976,
        991,
        658,
        869,
        905,
        758,
        745,
        193,
        768,
        550,
        608,
        933,
        378,
        286,
        215,
        979,
        792,
        961,
        61,
        688,
        793,
        644,
        986,
        403,
        106,
        366,
        905,
        644,
        372,
        567,
        466,
        434,
        645,
        210,
        389,
        550,
        919,
        135,
        780,
        773,
        635,
        389,
        707,
        100,
        626,
        958,
        165,
        504,
        920,
        176,
        193,
        713,
        857,
        265,
        203,
        50,
        668,
        108,
        645,
        990,
        626,
        197,
        510,
        357,
        358,
        850,
        858,
        364,
        936,
        638,
    };
}

public sealed class NsisBZip2Stream : Stream
{
    private static void Cadvise()
    {
        //System.out.Println("CRC Error");
        throw new InvalidDataException("BZip2 error");
    }

    private static void BadBGLengths() => Cadvise();

    private static void BitStreamEOF() => Cadvise();

    private static void CompressedStreamEOF()
    {
        throw new InvalidDataException("BZip2 compressed file ends unexpectedly");
    }

    // Handles the underlying stream running out while BsR needs more bits. In tolerateTruncatedStream
    // mode an EOF that lands on a block boundary (expectingBlockStart) ends the stream cleanly; anywhere
    // else - or when not tolerating truncation - it is an unexpected truncation and throws.
    private void HandleCompressedStreamEof()
    {
        CompressedStreamEOF();
    }
    private void MakeMaps()
    {
        int i;
        nInUse = 0;
        for (i = 0; i < 256; i++)
        {
            if (inUse[i])
            {
                seqToUnseq[nInUse] = (char)i;
                unseqToSeq[i] = (char)nInUse;
                nInUse++;
            }
        }
    }

    /*
    index of the last char in the block, so
    the block size == last + 1.
    */
    private int last;

    /*
    index in zptr[] of original string after sorting.
    */
    private int origPtr;

    /*
    always: in the range 0 .. 9.
    The current block size is 100000 * this number.
    */
    private int blockSize100k;

    private bool blockRandomised;

    private int bsBuff;
    private int bsLive;

    private readonly bool[] inUse = new bool[256];
    private int nInUse;

    private readonly char[] seqToUnseq = new char[256];
    private readonly char[] unseqToSeq = new char[256];

    private readonly char[] selector = new char[BZip2Constants.MAX_SELECTORS];
    private readonly char[] selectorMtf = new char[BZip2Constants.MAX_SELECTORS];

    private int[] tt;
    private char[] ll8;

    /*
    freq table collected to save a pass over the data
    during decompression.
    */
    private readonly int[] unzftab = new int[256];

    private readonly int[][] limit = InitIntArray(
        BZip2Constants.N_GROUPS,
        BZip2Constants.MAX_ALPHA_SIZE
    );
    private readonly int[][] basev = InitIntArray(
        BZip2Constants.N_GROUPS,
        BZip2Constants.MAX_ALPHA_SIZE
    );
    private readonly int[][] perm = InitIntArray(
        BZip2Constants.N_GROUPS,
        BZip2Constants.MAX_ALPHA_SIZE
    );
    private readonly int[] minLens = new int[BZip2Constants.N_GROUPS];

    private Stream bsStream;

    private bool streamEnd;

    private int currentChar = -1;

    private const int START_BLOCK_STATE = 1;
    private const int RAND_PART_A_STATE = 2;
    private const int RAND_PART_B_STATE = 3;
    private const int RAND_PART_C_STATE = 4;
    private const int NO_RAND_PART_A_STATE = 5;
    private const int NO_RAND_PART_B_STATE = 6;
    private const int NO_RAND_PART_C_STATE = 7;

    private int currentState = START_BLOCK_STATE;
    private readonly bool leaveOpen;

    private int i2,
        count,
        chPrev,
        ch2;
    private int i,
        tPos;
    private int rNToGo;
    private int rTPos;
    private int j2;
    private char z;
    private bool isDisposed;

    private NsisBZip2Stream(bool leaveOpen)
    {
        this.leaveOpen = leaveOpen;
    }

    /// <summary>
    /// Creates a forward-only decoder over an NSIS raw BZip2 stream.
    /// </summary>
    /// <param name="stream">Stream positioned at the first 0x31 block marker.</param>
    /// <param name="leaveOpen">Whether disposing the decoder leaves the compressed stream open.</param>
    public static NsisBZip2Stream Create(Stream stream, bool leaveOpen)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var decoder = new NsisBZip2Stream(leaveOpen);
        decoder.SetDecompressStructureSizes(9);
        decoder.BsSetStream(stream);
        decoder.InitBlock();
        if (!decoder.streamEnd)
        {
            decoder.SetupBlock();
        }
        return decoder;
    }
    protected override void Dispose(bool disposing)
    {
        if (isDisposed || leaveOpen)
        {
            return;
        }
        isDisposed = true;
        base.Dispose(disposing);
        bsStream?.Dispose();
    }

    internal static int[][] InitIntArray(int n1, int n2)
    {
        var a = new int[n1][];
        for (var k = 0; k < n1; ++k)
        {
            a[k] = new int[n2];
        }
        return a;
    }

    internal static char[][] InitCharArray(int n1, int n2)
    {
        var a = new char[n1][];
        for (var k = 0; k < n1; ++k)
        {
            a[k] = new char[n2];
        }
        return a;
    }

    public override int ReadByte()
    {
        if (streamEnd)
        {
            return -1;
        }
        var retChar = currentChar;
        switch (currentState)
        {
            case START_BLOCK_STATE:
                break;
            case RAND_PART_A_STATE:
                break;
            case RAND_PART_B_STATE:
                SetupRandPartB();
                break;
            case RAND_PART_C_STATE:
                SetupRandPartC();
                break;
            case NO_RAND_PART_A_STATE:
                break;
            case NO_RAND_PART_B_STATE:
                SetupNoRandPartB();
                break;
            case NO_RAND_PART_C_STATE:
                SetupNoRandPartC();
                break;
            default:
                break;
        }
        return retChar;
    }

    private void InitBlock()
    {
        int marker = BsR(8);
        if (marker == 0x17)
        {
            BsFinishedWithStream();
            streamEnd = true;
            currentChar = -1;
            return;
        }
        if (marker != 0x31)
        {
            throw new InvalidDataException($"Invalid NSIS BZip2 block marker 0x{marker:X2}.");
        }

        // NSIS writes origPtr and the Huffman/MTF payload directly after this marker.
        // It omits the standard six-byte signature, CRC, and randomization flag.
        blockRandomised = false;
        GetAndMoveToFrontDecode();
        currentState = START_BLOCK_STATE;
    }
    private void EndBlock()
    {
        // NSIS omits the per-block and combined CRC fields used by standard BZip2.
    }
    private static void BlockOverrun() => Cadvise();

    private static void BadBlockHeader() => Cadvise();

    private void BsFinishedWithStream()
    {
        if (!leaveOpen)
        {
            bsStream?.Dispose();
        }
        bsStream = null;
    }

    private void BsSetStream(Stream f)
    {
        bsStream = f;
        bsLive = 0;
        bsBuff = 0;
    }

    private int BsR(int n)
    {
        while (bsLive < n)
        {
            int next = bsStream?.ReadByte() ?? -1;
            if (next < 0)
            {
                CompressedStreamEOF();
            }
            bsBuff = (bsBuff << 8) | (next & 0xff);
            bsLive += 8;
        }

        int value = (bsBuff >> (bsLive - n)) & ((1 << n) - 1);
        bsLive -= n;
        return value;
    }
    private char BsGetUChar() => (char)BsR(8);

    private int BsGetint()
    {
        var u = 0;
        u = (u << 8) | BsR(8);
        u = (u << 8) | BsR(8);
        u = (u << 8) | BsR(8);
        u = (u << 8) | BsR(8);
        return u;
    }

    private int BsGetIntVS(int numBits) => BsR(numBits);

    private int BsGetInt32() => BsGetint();

    private void HbCreateDecodeTables(
        int[] limit,
        int[] basev,
        int[] perm,
        char[] length,
        int minLen,
        int maxLen,
        int alphaSize
    )
    {
        int pp,
            i,
            j,
            vec;

        pp = 0;
        for (i = minLen; i <= maxLen; i++)
        {
            for (j = 0; j < alphaSize; j++)
            {
                if (length[j] == i)
                {
                    perm[pp] = j;
                    pp++;
                }
            }
        }

        for (i = 0; i < BZip2Constants.MAX_CODE_LEN; i++)
        {
            basev[i] = 0;
        }
        for (i = 0; i < alphaSize; i++)
        {
            if (length[i] >= BZip2Constants.MAX_CODE_LEN)
            {
                throw new InvalidDataException("BZip2: invalid Huffman code length");
            }
            basev[length[i] + 1]++;
        }

        for (i = 1; i < BZip2Constants.MAX_CODE_LEN; i++)
        {
            basev[i] += basev[i - 1];
        }

        for (i = 0; i < BZip2Constants.MAX_CODE_LEN; i++)
        {
            limit[i] = 0;
        }
        vec = 0;

        for (i = minLen; i <= maxLen; i++)
        {
            vec += (basev[i + 1] - basev[i]);
            limit[i] = vec - 1;
            vec <<= 1;
        }
        for (i = minLen + 1; i <= maxLen; i++)
        {
            basev[i] = ((limit[i - 1] + 1) << 1) - basev[i];
        }
    }

    private void RecvDecodingTables()
    {
        var len = InitCharArray(BZip2Constants.N_GROUPS, BZip2Constants.MAX_ALPHA_SIZE);
        int i,
            j,
            t,
            nGroups,
            nSelectors,
            alphaSize;
        int minLen,
            maxLen;
        var inUse16 = new bool[16];

        /* Receive the mapping table */
        for (i = 0; i < 16; i++)
        {
            if (BsR(1) == 1)
            {
                inUse16[i] = true;
            }
            else
            {
                inUse16[i] = false;
            }
        }

        for (i = 0; i < 256; i++)
        {
            inUse[i] = false;
        }

        for (i = 0; i < 16; i++)
        {
            if (inUse16[i])
            {
                for (j = 0; j < 16; j++)
                {
                    if (BsR(1) == 1)
                    {
                        inUse[(i * 16) + j] = true;
                    }
                }
            }
        }

        MakeMaps();
        alphaSize = nInUse + 2;

        /* Now the selectors */
        nGroups = BsR(3);
        if (nGroups < 2 || nGroups > BZip2Constants.N_GROUPS)
        {
            throw new InvalidDataException("BZip2: invalid number of Huffman trees");
        }
        nSelectors = BsR(15);
        for (i = 0; i < nSelectors; i++)
        {
            j = 0;
            while (BsR(1) == 1)
            {
                j++;
                if (j >= nGroups)
                {
                    throw new InvalidDataException("BZip2: invalid selector MTF value");
                }
            }
            if (i < BZip2Constants.MAX_SELECTORS)
            {
                selectorMtf[i] = (char)j;
            }
        }

        nSelectors = Math.Min(nSelectors, BZip2Constants.MAX_SELECTORS);

        /* Undo the MTF values for the selectors. */
        {
            var pos = new char[BZip2Constants.N_GROUPS];
            char tmp,
                v;
            for (v = '\0'; v < nGroups; v++)
            {
                pos[v] = v;
            }

            for (i = 0; i < nSelectors; i++)
            {
                v = selectorMtf[i];
                if (v >= nGroups)
                {
                    throw new InvalidDataException("BZip2: selector MTF value out of range");
                }
                tmp = pos[v];
                while (v > 0)
                {
                    pos[v] = pos[v - 1];
                    v--;
                }
                pos[0] = tmp;
                selector[i] = tmp;
            }
        }

        /* Now the coding tables */
        for (t = 0; t < nGroups; t++)
        {
            var curr = BsR(5);
            for (i = 0; i < alphaSize; i++)
            {
                while (BsR(1) == 1)
                {
                    if (BsR(1) == 0)
                    {
                        curr++;
                    }
                    else
                    {
                        curr--;
                    }
                }
                len[t][i] = (char)curr;
            }
        }

        /* Create the Huffman decoding tables */
        for (t = 0; t < nGroups; t++)
        {
            minLen = 32;
            maxLen = 0;
            for (i = 0; i < alphaSize; i++)
            {
                if (len[t][i] > maxLen)
                {
                    maxLen = len[t][i];
                }
                if (len[t][i] < minLen)
                {
                    minLen = len[t][i];
                }
            }
            HbCreateDecodeTables(limit[t], basev[t], perm[t], len[t], minLen, maxLen, alphaSize);
            minLens[t] = minLen;
        }
    }

    private void GetAndMoveToFrontDecode()
    {
        var yy = new char[256];
        int i,
            j,
            nextSym,
            limitLast;
        int EOB,
            groupNo,
            groupPos;

        limitLast = BZip2Constants.baseBlockSize * blockSize100k;
        origPtr = BsGetIntVS(24);

        RecvDecodingTables();
        EOB = nInUse + 1;
        groupNo = -1;
        groupPos = 0;

        /*
        Setting up the unzftab entries here is not strictly
        necessary, but it does save having to do it later
        in a separate pass, and so saves a block's worth of
        cache misses.
        */
        for (i = 0; i <= 255; i++)
        {
            unzftab[i] = 0;
        }

        for (i = 0; i <= 255; i++)
        {
            yy[i] = (char)i;
        }

        last = -1;

        {
            int zt,
                zn,
                zvec,
                zj;
            if (groupPos == 0)
            {
                groupNo++;
                groupPos = BZip2Constants.G_SIZE;
            }
            groupPos--;
            if (groupNo < 0 || groupNo >= selector.Length)
            {
                throw new InvalidDataException("BZip2: group selector out of range");
            }
            zt = selector[groupNo];
            zn = minLens[zt];
            zvec = BsR(zn);
            while (zvec > limit[zt][zn])
            {
                zn++;
                if (zn >= BZip2Constants.MAX_CODE_LEN)
                {
                    throw new InvalidDataException("BZip2: Huffman code too long");
                }
                {
                    {
                        while (bsLive < 1)
                        {
                            int zzi;
                            var thech = '\0';
                            try
                            {
                                thech = (char)bsStream.ReadByte();
                            }
                            catch (IOException)
                            {
                                CompressedStreamEOF();
                            }
                            if (thech == '\uffff')
                            {
                                CompressedStreamEOF();
                            }
                            zzi = thech;
                            bsBuff = (bsBuff << 8) | (zzi & 0xff);
                            bsLive += 8;
                        }
                    }
                    zj = (bsBuff >> (bsLive - 1)) & 1;
                    bsLive--;
                }
                zvec = (zvec << 1) | zj;
            }
            {
                int permIdx = zvec - basev[zt][zn];
                if (permIdx < 0 || permIdx >= perm[zt].Length)
                {
                    throw new InvalidDataException("BZip2: invalid Huffman symbol");
                }
                nextSym = perm[zt][permIdx];
            }
        }

        while (true)
        {
            if (nextSym == EOB)
            {
                break;
            }

            if (nextSym == BZip2Constants.RUNA || nextSym == BZip2Constants.RUNB)
            {
                char ch;
                var s = -1;
                var N = 1;
                do
                {
                    if (nextSym == BZip2Constants.RUNA)
                    {
                        s += (0 + 1) * N;
                    }
                    else if (nextSym == BZip2Constants.RUNB)
                    {
                        s += (1 + 1) * N;
                    }
                    N *= 2;
                    {
                        int zt,
                            zn,
                            zvec,
                            zj;
                        if (groupPos == 0)
                        {
                            groupNo++;
                            groupPos = BZip2Constants.G_SIZE;
                        }
                        groupPos--;
                        if (groupNo < 0 || groupNo >= selector.Length)
                        {
                            throw new InvalidDataException("BZip2: group selector out of range");
                        }
                        zt = selector[groupNo];
                        zn = minLens[zt];
                        zvec = BsR(zn);
                        while (zvec > limit[zt][zn])
                        {
                            zn++;
                            if (zn >= BZip2Constants.MAX_CODE_LEN)
                            {
                                throw new InvalidDataException("BZip2: Huffman code too long");
                            }
                            {
                                {
                                    while (bsLive < 1)
                                    {
                                        int zzi;
                                        var thech = '\0';
                                        try
                                        {
                                            thech = (char)bsStream.ReadByte();
                                        }
                                        catch (IOException)
                                        {
                                            CompressedStreamEOF();
                                        }
                                        if (thech == '\uffff')
                                        {
                                            CompressedStreamEOF();
                                        }
                                        zzi = thech;
                                        bsBuff = (bsBuff << 8) | (zzi & 0xff);
                                        bsLive += 8;
                                    }
                                }
                                zj = (bsBuff >> (bsLive - 1)) & 1;
                                bsLive--;
                            }
                            zvec = (zvec << 1) | zj;
                        }
                        {
                            int permIdx = zvec - basev[zt][zn];
                            if (permIdx < 0 || permIdx >= perm[zt].Length)
                            {
                                throw new InvalidDataException("BZip2: invalid Huffman symbol");
                            }
                            nextSym = perm[zt][permIdx];
                        }
                    }
                } while (nextSym == BZip2Constants.RUNA || nextSym == BZip2Constants.RUNB);

                s++;
                ch = seqToUnseq[yy[0]];
                unzftab[ch] += s;

                while (s > 0)
                {
                    if (last + 1 >= limitLast)
                    {
                        BlockOverrun();
                    }
                    last++;
                    ll8[last] = ch;
                    s--;
                }
            }
            else
            {
                char tmp;
                last++;
                if (last >= limitLast)
                {
                    BlockOverrun();
                }

                if (nextSym - 1 < 0 || nextSym - 1 >= yy.Length)
                {
                    throw new InvalidDataException("BZip2: symbol out of range");
                }
                tmp = yy[nextSym - 1];
                unzftab[seqToUnseq[tmp]]++;
                ll8[last] = seqToUnseq[tmp];

                /*
                This loop is hammered during decompression,
                hence the unrolling.

                for (j = nextSym-1; j > 0; j--) yy[j] = yy[j-1];
                */

                j = nextSym - 1;
                for (; j > 3; j -= 4)
                {
                    yy[j] = yy[j - 1];
                    yy[j - 1] = yy[j - 2];
                    yy[j - 2] = yy[j - 3];
                    yy[j - 3] = yy[j - 4];
                }
                for (; j > 0; j--)
                {
                    yy[j] = yy[j - 1];
                }

                yy[0] = tmp;
                {
                    int zt,
                        zn,
                        zvec,
                        zj;
                    if (groupPos == 0)
                    {
                        groupNo++;
                        groupPos = BZip2Constants.G_SIZE;
                    }
                    groupPos--;
                    if (groupNo < 0 || groupNo >= selector.Length)
                    {
                        throw new InvalidDataException("BZip2: group selector out of range");
                    }
                    zt = selector[groupNo];
                    zn = minLens[zt];
                    zvec = BsR(zn);
                    while (zvec > limit[zt][zn])
                    {
                        zn++;
                        if (zn >= BZip2Constants.MAX_CODE_LEN)
                        {
                            throw new InvalidDataException("BZip2: Huffman code too long");
                        }
                        {
                            {
                                while (bsLive < 1)
                                {
                                    int zzi;
                                    var thech = '\0';
                                    try
                                    {
                                        thech = (char)bsStream.ReadByte();
                                    }
                                    catch (IOException)
                                    {
                                        CompressedStreamEOF();
                                    }
                                    zzi = thech;
                                    bsBuff = (bsBuff << 8) | (zzi & 0xff);
                                    bsLive += 8;
                                }
                            }
                            zj = (bsBuff >> (bsLive - 1)) & 1;
                            bsLive--;
                        }
                        zvec = (zvec << 1) | zj;
                    }
                    {
                        int permIdx = zvec - basev[zt][zn];
                        if (permIdx < 0 || permIdx >= perm[zt].Length)
                        {
                            throw new InvalidDataException("BZip2: invalid Huffman symbol");
                        }
                        nextSym = perm[zt][permIdx];
                    }
                }
            }
        }
    }

    private void SetupBlock()
    {
        Span<int> cftab = stackalloc int[257];
        char ch;

        cftab[0] = 0;
        for (i = 1; i <= 256; i++)
        {
            cftab[i] = unzftab[i - 1];
        }
        for (i = 1; i <= 256; i++)
        {
            cftab[i] += cftab[i - 1];
        }

        for (i = 0; i <= last; i++)
        {
            ch = ll8[i];
            if (cftab[ch] < 0 || cftab[ch] >= tt.Length)
            {
                throw new InvalidDataException("BZip2: block data out of bounds");
            }
            tt[cftab[ch]] = i;
            cftab[ch]++;
        }

        // origPtr addresses a symbol in this block, not merely the allocated
        // level-9 workspace. Reject references into uninitialized workspace.
        if (origPtr < 0 || origPtr > last)
        {
            throw new InvalidDataException("BZip2: origPtr out of bounds");
        }
        tPos = tt[origPtr];

        count = 0;
        i2 = 0;
        ch2 = 256; /* not a char and not EOF */

        if (blockRandomised)
        {
            rNToGo = 0;
            rTPos = 0;
            SetupRandPartA();
        }
        else
        {
            SetupNoRandPartA();
        }
    }

    private void SetupRandPartA()
    {
        if (i2 <= last)
        {
            chPrev = ch2;
            ch2 = ll8[tPos];
            tPos = tt[tPos];
            if (rNToGo == 0)
            {
                rNToGo = BZip2Constants.rNums[rTPos];
                rTPos++;
                if (rTPos == 512)
                {
                    rTPos = 0;
                }
            }
            rNToGo--;
            ch2 ^= (rNToGo == 1) ? 1 : 0;
            i2++;

            currentChar = ch2;
            currentState = RAND_PART_B_STATE;
        }
        else
        {
            EndBlock();
            InitBlock();
            if (!streamEnd)
            {
                SetupBlock();
            }
        }
    }

    private void SetupNoRandPartA()
    {
        if (i2 <= last)
        {
            chPrev = ch2;
            ch2 = ll8[tPos];
            tPos = tt[tPos];
            i2++;

            currentChar = ch2;
            currentState = NO_RAND_PART_B_STATE;
        }
        else
        {
            EndBlock();
            InitBlock();
            if (!streamEnd)
            {
                SetupBlock();
            }
        }
    }

    private void SetupRandPartB()
    {
        if (ch2 != chPrev)
        {
            currentState = RAND_PART_A_STATE;
            count = 1;
            SetupRandPartA();
        }
        else
        {
            count++;
            if (count >= 4)
            {
                z = ll8[tPos];
                tPos = tt[tPos];
                if (rNToGo == 0)
                {
                    rNToGo = BZip2Constants.rNums[rTPos];
                    rTPos++;
                    if (rTPos == 512)
                    {
                        rTPos = 0;
                    }
                }
                rNToGo--;
                z ^= (char)((rNToGo == 1) ? 1 : 0);
                j2 = 0;
                currentState = RAND_PART_C_STATE;
                SetupRandPartC();
            }
            else
            {
                currentState = RAND_PART_A_STATE;
                SetupRandPartA();
            }
        }
    }

    private void SetupRandPartC()
    {
        if (j2 < z)
        {
            currentChar = ch2;
            j2++;
        }
        else
        {
            currentState = RAND_PART_A_STATE;
            i2++;
            count = 0;
            SetupRandPartA();
        }
    }

    private void SetupNoRandPartB()
    {
        if (ch2 != chPrev)
        {
            currentState = NO_RAND_PART_A_STATE;
            count = 1;
            SetupNoRandPartA();
        }
        else
        {
            count++;
            if (count >= 4)
            {
                z = ll8[tPos];
                tPos = tt[tPos];
                currentState = NO_RAND_PART_C_STATE;
                j2 = 0;
                SetupNoRandPartC();
            }
            else
            {
                currentState = NO_RAND_PART_A_STATE;
                SetupNoRandPartA();
            }
        }
    }

    private void SetupNoRandPartC()
    {
        if (j2 < z)
        {
            currentChar = ch2;
            j2++;
        }
        else
        {
            currentState = NO_RAND_PART_A_STATE;
            i2++;
            count = 0;
            SetupNoRandPartA();
        }
    }

    private void SetDecompressStructureSizes(int newSize100k)
    {
        if (!(0 <= newSize100k && newSize100k <= 9 && 0 <= blockSize100k && blockSize100k <= 9))
        {
            // throw new InvalidDataException("Invalid block size");
        }

        blockSize100k = newSize100k;

        if (newSize100k == 0)
        {
            return;
        }

        var n = BZip2Constants.baseBlockSize * newSize100k;
        ll8 = new char[n];
        tt = new int[n];
    }

    public override void Flush() { }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var c = -1;
        int k;
        for (k = 0; k < count; ++k)
        {
            c = ReadByte();
            if (c == -1)
            {
                break;
            }
            buffer[k + offset] = (byte)c;
        }
        return k;
    }

    public override long Seek(long offset, SeekOrigin origin) => 0;

    public override void SetLength(long value) { }

    public override void Write(byte[] buffer, int offset, int count) { }

    public override void WriteByte(byte value) { }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => 0;

    public override long Position
    {
        get => 0;
        set { }
    }
}

}
