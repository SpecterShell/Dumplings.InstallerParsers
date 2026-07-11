// SPDX-License-Identifier: Zlib
// Derived from Mark Adler's blast.c algorithm in zlib/contrib/blast.

using System;
using System.Collections.Generic;
using System.IO;

namespace Dumplings.InstallerParsers
{
    public static class PkwareBlast
    {
        private const int MaxBits = 13;

        private static readonly byte[] LitLengths = {
            11,124,8,7,28,7,188,13,76,4,10,8,12,10,12,10,8,23,8,9,7,6,7,8,7,6,55,8,23,24,
            12,11,7,9,11,12,6,7,22,5,7,24,6,11,9,6,7,22,7,11,38,7,9,8,25,11,8,11,9,12,
            8,12,5,38,5,38,5,11,7,5,6,21,6,10,53,8,7,24,10,27,44,253,253,253,252,252,252,
            13,12,45,12,45,12,61,12,45,44,173
        };
        private static readonly byte[] LenLengths = { 2,35,36,53,38,23 };
        private static readonly byte[] DistLengths = { 2,20,53,230,247,151,248 };
        private static readonly int[] LengthBase = { 3,2,4,5,6,7,8,9,10,12,16,24,40,72,136,264 };
        private static readonly int[] LengthExtra = { 0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8 };

        private static readonly Huffman LitTable = Construct(256, LitLengths);
        private static readonly Huffman LenTable = Construct(16, LenLengths);
        private static readonly Huffman DistTable = Construct(64, DistLengths);

        public static byte[] Decode(byte[] input, long maximumOutputBytes)
        {
            if (input == null || input.Length < 3)
                throw new InvalidDataException("The PKWARE implode stream is truncated.");
            if (maximumOutputBytes < 1 || maximumOutputBytes > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(maximumOutputBytes));

            int codedLiterals = input[0];
            int dictionaryBits = input[1];
            if (codedLiterals < 0 || codedLiterals > 1)
                throw new InvalidDataException("The PKWARE literal flag is invalid.");
            if (dictionaryBits < 4 || dictionaryBits > 6)
                throw new InvalidDataException("The PKWARE dictionary size is invalid.");

            var bits = new BitReader(input, 2);
            var output = new List<byte>();
            while (true)
            {
                if (bits.ReadBits(1) != 0)
                {
                    int lengthSymbol = DecodeSymbol(bits, LenTable);
                    int length = LengthBase[lengthSymbol] + bits.ReadBits(LengthExtra[lengthSymbol]);
                    if (length == 519)
                        return output.ToArray();

                    int lowDistanceBits = length == 2 ? 2 : dictionaryBits;
                    int distance = (DecodeSymbol(bits, DistTable) << lowDistanceBits) +
                        bits.ReadBits(lowDistanceBits) + 1;
                    if (distance < 1 || distance > output.Count)
                        throw new InvalidDataException("The PKWARE back-reference exceeds the decoded window.");
                    EnsureOutputLimit(output.Count, length, maximumOutputBytes);
                    for (int index = 0; index < length; index++)
                        output.Add(output[output.Count - distance]);
                }
                else
                {
                    int literal = codedLiterals != 0 ? DecodeSymbol(bits, LitTable) : bits.ReadBits(8);
                    EnsureOutputLimit(output.Count, 1, maximumOutputBytes);
                    output.Add((byte)literal);
                }
            }
        }

        private static void EnsureOutputLimit(int current, int additional, long maximum)
        {
            if ((long)current + additional > maximum)
                throw new InvalidDataException("The PKWARE decoded output exceeds the configured limit.");
        }

        private static int DecodeSymbol(BitReader bits, Huffman table)
        {
            int code = 0, first = 0, index = 0;
            for (int length = 1; length <= MaxBits; length++)
            {
                code |= bits.ReadBits(1) ^ 1;
                int count = table.Count[length];
                if (code < first + count)
                    return table.Symbol[index + code - first];
                index += count;
                first = (first + count) << 1;
                code <<= 1;
            }
            throw new InvalidDataException("The PKWARE Huffman code is invalid.");
        }

        private static Huffman Construct(int symbolCapacity, byte[] representation)
        {
            var lengths = new byte[256];
            int symbolCount = 0;
            foreach (byte value in representation)
            {
                int repeat = (value >> 4) + 1;
                int bitLength = value & 15;
                if (symbolCount + repeat > lengths.Length)
                    throw new InvalidDataException("The PKWARE Huffman table is invalid.");
                for (int index = 0; index < repeat; index++)
                    lengths[symbolCount++] = (byte)bitLength;
            }

            var table = new Huffman(symbolCapacity);
            for (int symbol = 0; symbol < symbolCount; symbol++)
                table.Count[lengths[symbol]]++;
            if (table.Count[0] == symbolCount)
                throw new InvalidDataException("The PKWARE Huffman table is empty.");

            int remaining = 1;
            for (int length = 1; length <= MaxBits; length++)
            {
                remaining = (remaining << 1) - table.Count[length];
                if (remaining < 0)
                    throw new InvalidDataException("The PKWARE Huffman table is over-subscribed.");
            }

            var offsets = new int[MaxBits + 1];
            for (int length = 1; length < MaxBits; length++)
                offsets[length + 1] = offsets[length] + table.Count[length];
            for (int symbol = 0; symbol < symbolCount; symbol++)
                if (lengths[symbol] != 0)
                    table.Symbol[offsets[lengths[symbol]]++] = symbol;
            return table;
        }

        private sealed class Huffman
        {
            public readonly int[] Count = new int[MaxBits + 1];
            public readonly int[] Symbol;
            public Huffman(int symbolCapacity) { Symbol = new int[symbolCapacity]; }
        }

        private sealed class BitReader
        {
            private readonly byte[] input;
            private int index;
            private int accumulator;
            private int available;

            public BitReader(byte[] input, int offset)
            {
                this.input = input;
                index = offset;
            }

            public int ReadBits(int count)
            {
                if (count < 0 || count > 16)
                    throw new ArgumentOutOfRangeException(nameof(count));
                int value = 0;
                for (int bit = 0; bit < count; bit++)
                {
                    if (available == 0)
                    {
                        if (index >= input.Length)
                            throw new InvalidDataException("The PKWARE implode stream ended before its end marker.");
                        accumulator = input[index++];
                        available = 8;
                    }
                    value |= (accumulator & 1) << bit;
                    accumulator >>= 1;
                    available--;
                }
                return value;
            }
        }
    }
}
