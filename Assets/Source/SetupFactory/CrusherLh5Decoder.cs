// SPDX-License-Identifier: ISC
// Copyright (c) 2011-2025, Simon Howard
// Copyright (c) 2026, Dumplings contributors
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
// The block and tree model follows the permissively licensed Lhasa LH5 decoder:
// https://github.com/fragglet/lhasa/blob/master/lib/lh_new_decoder.c
// Setup Factory 3.1 uses this stream inside Crusher ARQ method 2 records.

using System;
using System.IO;

namespace Dumplings.InstallerParsers
{
    /// <summary>Decodes the bounded LH5-family stream used by Crusher ARQ archives.</summary>
    public static class CrusherLh5Decoder
    {
        private const int TemporaryCodeBits = 5;
        private const int MaximumTemporaryCodes = (1 << TemporaryCodeBits) - 1;
        private const int CopyThreshold = 3;

        /// <summary>Decode one Crusher method-2 member payload into a caller-owned stream.</summary>
        public static long Decode(
            Stream source,
            long offset,
            long compressedLength,
            Stream destination,
            long expectedLength,
            long maximumLength)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (destination == null) throw new ArgumentNullException(nameof(destination));
            if (!source.CanRead || !source.CanSeek) throw new ArgumentException("The Crusher input stream must be readable and seekable.", nameof(source));
            if (!destination.CanWrite) throw new ArgumentException("The Crusher output stream must be writable.", nameof(destination));
            if (offset < 0 || compressedLength < 0 || expectedLength < 0 || maximumLength < 0) throw new ArgumentOutOfRangeException(nameof(offset));
            if (expectedLength > maximumLength) throw new InvalidDataException("The Crusher expanded stream exceeds the configured limit.");
            if (offset > source.Length || compressedLength > source.Length - offset) throw new InvalidDataException("The Crusher compressed range is outside the source stream.");

            long originalPosition = source.Position;
            try
            {
                source.Position = offset;
                var decoder = new Decoder(new BitReader(source, compressedLength), 14, 4, 510);
                decoder.Decode(destination, expectedLength);
                return decoder.Reader.BytesConsumed;
            }
            finally
            {
                source.Position = originalPosition;
            }
        }

        /// <summary>Decode Setup Factory 3.1's extended Crusher file stream.</summary>
        public static long DecodeSetupFactory31(
            Stream source,
            long offset,
            long compressedLength,
            Stream destination,
            long expectedLength,
            long maximumLength)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (destination == null) throw new ArgumentNullException(nameof(destination));
            if (!source.CanRead || !source.CanSeek) throw new ArgumentException("The Crusher input stream must be readable and seekable.", nameof(source));
            if (!destination.CanWrite) throw new ArgumentException("The Crusher output stream must be writable.", nameof(destination));
            if (offset < 0 || compressedLength < 0 || expectedLength < 0 || maximumLength < 0) throw new ArgumentOutOfRangeException(nameof(offset));
            if (expectedLength > maximumLength) throw new InvalidDataException("The Crusher expanded stream exceeds the configured limit.");
            if (offset > source.Length || compressedLength > source.Length - offset) throw new InvalidDataException("The Crusher compressed range is outside the source stream.");

            long originalPosition = source.Position;
            try
            {
                source.Position = offset;
                // Setup Factory's standalone compressed files use the 32 KiB
                // dictionary and one additional copy-length command observed
                // in the version 3.1 runtime, rather than ARQ method 2's
                // standard 16 KiB LH5 profile.
                var decoder = new Decoder(new BitReader(source, compressedLength), 15, 5, 511);
                decoder.Decode(destination, expectedLength);
                return decoder.Reader.BytesConsumed;
            }
            finally
            {
                source.Position = originalPosition;
            }
        }

        private sealed class Decoder
        {
            private readonly byte[] history;
            private readonly int historyMask;
            private readonly int historyBits;
            private readonly int offsetBits;
            private readonly int numberOfCodes;
            private readonly int maximumOffsetCodes;
            private int historyPosition;
            private int blockRemaining;
            private HuffmanTree temporaryTree = HuffmanTree.Empty;
            private HuffmanTree codeTree = HuffmanTree.Empty;
            private HuffmanTree offsetTree = HuffmanTree.Empty;

            internal Decoder(BitReader reader, int historyBits, int offsetBits, int numberOfCodes)
            {
                Reader = reader;
                this.historyBits = historyBits;
                this.offsetBits = offsetBits;
                this.numberOfCodes = numberOfCodes;
                maximumOffsetCodes = (1 << offsetBits) - 1;
                history = new byte[1 << historyBits];
                historyMask = history.Length - 1;
                Array.Fill(history, (byte)' ');
            }

            internal BitReader Reader { get; }

            internal void Decode(Stream destination, long expectedLength)
            {
                long written = 0;
                while (written < expectedLength)
                {
                    if (blockRemaining == 0) StartBlock();
                    blockRemaining--;
                    int code = codeTree.Decode(Reader);
                    if (code < 256)
                    {
                        WriteByte(destination, (byte)code);
                        written++;
                        continue;
                    }

                    int count = code - 256 + CopyThreshold;
                    if (count <= 0 || count > expectedLength - written) throw new InvalidDataException("A Crusher back-reference exceeds the declared output size.");
                    int offset = ReadOffset();
                    int sourcePosition = (historyPosition + history.Length - offset - 1) & historyMask;
                    for (int index = 0; index < count; index++)
                    {
                        byte value = history[(sourcePosition + index) & historyMask];
                        WriteByte(destination, value);
                    }
                    written += count;
                }
            }

            private void StartBlock()
            {
                blockRemaining = Reader.ReadBits(16);
                if (blockRemaining <= 0) throw new InvalidDataException("The Crusher stream contains an empty command block.");
                temporaryTree = ReadTemporaryTree();
                codeTree = ReadCodeTree();
                offsetTree = ReadOffsetTree();
            }

            private HuffmanTree ReadTemporaryTree()
            {
                int count = Reader.ReadBits(TemporaryCodeBits);
                if (count == 0) return HuffmanTree.Single(Reader.ReadBits(TemporaryCodeBits));
                if (count > MaximumTemporaryCodes) throw new InvalidDataException($"The Crusher temporary-tree entry count {count} is invalid.");

                var lengths = new byte[count];
                for (int index = 0; index < count; index++)
                {
                    lengths[index] = checked((byte)ReadLength());
                    if (index == 2)
                    {
                        int skipped = Reader.ReadBits(2);
                        if (index + skipped >= count) throw new InvalidDataException("The Crusher temporary-tree skip exceeds its table.");
                        index += skipped;
                    }
                }
                return HuffmanTree.Build(lengths, MaximumTemporaryCodes);
            }

            private HuffmanTree ReadCodeTree()
            {
                int count = Reader.ReadBits(9);
                if (count == 0) return HuffmanTree.Single(Reader.ReadBits(9));
                if (count > numberOfCodes) throw new InvalidDataException($"The Crusher code-tree entry count {count} is invalid.");

                var lengths = new byte[count];
                int index = 0;
                while (index < count)
                {
                    int code = temporaryTree.Decode(Reader);
                    if (code <= 2)
                    {
                        int skipped = code == 0 ? 1 : code == 1 ? Reader.ReadBits(4) + 3 : Reader.ReadBits(9) + 20;
                        if (skipped > count - index) throw new InvalidDataException("The Crusher code-tree skip exceeds its table.");
                        index += skipped;
                    }
                    else
                    {
                        lengths[index++] = checked((byte)(code - 2));
                    }
                }
                return HuffmanTree.Build(lengths, numberOfCodes);
            }

            private HuffmanTree ReadOffsetTree()
            {
                int count = Reader.ReadBits(offsetBits);
                if (count == 0) return HuffmanTree.Single(Reader.ReadBits(offsetBits));
                if (count > maximumOffsetCodes) throw new InvalidDataException($"The Crusher offset-tree entry count {count} is invalid.");

                var lengths = new byte[count];
                for (int index = 0; index < count; index++) lengths[index] = checked((byte)ReadLength());
                return HuffmanTree.Build(lengths, maximumOffsetCodes);
            }

            private int ReadLength()
            {
                int length = Reader.ReadBits(3);
                if (length == 7)
                {
                    while (Reader.ReadBit() != 0)
                    {
                        length++;
                        if (length > 31) throw new InvalidDataException("A Crusher Huffman code is too long.");
                    }
                }
                return length;
            }

            private int ReadOffset()
            {
                int bits = offsetTree.Decode(Reader);
                if (bits == 0) return 0;
                if (bits == 1) return 1;
                if (bits >= historyBits) throw new InvalidDataException("A Crusher history offset exceeds its declared dictionary.");
                return (1 << (bits - 1)) + Reader.ReadBits(bits - 1);
            }

            private void WriteByte(Stream destination, byte value)
            {
                destination.WriteByte(value);
                history[historyPosition] = value;
                historyPosition = (historyPosition + 1) & historyMask;
            }
        }

        private sealed class HuffmanTree
        {
            private readonly Node root;
            internal static HuffmanTree Empty { get; } = new HuffmanTree(new Node());

            private HuffmanTree(Node root) { this.root = root; }

            internal static HuffmanTree Single(int symbol)
            {
                if (symbol < 0) throw new InvalidDataException("The Crusher single-symbol tree is invalid.");
                return new HuffmanTree(new Node { Symbol = symbol });
            }

            internal static HuffmanTree Build(byte[] lengths, int symbolLimit)
            {
                int maximumLength = 0;
                var counts = new int[32];
                for (int symbol = 0; symbol < lengths.Length; symbol++)
                {
                    int length = lengths[symbol];
                    if (length > 31) throw new InvalidDataException("A Crusher Huffman code is too long.");
                    if (length != 0)
                    {
                        counts[length]++;
                        maximumLength = Math.Max(maximumLength, length);
                    }
                }
                if (maximumLength == 0) throw new InvalidDataException("The Crusher Huffman tree is empty.");

                var nextCode = new int[32];
                int code = 0;
                for (int bits = 1; bits <= maximumLength; bits++)
                {
                    code = checked((code + counts[bits - 1]) << 1);
                    nextCode[bits] = code;
                    if ((long)code + counts[bits] > 1L << bits) throw new InvalidDataException("The Crusher Huffman tree is over-subscribed.");
                }

                var root = new Node();
                for (int symbol = 0; symbol < lengths.Length; symbol++)
                {
                    int length = lengths[symbol];
                    if (length == 0) continue;
                    if (symbol >= symbolLimit) throw new InvalidDataException("A Crusher Huffman symbol exceeds its table.");
                    int symbolCode = nextCode[length]++;
                    Node node = root;
                    for (int bitIndex = length - 1; bitIndex >= 0; bitIndex--)
                    {
                        bool one = ((symbolCode >> bitIndex) & 1) != 0;
                        if (bitIndex == 0)
                        {
                            Node leaf = one ? node.One : node.Zero;
                            if (leaf != null) throw new InvalidDataException("The Crusher Huffman tree contains overlapping codes.");
                            leaf = new Node { Symbol = symbol };
                            if (one) node.One = leaf; else node.Zero = leaf;
                        }
                        else
                        {
                            Node child = one ? node.One : node.Zero;
                            if (child == null)
                            {
                                child = new Node();
                                if (one) node.One = child; else node.Zero = child;
                            }
                            else if (child.Symbol.HasValue)
                            {
                                throw new InvalidDataException("The Crusher Huffman tree contains a prefix collision.");
                            }
                            node = child;
                        }
                    }
                }
                return new HuffmanTree(root);
            }

            internal int Decode(BitReader reader)
            {
                Node node = root;
                for (int depth = 0; depth <= 31; depth++)
                {
                    if (node.Symbol.HasValue) return node.Symbol.Value;
                    node = reader.ReadBit() == 0 ? node.Zero : node.One;
                    if (node == null) throw new InvalidDataException("The Crusher Huffman path is invalid.");
                }
                throw new InvalidDataException("The Crusher Huffman path exceeds its maximum depth.");
            }

            private sealed class Node
            {
                internal int? Symbol;
                internal Node Zero;
                internal Node One;
            }
        }

        internal sealed class BitReader
        {
            private readonly Stream source;
            private readonly long maximumBytes;
            private ulong buffer;
            private int availableBits;

            internal BitReader(Stream source, long maximumBytes)
            {
                this.source = source;
                this.maximumBytes = maximumBytes;
            }

            internal long BytesConsumed { get; private set; }

            internal int ReadBit() => ReadBits(1);

            internal int ReadBits(int count)
            {
                if (count < 0 || count > 31) throw new ArgumentOutOfRangeException(nameof(count));
                if (count == 0) return 0;
                while (availableBits < count)
                {
                    if (BytesConsumed >= maximumBytes) throw new EndOfStreamException("The Crusher bit stream is truncated.");
                    int value = source.ReadByte();
                    if (value < 0) throw new EndOfStreamException("The Crusher bit stream is truncated.");
                    buffer = (buffer << 8) | (byte)value;
                    availableBits += 8;
                    BytesConsumed++;
                }
                int shift = availableBits - count;
                int result = (int)((buffer >> shift) & ((1UL << count) - 1));
                availableBits -= count;
                buffer &= availableBits == 0 ? 0 : (1UL << availableBits) - 1;
                return result;
            }
        }
    }
}
