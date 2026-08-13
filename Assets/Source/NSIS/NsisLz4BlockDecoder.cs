// SPDX-License-Identifier: GPL-3.0-or-later
// Decoder for the NSISBI LZ4 stream carried by one MTW record. NSISBI adds a
// little-endian uint16 length around each raw LZ4 block and terminates the
// stream with a zero length. Raw blocks share the preceding 64 KiB dictionary.
using System;

namespace Dumplings.InstallerParsers.NSIS
{
    public static class NsisLz4BlockDecoder
    {
        private const int MaximumCompressedBlockBytes = 65534;

        public static byte[] Decode(byte[] input, int maximumOutputBytes)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (maximumOutputBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumOutputBytes));

            byte[] output = new byte[maximumOutputBytes];
            int source = 0;
            int destination = 0;
            bool foundTerminator = false;

            while (source < input.Length)
            {
                if (source > input.Length - 2)
                    throw new InvalidOperationException("The NSISBI LZ4 block length is truncated.");

                int compressedLength = input[source] | (input[source + 1] << 8);
                source += 2;
                if (compressedLength == 0)
                {
                    if (source != input.Length)
                        throw new InvalidOperationException("The NSISBI LZ4 stream contains trailing bytes after its end marker.");
                    foundTerminator = true;
                    break;
                }
                if (compressedLength > MaximumCompressedBlockBytes || compressedLength > input.Length - source)
                    throw new InvalidOperationException("The NSISBI LZ4 block exceeds its bounded input.");

                int blockEnd = source + compressedLength;
                DecodeRawBlock(input, ref source, blockEnd, output, ref destination, maximumOutputBytes);
                if (source != blockEnd)
                    throw new InvalidOperationException("The NSISBI LZ4 decoder did not consume the complete block.");
            }

            if (!foundTerminator)
                throw new InvalidOperationException("The NSISBI LZ4 stream end marker is missing.");
            if (destination == 0)
                throw new InvalidOperationException("The NSISBI LZ4 stream produced no output.");

            byte[] result = new byte[destination];
            Buffer.BlockCopy(output, 0, result, 0, destination);
            return result;
        }

        private static void DecodeRawBlock(byte[] input, ref int source, int blockEnd, byte[] output, ref int destination, int maximumOutputBytes)
        {
            while (source < blockEnd)
            {
                byte token = input[source++];
                int literalLength = ReadExtendedLength(input, ref source, blockEnd, token >> 4);
                if (literalLength > blockEnd - source || literalLength > maximumOutputBytes - destination)
                    throw new InvalidOperationException("The NSISBI LZ4 literal range exceeds its bounded input or output.");

                Buffer.BlockCopy(input, source, output, destination, literalLength);
                source += literalLength;
                destination += literalLength;

                // A literal-only sequence is the normal final sequence of a
                // raw LZ4 block. The next uint16 belongs to the outer stream.
                if (source == blockEnd) break;
                if (source > blockEnd - 2)
                    throw new InvalidOperationException("The NSISBI LZ4 match offset is truncated.");

                int matchOffset = input[source] | (input[source + 1] << 8);
                source += 2;
                // destination includes earlier inner blocks, reproducing the
                // streaming dictionary retained by LZ4_decompress_safe_continue.
                if (matchOffset == 0 || matchOffset > destination || matchOffset > 65535)
                    throw new InvalidOperationException("The NSISBI LZ4 match offset is invalid.");

                int matchLength = ReadExtendedLength(input, ref source, blockEnd, token & 0x0F) + 4;
                if (matchLength > maximumOutputBytes - destination)
                    throw new InvalidOperationException("The NSISBI LZ4 match exceeds the bounded output.");

                int match = destination - matchOffset;
                for (int index = 0; index < matchLength; index++)
                    output[destination++] = output[match + index];
            }
        }

        private static int ReadExtendedLength(byte[] input, ref int source, int blockEnd, int length)
        {
            if (length != 15) return length;
            while (true)
            {
                if (source >= blockEnd)
                    throw new InvalidOperationException("The NSISBI LZ4 length extension is truncated.");
                int value = input[source++];
                checked { length += value; }
                if (value != 255) return length;
            }
        }
    }
}
