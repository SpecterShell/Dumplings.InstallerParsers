// SPDX-License-Identifier: GPL-3.0-or-later
// Implements the historical and Inno Setup 5.3.9+ CALL/JMP transforms, plus the
// bounded scan used to locate variable-length TSetupFileEntry record candidates.
// The scanner recognizes only the serialized string framing; PowerShell still
// validates the complete version-specific record chain before accepting a table.
// Format sources:
// https://github.com/jrsoftware/issrc/blob/main/Projects/Src/Compression.Base.pas
// https://github.com/jrsoftware/issrc/blob/main/Projects/Src/Shared.Struct.pas
// https://github.com/jrsoftware/issrc/blob/main/Projects/Src/Compiler.SetupCompiler.pas
// https://github.com/jrathlev/InnoUnpacker-Windows-GUI/blob/master/innounp-2/sources/Extract.pas

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace Dumplings.InstallerParsers
{
    public static class InnoCallTransform
    {
        /// <summary>
        /// Finds candidate records whose second length-prefixed string begins at
        /// one of the supplied content offsets. The parser still validates each
        /// complete record chain; this method only removes a boxed PowerShell
        /// byte loop from variable-length table discovery.
        /// </summary>
        public static int[] FindLengthPrefixedSecondStringRecords(
            byte[] buffer,
            int startOffset,
            int maximumOffset,
            int[] secondStringContentOffsets,
            bool unicode,
            int maximumFirstStringBytes,
            int maximumSecondStringBytes)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));
            if (secondStringContentOffsets == null)
                throw new ArgumentNullException(nameof(secondStringContentOffsets));
            if (startOffset < 0 || startOffset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(startOffset));
            if (maximumOffset < startOffset)
                return Array.Empty<int>();
            if (maximumFirstStringBytes < 0 || maximumSecondStringBytes < 0)
                throw new ArgumentOutOfRangeException(nameof(maximumFirstStringBytes));

            var contentOffsets = new HashSet<int>(secondStringContentOffsets);
            var results = new List<int>();
            int limit = Math.Min(maximumOffset, buffer.Length - 8);
            for (int sourceOffset = startOffset; sourceOffset <= limit; sourceOffset++)
            {
                int sourceLength = ReadInt32LittleEndian(buffer, sourceOffset);
                if (sourceLength < 0 || sourceLength > maximumFirstStringBytes ||
                    (unicode && (sourceLength & 1) != 0))
                    continue;

                long destinationLengthOffset64 = (long)sourceOffset + sizeof(int) + sourceLength;
                if (destinationLengthOffset64 < sourceOffset || destinationLengthOffset64 > buffer.Length - sizeof(int))
                    continue;
                int destinationLengthOffset = (int)destinationLengthOffset64;
                int destinationLength = ReadInt32LittleEndian(buffer, destinationLengthOffset);
                if (destinationLength < 0 || destinationLength > maximumSecondStringBytes ||
                    destinationLength > buffer.Length - destinationLengthOffset - sizeof(int) ||
                    (unicode && (destinationLength & 1) != 0))
                    continue;
                if (contentOffsets.Contains(destinationLengthOffset + sizeof(int)))
                    results.Add(sourceOffset);
            }
            return results.ToArray();
        }

        public static void Decode(byte[] buffer, int count, uint addressOffset)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));
            if (count < 0 || count > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(count));
            if (count < 5)
                return;

            int limit = count - 4;
            int index = 0;
            while (index < limit)
            {
                if (buffer[index] != 0xE8 && buffer[index] != 0xE9)
                {
                    index++;
                    continue;
                }

                index++;
                byte high = buffer[index + 3];
                if (high == 0x00 || high == 0xFF)
                {
                    uint address = unchecked(addressOffset + (uint)index + 4U) & 0xFFFFFFU;
                    uint relative = (uint)(buffer[index] | (buffer[index + 1] << 8) | (buffer[index + 2] << 16));
                    relative = unchecked(relative - address) & 0xFFFFFFU;

                    if ((relative & 0x800000U) != 0)
                        buffer[index + 3] = (byte)~high;

                    buffer[index] = (byte)relative;
                    buffer[index + 1] = (byte)(relative >> 8);
                    buffer[index + 2] = (byte)(relative >> 16);
                }
                index += 4;
            }
        }

        /// <summary>
        /// Decodes the pre-5.3.9 transform, whose three-byte subtraction carries
        /// through one byte at a time instead of toggling the sign-extension byte.
        /// </summary>
        public static void DecodeLegacy(byte[] buffer, int count, uint addressOffset)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));
            if (count < 0 || count > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(count));
            if (count < 5)
                return;

            int limit = count - 4;
            int index = 0;
            while (index < limit)
            {
                if (buffer[index] != 0xE8 && buffer[index] != 0xE9)
                {
                    index++;
                    continue;
                }

                index++;
                if (buffer[index + 3] == 0x00 || buffer[index + 3] == 0xFF)
                {
                    uint address = unchecked(0U - (addressOffset + (uint)index + 4U));
                    for (int byteIndex = 0; byteIndex < 3; byteIndex++)
                    {
                        address = unchecked(address + buffer[index + byteIndex]);
                        buffer[index + byteIndex] = (byte)address;
                        address >>= 8;
                    }
                }
                index += 4;
            }
        }

        /// <summary>
        /// Decodes exactly <paramref name="count"/> bytes using the 64 KiB
        /// blocks selected by the Inno Setup extractor.
        /// </summary>
        /// <remarks>
        /// Inno Setup 5.2 and later deliberately applies the stateless transform
        /// to independent 65536-byte buffers and advances AddrOffset by that
        /// amount. The final four bytes of each buffer are therefore not joined
        /// to the next buffer. Using an arbitrary PowerShell buffer size changes
        /// those boundaries and produces a digest mismatch.
        /// </remarks>
        public static void Decode(Stream input, Stream output, long count, IncrementalHash hash)
        {
            DecodeStream(input, output, count, hash, false);
        }

        /// <summary>
        /// Decodes a pre-5.3.9 stream using the same independent 64 KiB framing.
        /// </summary>
        public static void DecodeLegacy(Stream input, Stream output, long count, IncrementalHash hash)
        {
            DecodeStream(input, output, count, hash, true);
        }

        /// <summary>
        /// Decodes the stateful CALL/JMP transform used before Inno Setup 5.2.
        /// The four address bytes may cross read-buffer boundaries, so the
        /// decoder state deliberately survives each stream read.
        /// </summary>
        public static void DecodeStateful(Stream input, Stream output, long count, IncrementalHash hash)
        {
            ValidateStreams(input, output, count);
            const int BufferSize = 64 * 1024;
            byte[] buffer = new byte[BufferSize];
            long remaining = count;
            uint offset = 5;
            uint address = 0;
            uint addressBytesLeft = 0;

            while (remaining > 0)
            {
                int blockLength = (int)Math.Min(BufferSize, remaining);
                ReadExactly(input, buffer, blockLength);
                for (int index = 0; index < blockLength; index++, offset++)
                {
                    if (addressBytesLeft == 0)
                    {
                        if (buffer[index] == 0xE8 || buffer[index] == 0xE9)
                        {
                            address = unchecked(0U - offset);
                            addressBytesLeft = 4;
                        }
                    }
                    else
                    {
                        address = unchecked(address + buffer[index]);
                        buffer[index] = (byte)address;
                        address >>= 8;
                        addressBytesLeft--;
                    }
                }
                output.Write(buffer, 0, blockLength);
                if (hash != null)
                    hash.AppendData(buffer, 0, blockLength);
                remaining -= blockLength;
            }
        }

        /// <summary>Calculates the Adler-32 value used by historical Inno payload records.</summary>
        public static uint ComputeAdler32(Stream input)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (!input.CanRead)
                throw new ArgumentException("The input stream is not readable.", nameof(input));

            const uint Modulo = 65521;
            byte[] buffer = new byte[64 * 1024];
            uint first = 1;
            uint second = 0;
            int read;
            while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                for (int index = 0; index < read; index++)
                {
                    first += buffer[index];
                    second += first;
                    if ((index & 0x0FFF) == 0x0FFF)
                    {
                        first %= Modulo;
                        second %= Modulo;
                    }
                }
                first %= Modulo;
                second %= Modulo;
            }
            return (second << 16) | first;
        }

        private static void DecodeStream(Stream input, Stream output, long count, IncrementalHash hash, bool legacy)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (output == null)
                throw new ArgumentNullException(nameof(output));
            ValidateStreams(input, output, count);

            const int BufferSize = 64 * 1024;
            byte[] buffer = new byte[BufferSize];
            long remaining = count;
            uint addressOffset = 0;

            while (remaining > 0)
            {
                int blockLength = (int)Math.Min(BufferSize, remaining);
                ReadExactly(input, buffer, blockLength);

                if (legacy)
                    DecodeLegacy(buffer, blockLength, addressOffset);
                else
                    Decode(buffer, blockLength, addressOffset);
                output.Write(buffer, 0, blockLength);
                if (hash != null)
                    hash.AppendData(buffer, 0, blockLength);
                addressOffset = unchecked(addressOffset + (uint)blockLength);
                remaining -= blockLength;
            }
        }

        private static void ValidateStreams(Stream input, Stream output, long count)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (output == null)
                throw new ArgumentNullException(nameof(output));
            if (!input.CanRead)
                throw new ArgumentException("The input stream is not readable.", nameof(input));
            if (!output.CanWrite)
                throw new ArgumentException("The output stream is not writable.", nameof(output));
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));
        }

        private static void ReadExactly(Stream input, byte[] buffer, int count)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int read = input.Read(buffer, totalRead, count - totalRead);
                if (read <= 0)
                    throw new EndOfStreamException("The Inno Setup file payload is truncated.");
                totalRead += read;
            }
        }

        private static int ReadInt32LittleEndian(byte[] buffer, int offset)
        {
            return buffer[offset] |
                (buffer[offset + 1] << 8) |
                (buffer[offset + 2] << 16) |
                (buffer[offset + 3] << 24);
        }
    }
}
