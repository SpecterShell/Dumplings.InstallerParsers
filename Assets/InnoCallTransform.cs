// SPDX-License-Identifier: GPL-3.0-or-later
// Implements the historical and Inno Setup 5.3.9+ CALL/JMP transforms documented by:
// https://github.com/jrsoftware/issrc/blob/main/Projects/Src/Compression.Base.pas
// https://github.com/jrathlev/InnoUnpacker-Windows-GUI/blob/master/innounp-2/sources/Extract.pas

using System;
using System.IO;
using System.Security.Cryptography;

namespace Dumplings.InstallerParsers
{
    public static class InnoCallTransform
    {
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

        private static void DecodeStream(Stream input, Stream output, long count, IncrementalHash hash, bool legacy)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (output == null)
                throw new ArgumentNullException(nameof(output));
            if (hash == null)
                throw new ArgumentNullException(nameof(hash));
            if (!input.CanRead)
                throw new ArgumentException("The input stream is not readable.", nameof(input));
            if (!output.CanWrite)
                throw new ArgumentException("The output stream is not writable.", nameof(output));
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));

            const int BufferSize = 64 * 1024;
            byte[] buffer = new byte[BufferSize];
            long remaining = count;
            uint addressOffset = 0;

            while (remaining > 0)
            {
                int blockLength = (int)Math.Min(BufferSize, remaining);
                int totalRead = 0;
                while (totalRead < blockLength)
                {
                    int read = input.Read(buffer, totalRead, blockLength - totalRead);
                    if (read <= 0)
                        throw new EndOfStreamException("The Inno Setup file payload is truncated.");
                    totalRead += read;
                }

                if (legacy)
                    DecodeLegacy(buffer, blockLength, addressOffset);
                else
                    Decode(buffer, blockLength, addressOffset);
                output.Write(buffer, 0, blockLength);
                hash.AppendData(buffer, 0, blockLength);
                addressOffset = unchecked(addressOffset + (uint)blockLength);
                remaining -= blockLength;
            }
        }
    }
}
