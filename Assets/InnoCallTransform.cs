// SPDX-License-Identifier: GPL-3.0-or-later
// Implements the Inno Setup 5.3.9+ CALL/JMP transform documented by:
// https://github.com/jrsoftware/issrc/blob/main/Projects/Src/Compression.Base.pas

using System;

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
    }
}
