// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;

namespace Dumplings.InstallerParsers.NSIS
{
    /// <summary>Read-only logical stream over ordered NSISBI setup*.bin segments.</summary>
    public sealed class NsisSegmentedReadStream : Stream
    {
        private readonly FileStream[] streams;
        private readonly long[] starts;
        private readonly long length;
        private long position;

        public NsisSegmentedReadStream(string[] paths)
        {
            if (paths == null || paths.Length == 0) throw new ArgumentException("At least one NSISBI sidecar is required.", nameof(paths));
            streams = new FileStream[paths.Length];
            starts = new long[paths.Length];
            long total = 0;
            try
            {
                for (int index = 0; index < paths.Length; index++)
                {
                    starts[index] = total;
                    streams[index] = new FileStream(Path.GetFullPath(paths[index]), FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    total = checked(total + streams[index].Length);
                }
            }
            catch
            {
                DisposeStreams();
                throw;
            }
            length = total;
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get => position; set => Seek(value, SeekOrigin.Begin); }
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || count < 0 || offset > buffer.Length - count) throw new ArgumentOutOfRangeException();
            if (count == 0 || position >= length) return 0;

            int totalRead = 0;
            while (count > 0 && position < length)
            {
                int segment = FindSegment(position);
                FileStream stream = streams[segment];
                long local = position - starts[segment];
                stream.Position = local;
                int available = (int)Math.Min(count, stream.Length - local);
                int read = stream.Read(buffer, offset, available);
                if (read <= 0) break;
                position += read;
                offset += read;
                count -= read;
                totalRead += read;
            }
            return totalRead;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            long target;
            switch (origin)
            {
                case SeekOrigin.Begin: target = offset; break;
                case SeekOrigin.Current: target = checked(position + offset); break;
                case SeekOrigin.End: target = checked(length + offset); break;
                default: throw new ArgumentOutOfRangeException(nameof(origin));
            }
            if (target < 0 || target > length) throw new IOException("Attempted to seek outside the NSISBI sidecar stream.");
            position = target;
            return position;
        }

        private int FindSegment(long absolutePosition)
        {
            int low = 0;
            int high = starts.Length - 1;
            while (low <= high)
            {
                int middle = low + ((high - low) / 2);
                if (starts[middle] <= absolutePosition)
                {
                    if (middle == starts.Length - 1 || starts[middle + 1] > absolutePosition) return middle;
                    low = middle + 1;
                }
                else high = middle - 1;
            }
            throw new IOException("The NSISBI sidecar position is not covered by a segment.");
        }

        private void DisposeStreams()
        {
            foreach (FileStream stream in streams) stream?.Dispose();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) DisposeStreams();
            base.Dispose(disposing);
        }
    }
}
