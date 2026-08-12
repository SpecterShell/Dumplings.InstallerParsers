// SPDX-License-Identifier: GPL-3.0-or-later
// Source behavior: https://github.com/jrsoftware/issrc/blob/main/Projects/Src/Setup.FileExtractor.pas

using System;
using System.IO;

namespace Dumplings.InstallerParsers
{
    /// <summary>
    /// Presents validated ranges from Inno Setup disk-slice files as one forward-only stream.
    /// Only the current slice is open, which bounds handles and memory for large multi-disk media.
    /// </summary>
    public sealed class InnoSliceStream : Stream
    {
        private readonly string[] paths;
        private readonly long[] offsets;
        private readonly long[] lengths;
        private readonly long length;
        private FileStream current;
        private int segmentIndex = -1;
        private long segmentPosition;
        private long position;
        private bool disposed;

        public InnoSliceStream(string[] paths, long[] offsets, long[] lengths)
        {
            if (paths == null) throw new ArgumentNullException(nameof(paths));
            if (offsets == null) throw new ArgumentNullException(nameof(offsets));
            if (lengths == null) throw new ArgumentNullException(nameof(lengths));
            if (paths.Length == 0 || paths.Length != offsets.Length || paths.Length != lengths.Length)
                throw new ArgumentException("Slice path, offset, and length arrays must have the same non-zero length.");

            this.paths = (string[])paths.Clone();
            this.offsets = (long[])offsets.Clone();
            this.lengths = (long[])lengths.Clone();
            long total = 0;
            for (int i = 0; i < paths.Length; i++)
            {
                if (String.IsNullOrWhiteSpace(paths[i])) throw new ArgumentException("A slice path is empty.", nameof(paths));
                if (offsets[i] < 0 || lengths[i] < 0) throw new ArgumentOutOfRangeException(nameof(lengths));
                total = checked(total + lengths[i]);
            }
            length = total;
        }

        public override bool CanRead => !disposed;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length { get { ThrowIfDisposed(); return length; } }
        public override long Position
        {
            get { ThrowIfDisposed(); return position; }
            set { throw new NotSupportedException(); }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ThrowIfDisposed();
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || count < 0 || offset > buffer.Length - count) throw new ArgumentOutOfRangeException();
            if (count == 0 || position == length) return 0;

            int totalRead = 0;
            while (count > 0 && position < length)
            {
                EnsureSegment();
                long remaining = lengths[segmentIndex] - segmentPosition;
                if (remaining == 0)
                {
                    CloseCurrent();
                    segmentIndex++;
                    segmentPosition = 0;
                    continue;
                }

                int requested = (int)Math.Min((long)count, remaining);
                int read = current.Read(buffer, offset, requested);
                if (read <= 0) throw new EndOfStreamException("An Inno Setup disk slice ended before its validated segment length.");
                offset += read;
                count -= read;
                totalRead += read;
                position += read;
                segmentPosition += read;
            }
            return totalRead;
        }

        private void EnsureSegment()
        {
            if (segmentIndex < 0) segmentIndex = 0;
            if (current != null || segmentIndex >= paths.Length) return;
            current = new FileStream(paths[segmentIndex], FileMode.Open, FileAccess.Read, FileShare.Read);
            long end = checked(offsets[segmentIndex] + lengths[segmentIndex]);
            if (end > current.Length)
            {
                CloseCurrent();
                throw new InvalidDataException("An Inno Setup disk-slice segment is outside its file.");
            }
            current.Position = offsets[segmentIndex] + segmentPosition;
        }

        private void CloseCurrent()
        {
            if (current == null) return;
            current.Dispose();
            current = null;
        }

        private void ThrowIfDisposed()
        {
            if (disposed) throw new ObjectDisposedException(nameof(InnoSliceStream));
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !disposed) CloseCurrent();
            disposed = true;
            base.Dispose(disposing);
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
