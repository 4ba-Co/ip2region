// Copyright 2025 The Ip2Region Authors. All rights reserved.
// Use of this source code is governed by a Apache2.0-style
// license that can be found in the LICENSE file.
// @Author Alan <lzh.shap@gmail.com>
// @Date   2023/07/25

using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace IP2Region.Net.Internal;

internal sealed class VectorIndexCacheStrategy : FileCacheStrategy
{
    private const int VectorIndexRows = 256;
    private const int StackallocThreshold = 256;

    private readonly uint[] _vectorStart;
    private readonly uint[] _vectorEnd;

    public VectorIndexCacheStrategy(string xdbPath) : base(xdbPath)
    {
        _vectorStart = new uint[VectorIndexRows * VectorIndexCols];
        _vectorEnd = new uint[VectorIndexRows * VectorIndexCols];

        const int vectorSize = VectorIndexRows * VectorIndexCols * VectorIndexSize;
        var buffer = ArrayPool<byte>.Shared.Rent(vectorSize);
        try
        {
            Read(HeaderInfoLength, buffer.AsSpan(0, vectorSize));
            var span = buffer.AsSpan(0, vectorSize);
            var offset = 0;
            for (int i = 0; i < _vectorStart.Length; i++)
            {
                _vectorStart[i] = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(offset, 4));
                _vectorEnd[i] = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(offset + 4, 4));
                offset += VectorIndexSize;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        IoCount = 0;
    }

    public override string Search(ReadOnlySpan<byte> ipBytes)
    {
        IoCount = 0;

        var idx = ipBytes[0] * VectorIndexCols + ipBytes[1];
        var sPtr = _vectorStart[idx];
        var ePtr = _vectorEnd[idx];

        var ipLen = ipBytes.Length;
        var indexSize = ipLen * 2 + 6;
        var low = 0;
        var high = (int)((ePtr - sPtr) / (uint)indexSize);

        var dataLen = 0;
        uint dataPtr = 0;

        byte[]? rentedIndexBuffer = null;
        var indexSpan = indexSize <= StackallocThreshold
            ? stackalloc byte[indexSize]
            : (rentedIndexBuffer = ArrayPool<byte>.Shared.Rent(indexSize)).AsSpan(0, indexSize);

        try
        {
            while (low <= high)
            {
                var mid = (low + high) >> 1;
                var p = sPtr + (uint)(mid * indexSize);

                Read(p, indexSpan);

                var sip = indexSpan.Slice(0, ipLen);
                var eip = indexSpan.Slice(ipLen, ipLen);

                var cmpStart = ByteCompare(ipBytes, sip);
                if (cmpStart < 0)
                {
                    high = mid - 1;
                    continue;
                }

                var cmpEnd = ByteCompare(ipBytes, eip);
                if (cmpEnd > 0)
                {
                    low = mid + 1;
                    continue;
                }

                dataLen = BinaryPrimitives.ReadUInt16LittleEndian(indexSpan.Slice(ipLen * 2, 2));
                dataPtr = BinaryPrimitives.ReadUInt32LittleEndian(indexSpan.Slice(ipLen * 2 + 2, 4));
                break;
            }
        }
        finally
        {
            if (rentedIndexBuffer is not null)
            {
                ArrayPool<byte>.Shared.Return(rentedIndexBuffer);
            }
        }

        switch (dataLen)
        {
            case 0:
                return string.Empty;
            case <= StackallocThreshold:
            {
                Span<byte> regionSpan = stackalloc byte[dataLen];
                Read(dataPtr, regionSpan);
                return Decode(regionSpan);
            }
            default:
            {
                var rented = ArrayPool<byte>.Shared.Rent(dataLen);
                try
                {
                    Read(dataPtr, rented.AsSpan(0, dataLen));
                    return Decode(rented.AsSpan(0, dataLen));
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }
        }
    }

    private static string Decode(ReadOnlySpan<byte> buffer)
    {
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
        return Encoding.UTF8.GetString(buffer);
#else
        if (buffer.IsEmpty)
        {
            return string.Empty;
        }

        var arr = new byte[buffer.Length];
        buffer.CopyTo(arr);
        return Encoding.UTF8.GetString(arr);
#endif
    }

    private static int ByteCompare(ReadOnlySpan<byte> ip1, ReadOnlySpan<byte> ip2)
        => ip1.Length == 4 ? IPv4Compare(ip1, ip2) : IPv6Compare(ip1, ip2);

    private static int IPv6Compare(ReadOnlySpan<byte> ip1, ReadOnlySpan<byte> ip2)
    {
        var a1 = BinaryPrimitives.ReadUInt64BigEndian(ip1);
        var a2 = BinaryPrimitives.ReadUInt64BigEndian(ip2);
        var cmp = a1.CompareTo(a2);
        if (cmp != 0) return cmp;

        var b1 = BinaryPrimitives.ReadUInt64BigEndian(ip1.Slice(8));
        var b2 = BinaryPrimitives.ReadUInt64BigEndian(ip2.Slice(8));
        return b1.CompareTo(b2);
    }

    private static int IPv4Compare(ReadOnlySpan<byte> ip1, ReadOnlySpan<byte> ip2)
    {
        for (var i = 0; i < ip1.Length; i++)
        {
            var ip2Index = ip1.Length - 1 - i;
            if (ip1[i] < ip2[ip2Index])
            {
                return -1;
            }

            if (ip1[i] > ip2[ip2Index])
            {
                return 1;
            }
        }

        return 0;
    }
}
