// Copyright 2025 The Ip2Region Authors. All rights reserved.
// Use of this source code is governed by a Apache2.0-style
// license that can be found in the LICENSE file.
// @Author Alan <lzh.shap@gmail.com>
// @Date   2023/07/25

using IP2Region.Net.Abstractions;
using IP2Region.Net.Internal;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Net;

namespace IP2Region.Net.XDB;

/// <summary>
/// <see cref="ISearcher"/> 实现类
/// </summary>
public class Searcher(CachePolicy cachePolicy, string xdbPath) : ISearcher
{
    private readonly ICacheStrategy _cacheStrategy = CacheStrategyFactory.CreateCacheStrategy(cachePolicy, xdbPath);

    public int IoCount => _cacheStrategy.IoCount;

    /// <summary>
    /// <inheritdoc/>
    /// </summary>
    public string? Search(string ipStr)
    {
        var ipAddress = IPAddress.Parse(ipStr);
        return Search(ipAddress);
    }

    /// <summary>
    /// <inheritdoc/>
    /// </summary>
    public string? Search(IPAddress ipAddress)
    {
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
        Span<byte> ipBytes = stackalloc byte[16];
        if (ipAddress.TryWriteBytes(ipBytes, out var bytesWritten))
        {
            return _cacheStrategy.Search(ipBytes.Slice(0, bytesWritten));
        }
#endif
        return _cacheStrategy.Search(ipAddress.GetAddressBytes());
    }

    /// <summary>
    /// <inheritdoc/>
    /// </summary>
    [Obsolete("已弃用，请改用其他方法；Deprecated; please use Search(string) or Search(IPAddress) method.")]
    [ExcludeFromCodeCoverage]
    public string? Search(uint ipAddress)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, ipAddress);
        return _cacheStrategy.Search(bytes);
    }

    /// <summary>
    /// <inheritdoc/>
    /// </summary>
    public void Dispose()
    {
        _cacheStrategy.Dispose();
        GC.SuppressFinalize(this);
    }
}
