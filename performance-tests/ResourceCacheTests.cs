using System;
using System.Linq;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Services;
using Xunit;

public class ResourceCacheTests
{
    private sealed class Resource : IDisposable
    {
        public int Disposals;
        public void Dispose() { Disposals++; }
    }

    [Fact]
    public async Task ReusesResourcesAndDefersDisposalUntilLastOperationFinishes()
    {
        var cache = new ResourceCache<int, Resource>((a, b) => a == b);
        int creations = 0;
        Func<int, Resource> create = _ => { creations++; return new Resource(); };
        var first = cache.Acquire(1, create);
        await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(() =>
        {
            using (var same = cache.Acquire(1, create)) Assert.Same(first.Value, same.Value);
        })));
        Assert.Equal(1, creations);
        var replacement = cache.Acquire(2, create);
        Assert.NotSame(first.Value, replacement.Value);
        Assert.Equal(0, first.Value.Disposals);
        cache.Dispose();
        Assert.Equal(0, replacement.Value.Disposals);
        first.Dispose(); first.Dispose(); replacement.Dispose(); cache.Dispose();
        Assert.Equal(1, first.Value.Disposals);
        Assert.Equal(1, replacement.Value.Disposals);
        Assert.Throws<ObjectDisposedException>(() => cache.Acquire(2, create));
    }
}
