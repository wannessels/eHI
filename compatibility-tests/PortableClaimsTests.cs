using System;
using System.IdentityModel.Claims;
using Egelke.EHealth.Client.Sts;
using Xunit;

public class PortableClaimsTests
{
    [Fact]
    public void AuthenticationClaimValuesAndDialectArePreserved()
    {
        var claim = new Claim("urn:test:role", "doctor", AuthClaimSet.Dialect);
        var claims = new AuthClaimSet(claim);
        Assert.True(claims.Contains(new Claim(claim.ClaimType, claim.Resource, claim.Right)));
        var clone = (AuthClaimSet)claims.Clone(); claims.Clear();
        Assert.Equal(1, clone.Count);
        Assert.Throws<InvalidOperationException>(() => new AuthClaimSet(new Claim("urn:test:role", "doctor", "urn:unsupported")));
    }
}
