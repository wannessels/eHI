#if NETSTANDARD2_0
using System;

// WCF 4.x's .NET Standard contract does not expose this request-value type.
// Framework and modern .NET targets keep using their WCF Claim implementation.
namespace System.IdentityModel.Claims
{
    public class Claim
    {
        public Claim(string claimType, object resource, string right)
        { ClaimType = claimType ?? throw new ArgumentNullException(nameof(claimType)); Resource = resource; Right = right; }
        public string ClaimType { get; }
        public object Resource { get; }
        public string Right { get; }
        public override bool Equals(object value) => value is Claim claim && ClaimType == claim.ClaimType && Equals(Resource, claim.Resource) && Right == claim.Right;
        public override int GetHashCode() => ClaimType.GetHashCode() ^ (Resource?.GetHashCode() ?? 0) ^ (Right?.GetHashCode() ?? 0);
    }
}
#endif
