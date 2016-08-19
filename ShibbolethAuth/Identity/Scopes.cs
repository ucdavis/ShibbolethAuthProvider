using System.Collections.Generic;
using IdentityServer3.Core.Models;

namespace ShibbolethAuth.Identity
{
    public static class Scopes
    {
        public static IEnumerable<Scope> Get()
        {
            var scopes = new List<Scope>
            {
                new Scope
                {
                    Enabled = true,
                    Name = "saml",
                    DisplayName = "Profile Information",
                    Description = "Basic profile information including your name",
                    Type = ScopeType.Identity,
                    Required = true,
                    Claims = new List<ScopeClaim>
                    {
                        new ScopeClaim("urn:oid:1.3.6.1.4.1.5923.1.1.1.6"),
                        new ScopeClaim("urn:oid:1.3.6.1.4.1.5923.1.1.1.9"),
                        new ScopeClaim("urn:oid:2.5.4.4"),
                        new ScopeClaim("urn:oid:2.5.4.42"),
                        new ScopeClaim("urn:oid:1.3.6.1.4.1.5923.1.1.1.2"),
                        new ScopeClaim("urn:oid:0.9.2342.19200300.100.1.3"),
                        new ScopeClaim("urn:oid:2.16.840.1.113730.3.1.241"),
                    }
                }
            };

            scopes.AddRange(StandardScopes.All);

            return scopes;
        }
    }
}