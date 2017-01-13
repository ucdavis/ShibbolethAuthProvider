using System.Collections.Generic;
using IdentityServer3.Core;
using IdentityServer3.Core.Models;

namespace ShibbolethAuth.Identity
{
    public static class Clients
    {
        public static IEnumerable<Client> Get()
        {
            return new[]
            {
                new Client
                {
                    ClientName = "Web Client",
                    ClientId = "web",
                    Flow = Flows.Implicit,

                    RedirectUris = new List<string>
                    {
                        Startup.BaseUrl
                    },
                    PostLogoutRedirectUris = new List<string>
                    {
                        Startup.BaseUrl
                    },
                    AllowedScopes = new List<string>
                    {
                        "openid",
                        "profile",
                        "email",
                        "saml"
                    }
                },
                new Client
                {
                    ClientName  = "Now Mobile",
                    ClientId = "nowmobile",
                    Flow = Flows.AuthorizationCode,
                    ClientSecrets = new List<Secret> { new Secret("secret".Sha256()) },
                    RedirectUris = new List<string>
                    {
                        "nowmobile://cb"
                    },
                    AllowedScopes = new List<string>
                    {
                        "openid",
                        "profile",
                        "saml"
                    }
                },
                new Client
                {
                    ClientName  = "Now Mobile",
                    ClientId = "nowimplicit",
                    ClientSecrets = new List<Secret> { new Secret("secret".Sha256()) },
                    Flow = Flows.Implicit,
                    Enabled = true,
                    AllowAccessToAllScopes = true,
                    AllowAccessTokensViaBrowser = true,
                    RequireConsent = false,
                    RedirectUris = new List<string>
                    {
                        "nowmobile://cb"
                    }
                },
                new Client()
                {
                    ClientName = "Core Tester",
                    ClientId = "coreauth",
                    Flow = Flows.Implicit,
                    RequireConsent = false,
                    RedirectUris = new List<string>() { "https://localhost:44370/signin-oidc" },
                    AllowAccessToAllScopes = true,
                },
                new Client()
                {
                    ClientName = "Campus Tester",
                    ClientId = "CampusCasOauth",
                    Flow = Flows.Implicit,
                    RequireConsent = false,
                    RedirectUris = new List<string>() { "https://localhost:44316/signin-oidc" },
                    AllowAccessToAllScopes = true,
                },
                new Client()
                {
                    ClientName = "Campus Tester Core",
                    ClientId = "CampusCasCode",
                    ClientSecrets = new List<Secret> { new Secret("y8huC52BE8E3".Sha256()) },
                    Flow = Flows.AuthorizationCode,
                    RequireConsent = false,
                    RedirectUris = new List<string>() { "https://localhost:44316/signin-oidc" },
                    AllowAccessToAllScopes = true,
                },
            };
        }
    }
}
