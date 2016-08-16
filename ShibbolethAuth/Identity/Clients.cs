using System.Collections.Generic;
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
                        "saml"
                    }
                },
                new Client
                {
                    ClientName = "Auth0 Client",
                    ClientId = "auth0",
                    Flow = Flows.AuthorizationCode,

                    RedirectUris = new List<string>
                    {
                        "https://ucdavis.auth0.com/login/callback"
                    },
                    PostLogoutRedirectUris = new List<string>
                    {
                        "https://ucdavis.auth0.com/login/callback"
                    },
                    AllowedScopes = new List<string>
                    {
                        "openid",
                        "profile",
                        "saml"
                    }
                }
            };
        }
    }
}