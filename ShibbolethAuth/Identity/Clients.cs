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
                        "https://localhost:44319/"
                    },
                    PostLogoutRedirectUris = new List<string>
                    {
                        "https://localhost:44319/"
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