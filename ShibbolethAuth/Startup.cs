using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using IdentityServer3.Core.Configuration;
using Microsoft.Owin;
using Owin;
using ShibbolethAuth.Identity;

[assembly: OwinStartup(typeof(ShibbolethAuth.Startup))]

namespace ShibbolethAuth
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.Map("/identity", idsrvApp =>
            {
                idsrvApp.UseIdentityServer(new IdentityServerOptions
                {
                    SiteName = "UC Identity Server",
                    // SigningCertificate = LoadCertificate(),

                    Factory = new IdentityServerServiceFactory()
                    .UseInMemoryUsers(Users.Get())
                    .UseInMemoryClients(Clients.Get())
                    .UseInMemoryScopes(Scopes.Get()),

                    AuthenticationOptions = new AuthenticationOptions
                    {
                        EnablePostSignOutAutoRedirect = true,
                        //IdentityProviders = ConfigureIdentityProviders,
                        EnableLocalLogin = false,
                    }
                });
            });
        }
    }
}