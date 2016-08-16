using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Helpers;
using IdentityServer3.Core;
using IdentityServer3.Core.Configuration;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using ShibbolethAuth.Identity;
using AuthenticationOptions = IdentityServer3.Core.Configuration.AuthenticationOptions;

[assembly: OwinStartup(typeof(ShibbolethAuth.Startup))]

namespace ShibbolethAuth
{
    public class Startup
    {
        public static string BaseUrl = "https://shibbolethauthtest.azurewebsites.net/";

        public void Configuration(IAppBuilder app)
        {
            //Kentor.AuthServices.Configuration.Options.GlobalEnableSha256XmlSignatures();

            // todo: replace with serilog
            //LogProvider.SetCurrentLogProvider(new DiagnosticsTraceLogProvider());

            //AntiForgeryConfig.UniqueClaimTypeIdentifier = Constants.ClaimTypes.Subject;
            //JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();
            
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

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies"
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Authority = BaseUrl + "identity",

                ClientId = "mvc",
                Scope = "openid saml",
                ResponseType = "id_token token",
                RedirectUri = BaseUrl,
                SignInAsAuthenticationType = "Cookies",
                UseTokenLifetime = false,

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    //SecurityTokenValidated = async n =>
                    //{
                    //    var nid = new ClaimsIdentity(
                    //        n.AuthenticationTicket.Identity.AuthenticationType,
                    //        Constants.ClaimTypes.GivenName,
                    //        Constants.ClaimTypes.Role);

                    //    // get userinfo data
                    //    var userInfoClient = new UserInfoClient(
                    //        new Uri(n.Options.Authority + "/connect/userinfo"),
                    //        n.ProtocolMessage.AccessToken);

                    //    var userInfo = await userInfoClient.GetAsync();
                    //    userInfo.Claims.ToList().ForEach(ui => nid.AddClaim(new Claim(ui.Item1, ui.Item2)));

                    //    // keep the id_token for logout
                    //    nid.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));

                    //    // add access token for sample API
                    //    nid.AddClaim(new Claim("access_token", n.ProtocolMessage.AccessToken));

                    //    // keep track of access token expiration
                    //    nid.AddClaim(new Claim("expires_at", DateTimeOffset.Now.AddSeconds(int.Parse(n.ProtocolMessage.ExpiresIn)).ToString()));

                    //    // add some other app specific claim
                    //    nid.AddClaim(new Claim("app_specific", "some data"));

                    //    n.AuthenticationTicket = new AuthenticationTicket(
                    //        nid,
                    //        n.AuthenticationTicket.Properties);
                    //},

                    RedirectToIdentityProvider = n =>
                    {
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
                        {
                            var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token");

                            if (idTokenHint != null)
                            {
                                n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                            }
                        }

                        return Task.FromResult(0);
                    }
                }
            });
        }

    }
}