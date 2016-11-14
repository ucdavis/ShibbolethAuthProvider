using System;
using System.IdentityModel.Metadata;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web.Helpers;
using IdentityModel.Client;
using IdentityServer3.Core;
using IdentityServer3.Core.Configuration;
using Kentor.AuthServices;
using Kentor.AuthServices.Configuration;
using Kentor.AuthServices.Metadata;
using Kentor.AuthServices.Owin;
using Microsoft.Azure;
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
        public static readonly string BaseUrl = CloudConfigurationManager.GetSetting("BaseUrl");
        public static readonly string FederationUrl = CloudConfigurationManager.GetSetting("FederationUrl");

        public void Configuration(IAppBuilder app)
        {
            Options.GlobalEnableSha256XmlSignatures();

            // todo: replace with serilog
            //LogProvider.SetCurrentLogProvider(new DiagnosticsTraceLogProvider());

            AntiForgeryConfig.UniqueClaimTypeIdentifier = Constants.ClaimTypes.Subject;

            app.Map("/identity", idsrvApp =>
            {
                idsrvApp.UseIdentityServer(new IdentityServerOptions
                {
                    SiteName = "UC Identity Server",
                    SigningCertificate = LoadCertificate(),

                    Factory = new IdentityServerServiceFactory()
                    .UseInMemoryUsers(Users.Get())
                    .UseInMemoryClients(Clients.Get())
                    .UseInMemoryScopes(Scopes.Get()),
                    
                    AuthenticationOptions = new AuthenticationOptions
                    {
                        EnablePostSignOutAutoRedirect = true,
                        IdentityProviders = ConfigureIdentityProviders,
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
                ClientId = "web",
                Scope = "openid profile email saml",
                ResponseType = "id_token token",
                RedirectUri = BaseUrl,
                SignInAsAuthenticationType = "Cookies",
                UseTokenLifetime = false,

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = async n =>
                    {
                        var nid = new ClaimsIdentity(
                            n.AuthenticationTicket.Identity.AuthenticationType,
                            Constants.ClaimTypes.GivenName,
                            Constants.ClaimTypes.Role);

                        // get userinfo data
                        var userInfoClient = new UserInfoClient(
                            new Uri(n.Options.Authority + "/connect/userinfo"),
                            n.ProtocolMessage.AccessToken);

                        var userInfo = await userInfoClient.GetAsync();
                        userInfo.Claims.ToList().ForEach(ui => nid.AddClaim(new Claim(ui.Item1, ui.Item2)));

                        // keep the id_token for logout
                        nid.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));

                        // add access token for sample API
                        nid.AddClaim(new Claim("access_token", n.ProtocolMessage.AccessToken));

                        // keep track of access token expiration
                        nid.AddClaim(new Claim("expires_at", DateTimeOffset.Now.AddSeconds(int.Parse(n.ProtocolMessage.ExpiresIn)).ToString()));

                        // add some other app specific claim
                        nid.AddClaim(new Claim("app_specific", "some data"));
                        
                        n.AuthenticationTicket = new AuthenticationTicket(
                            nid,
                            n.AuthenticationTicket.Properties);
                    },

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

        private void ConfigureIdentityProviders(IAppBuilder app, string signInAsType)
        {
            // Configure Kentor SAML Identity Provider
            var authServicesOptions = new KentorAuthServicesAuthenticationOptions(false)
            {
                SPOptions = new SPOptions
                {
                    EntityId = new EntityId(BaseUrl),
                    ReturnUrl = new Uri(BaseUrl),
                    AttributeConsumingServices = { GetAttributeService() },
                    //WantAssertionsSigned = true,
                    //AuthenticateRequestSigningBehavior = SigningBehavior.IfIdpWantAuthnRequestsSigned // TODO: decide what needs to be here in prod
                },
                SignInAsAuthenticationType = signInAsType,
                AuthenticationType = "saml2p",
                Caption = "SAML2p",
            };

            // Map claims Shibboleth->OIDC using a custom claims manager: https://github.com/KentorIT/authservices/blob/master/doc/ClaimsAuthenticationManager.md
            authServicesOptions.SPOptions.SystemIdentityModelIdentityConfiguration.ClaimsAuthenticationManager =
                new ShibbolethClaimsMapper();

            authServicesOptions.SPOptions.ServiceCertificates.Add(LoadCertificate());

            var ucdShibIdp = new IdentityProvider(
                new EntityId("urn:mace:incommon:ucdavis.edu"),
                authServicesOptions.SPOptions)
            {
                LoadMetadata = true,
                MetadataLocation = "https://shibboleth.ucdavis.edu/idp/shibboleth",
                AllowUnsolicitedAuthnResponse = true,
            };

            ucdShibIdp.SigningKeys.AddConfiguredKey(LoadCertificate());
            authServicesOptions.IdentityProviders.Add(ucdShibIdp);

            // Federate against the IdP
            //new Federation(FederationUrl, true, authServicesOptions);

            app.UseKentorAuthServicesAuthentication(authServicesOptions);
        }

        AttributeConsumingService GetAttributeService()
        {
            var attributeConsumingService = new AttributeConsumingService("AuthServices")
            {
                IsDefault = true,
            };

            //ePPN
            attributeConsumingService.RequestedAttributes.Add(new RequestedAttribute("urn:oid:1.3.6.1.4.1.5923.1.1.1.6")
            {
                FriendlyName = "eduPersonPrincipalName",
                NameFormat = new Uri("urn:oasis:names:tc:SAML:2.0:attrname-format:uri"),          
                //AttributeValueXsiType = "ScopedAttributeDecoder"
                //IsRequired = true
            });

            //Affiliation
            attributeConsumingService.RequestedAttributes.Add(new RequestedAttribute("urn:oid:1.3.6.1.4.1.5923.1.1.1.9")
            {
                FriendlyName = "eduPersonScopedAffiliation",
                NameFormat = new Uri("urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
            });

            //SN (surname)
            attributeConsumingService.RequestedAttributes.Add(new RequestedAttribute("urn:oid:2.5.4.4")
            {
                FriendlyName = "sn",
                NameFormat = new Uri("urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
            });

            //givenName
            attributeConsumingService.RequestedAttributes.Add(new RequestedAttribute("urn:oid:2.5.4.42")
            {
                FriendlyName = "givenName",
                NameFormat = new Uri("urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
            });

            //eduPersonNickname
            attributeConsumingService.RequestedAttributes.Add(new RequestedAttribute("urn:oid:1.3.6.1.4.1.5923.1.1.1.2")
            {
                FriendlyName = "eduPersonNickname",
                NameFormat = new Uri("urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
            });

            //mail
            attributeConsumingService.RequestedAttributes.Add(new RequestedAttribute("urn:oid:0.9.2342.19200300.100.1.3")
            {
                FriendlyName = "mail",
                NameFormat = new Uri("urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
            });

            //displayName
            attributeConsumingService.RequestedAttributes.Add(new RequestedAttribute("urn:oid:2.16.840.1.113730.3.1.241")
            {
                FriendlyName = "displayName",
                NameFormat = new Uri("urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
            });

            return attributeConsumingService;
        }

        X509Certificate2 LoadCertificate()
        {
            var certThumbprint = CloudConfigurationManager.GetSetting("WEBSITE_LOAD_CERTIFICATES");

            return string.IsNullOrWhiteSpace(certThumbprint) ? LoadCertificateFromFile() : LoadCertificateFromCloud(certThumbprint);
        }

        X509Certificate2 LoadCertificateFromFile()
        {
            // TODO: get rid of test certificate
            return new X509Certificate2(
                string.Format(@"{0}\identity\idsrv3test.pfx", AppDomain.CurrentDomain.BaseDirectory), "idsrv3test");
        }

        /// <summary>
        /// Loads certificate from the azure certificate store.
        /// See https://azure.microsoft.com/en-us/blog/using-certificates-in-azure-websites-applications/
        /// Note: Need to have config setting WEBSITE_LOAD_CERTIFICATES with a value set to the certificate thumbprint
        /// </summary>
        /// <returns></returns>
        X509Certificate2 LoadCertificateFromCloud(string thumbprint)
        {
            X509Certificate2 certificate = null;

            X509Store certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            certStore.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certCollection = certStore.Certificates.Find(
                                       X509FindType.FindByThumbprint,
                                       thumbprint,
                                       false);
            // Get the first cert with the thumbprint
            if (certCollection.Count > 0)
            {
                certificate = certCollection[0];
            }
            certStore.Close();
            return certificate;
        }
    }
}