using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using IdentityServer3.Core;

namespace ShibbolethAuth.Identity
{
    public class Claims
    {
        // map shibboleth attributes to openid profile attributes
        public static Dictionary<string, string> ShibbolethMap = new Dictionary<string, string>
        {
            {"urn:oid:2.5.4.4", Constants.ClaimTypes.FamilyName}, //sn
            {"urn:oid:2.5.4.42", Constants.ClaimTypes.GivenName}, //givenName
            {"urn:oid:1.3.6.1.4.1.5923.1.1.1.2", Constants.ClaimTypes.NickName}, //eduPersonNickname
            {"urn:oid:2.16.840.1.113730.3.1.241", Constants.ClaimTypes.Name}, //displayName
            {"urn:oid:0.9.2342.19200300.100.1.3", Constants.ClaimTypes.Email}, //mail
            //{"urn:oid:1.3.6.1.4.1.5923.1.1.1.6", Constants.ClaimTypes.ClientId}, //eduPersonPrincipalName
            {"urn:oid:1.3.6.1.4.1.5923.1.1.1.6", Constants.ClaimTypes.Id}, //eduPersonPrincipalName
            //{"urn:oid:1.3.6.1.4.1.5923.1.1.1.6", Constants.ClaimTypes.Subject}, //eduPersonPrincipalName
        };

        /// <summary>
        /// Get Oauth claim types from the shibboleth claims
        /// </summary>
        public static IEnumerable<Claim> ConvertToOauthClaims(Claim[] claims)
        {
            var oauthClaims = new List<Claim>();

            foreach (var claimMapItem in ShibbolethMap)
            {
                // see if there is a shibboleth claim for this item
                var shibbolethClaim = claims.FirstOrDefault(c => string.Equals(c.Type, claimMapItem.Key));

                if (shibbolethClaim != null && !string.IsNullOrWhiteSpace(shibbolethClaim.Value))
                {
                    // if so, add with the oauth claim name and existing value
                    oauthClaims.Add(new Claim(claimMapItem.Value, shibbolethClaim.Value));
                }
            }

            return oauthClaims;
        }
    }
}