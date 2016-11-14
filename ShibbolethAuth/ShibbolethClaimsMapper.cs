using System.Linq;
using System.Security.Claims;
using ShibbolethAuth.Identity;

namespace ShibbolethAuth
{
    /// <summary>
    /// Map our shibboleth claims to OAuth claims at SP authentication time
    /// </summary>
    public class ShibbolethClaimsMapper : ClaimsAuthenticationManager
    {
        public override ClaimsPrincipal Authenticate(string resourceName, ClaimsPrincipal incomingPrincipal)
        {
            foreach (var identity in incomingPrincipal.Identities)
            {
                identity.AddClaims(Claims.ConvertToOauthClaims(identity.Claims.ToArray()));
            }

            return base.Authenticate(resourceName, incomingPrincipal);
        }
    }
}