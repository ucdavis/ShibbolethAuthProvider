using System.Collections.Generic;
using IdentityServer3.Core.Services.InMemory;

namespace ShibbolethAuth.Identity
{
    public static class Users
    {
        public static List<InMemoryUser> Get()
        {
            return new List<InMemoryUser>();
        }
    }
}