using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace APIAlturas
{
    public class AccessCredentials
    {
        public string UserID { get; set; }
        public string AccessKey { get; set; }
        public string RefreshToken { get; set; }
        public string GrantType { get; set; }
        public IEnumerable<Role> Roles { get; set; }
    }
    public class RefreshTokenData
    {
        public string RefreshToken { get; set; }
        public string UserID { get; set; }
    }
    public class User
    {
        public string UserID { get; set; }
        public string AccessKey { get; set; }
        public string RefreshToken { get; set; }
        public IEnumerable<Role> Roles { get; set; }
    }

    public class Role
    {
        public int Id { get; set; }
        public string Name { get; set; }
    }

    public class TokenConfigurations
    {
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public int Seconds { get; set; }
        public int FinalExpiration { get; set; }
    }

    public class SigningConfigurations
    {
        public SecurityKey Key { get; }
        public SigningCredentials SigningCredentials { get; }
        public IConfiguration Configuration { get; }
        public SigningConfigurations(IConfiguration configuration)
        {
            Configuration = configuration;
            //using (var provider = new RSACryptoServiceProvider(2048))
            //
            //    Key = new RsaSecurityKey(provider.ExportParameters(true));
            //}

            Key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration.GetSection("TokenConfigurations:Secret").Value));

            SigningCredentials = new SigningCredentials(Key, SecurityAlgorithms.HmacSha256);
        }
    }
}
