using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace APIAlturas.Controllers
{
    [Route("api/[controller]")]
    public class LoginController : Controller
    {
        //[AllowAnonymous]
        //[HttpPost]
        //public object Post(
        //    [FromBody]User usuario,
        //    [FromServices]UsersDAO usersDAO,
        //    [FromServices]SigningConfigurations signingConfigurations,
        //    [FromServices]TokenConfigurations tokenConfigurations)
        //{
        //    bool credenciaisValidas = false;
        //    if (usuario != null && !String.IsNullOrWhiteSpace(usuario.UserID))
        //    {
        //        var usuarioBase = usersDAO.Find(usuario.UserID);
        //        usuario.Roles = usuarioBase.Roles;
        //        credenciaisValidas = (usuarioBase != null &&
        //            usuario.UserID == usuarioBase.UserID &&
        //            usuario.AccessKey == usuarioBase.AccessKey);
        //    }

        //    if (credenciaisValidas)
        //    {
        //        ClaimsIdentity identity = new ClaimsIdentity(
        //            new GenericIdentity(usuario.UserID, "Login"),
        //            new[] {
        //                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
        //                new Claim(JwtRegisteredClaimNames.UniqueName, usuario.UserID)
        //            }
        //        );
                
        //        if(usuario.Roles != null)
        //        {
        //            foreach(var role in usuario.Roles)
        //            {
        //                identity.AddClaim(new Claim(ClaimTypes.Role, role.Name));
        //            }
        //        }

        //        DateTime dataCriacao = DateTime.Now;
        //        DateTime dataExpiracao = dataCriacao +
        //            TimeSpan.FromSeconds(tokenConfigurations.Seconds);

        //        var handler = new JwtSecurityTokenHandler();
        //        var securityToken = handler.CreateToken(new SecurityTokenDescriptor
        //        {
        //            Issuer = tokenConfigurations.Issuer,
        //            Audience = tokenConfigurations.Audience,
        //            SigningCredentials = signingConfigurations.SigningCredentials,
        //            Subject = identity,
        //            NotBefore = dataCriacao,
        //            Expires = dataExpiracao
        //        });
        //        var token = handler.WriteToken(securityToken);

        //        return new
        //        {
        //            authenticated = true,
        //            created = dataCriacao.ToString("yyyy-MM-dd HH:mm:ss"),
        //            expiration = dataExpiracao.ToString("yyyy-MM-dd HH:mm:ss"),
        //            accessToken = token,
        //            message = "OK"
        //        };
        //    }
        //    else
        //    {
        //        return new
        //        {
        //            authenticated = false,
        //            message = "Falha ao autenticar"
        //        };
        //    }
        //}


        [AllowAnonymous]
        [HttpPost]
        public object Post(
            [FromBody]AccessCredentials credenciais,
            [FromServices]UsersDAO usersDAO,
            [FromServices]SigningConfigurations signingConfigurations,
            [FromServices]TokenConfigurations tokenConfigurations)
        {
            bool credenciaisValidas = false;
            if (credenciais != null && !String.IsNullOrWhiteSpace(credenciais.UserID))
            {
                if (credenciais.GrantType == "password")
                {
                    var usuarioBase = usersDAO.Find(credenciais.UserID);
                    credenciaisValidas = (usuarioBase != null &&
                        credenciais.UserID == usuarioBase.UserID &&
                        credenciais.AccessKey == usuarioBase.AccessKey);
                }
                else if (credenciais.GrantType == "refresh_token")
                {
                    if (!String.IsNullOrWhiteSpace(credenciais.RefreshToken))
                    {
                        var usuarioBase = usersDAO.FindByToken(credenciais.RefreshToken);

                        credenciaisValidas = (usuarioBase != null &&
                            credenciais.UserID == usuarioBase.UserID &&
                            credenciais.RefreshToken == usuarioBase.RefreshToken); 
                    }

                }
            }

            if (credenciaisValidas)
            {
                return GenerateToken(
                    credenciais.UserID, signingConfigurations,
                    tokenConfigurations, usersDAO.Find(credenciais.UserID).Roles, usersDAO);
            }
            else
            {
                return new
                {
                    authenticated = false,
                    message = "Falha ao autenticar"
                };
            }
        }

        private object GenerateToken(string userID,
            SigningConfigurations signingConfigurations,
            TokenConfigurations tokenConfigurations, IEnumerable<Role> roles, UsersDAO usersDAO)
        {
            ClaimsIdentity identity = new ClaimsIdentity(
                new GenericIdentity(userID, "Login"),
                new[] {
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                        new Claim(JwtRegisteredClaimNames.UniqueName, userID)
                }
            );
            if (roles != null)
            {
                foreach (var role in roles)
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, role.Name));
                }
            }


            DateTime dataCriacao = DateTime.Now;
            DateTime dataExpiracao = dataCriacao +
                TimeSpan.FromSeconds(tokenConfigurations.Seconds);

            // Calcula o tempo máximo de validade do refresh token
            // (o mesmo será invalidado automaticamente pelo Redis)
            TimeSpan finalExpiration =
                TimeSpan.FromSeconds(tokenConfigurations.FinalExpiration);

var handler = new JwtSecurityTokenHandler();
var securityToken = handler.CreateToken(new SecurityTokenDescriptor
{
    Issuer = tokenConfigurations.Issuer,
    Audience = tokenConfigurations.Audience,
    SigningCredentials = signingConfigurations.SigningCredentials,
    Subject = identity,
    NotBefore = dataCriacao,
    Expires = dataExpiracao
});
var token = handler.WriteToken(securityToken);

var resultado = new
{
    authenticated = true,
    created = dataCriacao.ToString("yyyy-MM-dd HH:mm:ss"),
    expiration = dataExpiracao.ToString("yyyy-MM-dd HH:mm:ss"),
    accessToken = token,
    refreshToken = Guid.NewGuid().ToString().Replace("-", String.Empty),
    message = "OK"
};

            // Armazena o refresh token em cache através do Redis 
            var refreshTokenData = new RefreshTokenData();
            refreshTokenData.RefreshToken = resultado.refreshToken;
            refreshTokenData.UserID = userID;

            //salvar no banco o novo refresh token
            usersDAO.UpdateRefreshToken(userID, resultado.refreshToken);


            return resultado;
        }
    }



}