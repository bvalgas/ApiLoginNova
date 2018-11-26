using Dapper;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;

namespace APIAlturas
{
    public class UsersDAO
    {
        private IConfiguration _configuration;

        public UsersDAO(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public User Find(string userID)
        {
            using (SqlConnection conexao = new SqlConnection(
                _configuration.GetConnectionString("ExemploJWT")))
            {
                var user = conexao.QueryFirstOrDefault<User>(
                    "SELECT UserID, AccessKey " +
                    "FROM dbo.Users " +
                    "WHERE UserID = @UserID", new { UserID = userID });

                if (user != null)
                {
                    user.Roles = conexao.Query<Role>(
                    "SELECT R.Id, R.Name " +
                    "FROM dbo.UserRoles UR " +
                    "INNER JOIN dbo.Roles R on R.Id = UR.IdRole " +
                    "WHERE UR.IdUser = @UserID", new { UserID = userID });
                }

                return user;
            }
        }

        public User FindByToken(string refreshToken)
        {
            using (SqlConnection conexao = new SqlConnection(
                _configuration.GetConnectionString("ExemploJWT")))
            {
                var user = conexao.QueryFirstOrDefault<User>(
                    "SELECT UserID, AccessKey, RefreshToken " +
                    "FROM dbo.Users " +
                    "WHERE RefreshToken = @RefreshToken", new { RefreshToken = refreshToken });

                if (user != null)
                {
                    user.Roles = conexao.Query<Role>(
                    "SELECT R.Id, R.Name " +
                    "FROM dbo.UserRoles UR " +
                    "INNER JOIN dbo.Roles R on R.Id = UR.IdRole " +
                    "WHERE UR.IdUser = @UserID", new { UserID = user.UserID });
                }

                return user;
            }
        }

        public void UpdateRefreshToken(string userID, string refreshToken)
        {
            using (SqlConnection conexao = new SqlConnection(
                _configuration.GetConnectionString("ExemploJWT")))
            {
                conexao.Execute("UPDATE dbo.Users SET RefreshToken = @RefreshToken WHERE UserID = @UserID", new { RefreshToken = refreshToken, UserID = userID });
            }
        }
    }
}
