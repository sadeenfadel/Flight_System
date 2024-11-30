using FlightSystem.Core.Data;
using FlightSystem.Core.DTO;
using FlightSystem.Core.Repository;
using FlightSystem.Core.Services;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Infra.Services
{
    public class LoginService : ILoginService
    {

        private readonly ILoginRepository _loginRepository;

        public LoginService(ILoginRepository loginRepository)
        {
            _loginRepository = loginRepository;
        }

        public string Auth(Login login)
        {
            var result = _loginRepository.Auth(login);//username + roleid if matching or null if no match

            if (result == null)
            {
                return null;
            }
            else
            {
                var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SuperSecretKey@ApiCourse123456"));// at least 256 bit 32byte 
                var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

                var claims = new List<Claim>
                {
                     new Claim("username", result.Username),
                     new Claim("roleid", result.Roleid.ToString()),
                     new Claim("userid", result.Userid.ToString()),
                     new Claim("airlineid", result.Airlineid.ToString()),
                    new Claim("email", result.Email.ToString())

                };

                var tokeOptions = new JwtSecurityToken(
                                claims: claims,
                                expires: DateTime.Now.AddHours(12),
                                signingCredentials: signinCredentials
                        );
                var tokenString = new JwtSecurityTokenHandler().WriteToken(tokeOptions);
                return tokenString;

            }
        }
        public string AirlineAuth(Login login)
        {
            var result = _loginRepository.AirlineAuth(login);//username + roleid if matching or null if no match

            if (result == null)
            {
                return null;
            }
            else
            {
                var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SuperSecretKey@ApiCourse123456"));// at least 256 bit 32byte 
                var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

                var claims = new List<Claim>
                {
                     new Claim("username", result.Username),
                     new Claim("roleid", result.Roleid.ToString()),
                     new Claim("airlineid", result.Airlineid.ToString())
                };

                var tokeOptions = new JwtSecurityToken(
                                claims: claims,
                                expires: DateTime.Now.AddHours(12),
                                signingCredentials: signinCredentials
                        );
                var tokenString = new JwtSecurityTokenHandler().WriteToken(tokeOptions);
                return tokenString;
            }
        }


    }
}
