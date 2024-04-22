using Microsoft.AspNetCore.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace UserControl.Api.Authenticacao.IdentityService
{
    public class IdentityService
    {
        private readonly UserManager<IdentityUser> _userManager;

        public IdentityService( UserManager<IdentityUser> userManager) 
        {
            _userManager = userManager;
        }

        private async Task<IList<Claim>> GetClaimsAsync(IdentityUser user)
        {
            var claims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);

            claims.Add(new Claim(JwtRegisteredClaimNames.Sub,user.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email,user.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Nbf,DateTime.Now.ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Iat,DateTime.Now.ToString()));

            foreach (var role in roles) 
            {
                claims.Add(new Claim("role", role)); 
            }

            return claims;
        }
    }
}
