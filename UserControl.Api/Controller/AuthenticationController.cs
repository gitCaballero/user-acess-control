using Azure;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using NetDevPack.Identity.Jwt;
using NetDevPack.Identity.Jwt.Model;
using NetDevPack.Identity.Model;
using UserControl.Api.Authenticacao.Model;
using System.Data;
using System.Reflection;

namespace UserControl.Api.Authenticacao.Controller
{
    [ApiController]
    [Route("api/account")]
    public class AuthenticationController : ControllerBase
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly AppJwtSettings _appJwtSettings;
        private readonly ILogger<AuthenticationController> _logger;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AuthenticationController(SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager,
            IOptions<AppJwtSettings> appJwtSettings,
            ILogger<AuthenticationController> logger,
            RoleManager<IdentityRole> roleManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _appJwtSettings = appJwtSettings.Value;
            _logger = logger;
            _roleManager = roleManager;
        }

        /// <summary>
        /// RegisterUse - method for user registration
        /// </summary>
        /// <remarks>
        /// Example:
        /// 
        ///     POST /register
        ///     {
        ///        "Email": abc@gmail.com,
        ///        "Password": "Abc123.",
        ///        "ConfirmPassword": Abc123.
        ///     }
        ///     
        /// </remarks>
        /// <param name="registerUser.Email">User's Email</param>
        /// <param name="registerUser.Password">Access Password</param>
        /// <param name="registerUser.ConfirmPassword">Confirm Access Password</param>
        [HttpPost("register")]
        [ProducesResponseType(typeof(Response<IdentityResult>),StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(Response<IdentityResult>), StatusCodes.Status400BadRequest)]
        [Produces("application/json")]
        public async Task<ActionResult> RegisterUser(RegisterUser registerUser)
        {
            var roleName = "Guest";
            _logger.LogInformation($"Validing model - {MethodBase.GetCurrentMethod().Name}");
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var user = new IdentityUser()
            {
                UserName = registerUser.Email,
                Email = registerUser.Email,
                EmailConfirmed = true,
            };

            _logger.LogInformation($"Registering user and password - {MethodBase.GetCurrentMethod().Name}");

            var result = await _userManager.CreateAsync(user, registerUser.Password);


            if (result.Succeeded)
            {
                if (!await _roleManager.RoleExistsAsync(roleName))
                {
                    _logger.LogInformation($"Registering role {roleName} - {MethodBase.GetCurrentMethod().Name}");

                    var resultRolecreated = await _roleManager.CreateAsync(new IdentityRole { Name = roleName });

                    if (resultRolecreated.Succeeded)
                        _logger.LogInformation($"Role {roleName} successfully registered - {MethodBase.GetCurrentMethod().Name}");
                    else
                        _logger.LogError($"Role {roleName} registered falied  - {MethodBase.GetCurrentMethod().Name}");
                }

                else
                {
                    var resultRole = await _userManager.AddToRoleAsync(user, roleName);
                    if (resultRole.Succeeded)                    
                        _logger.LogInformation($"Role {roleName} successfully registered to user {user.UserName} - {MethodBase.GetCurrentMethod().Name}");
                    else
                        _logger.LogError($"Role {roleName} registered failed to user {user.UserName} - {MethodBase.GetCurrentMethod().Name}");
                }

                _logger.LogInformation($"User and password successfully registered - {MethodBase.GetCurrentMethod().Name}");

                return StatusCode(StatusCodes.Status201Created, GetUserResponse(user.Email));

            }

            return BadRequest(result);
        }


        /// <summary>
        /// Login - method for user login
        /// </summary>
        /// <remarks>
        /// Example:
        /// 
        ///     POST /login
        ///     {
        ///        "Email": abc@gmail.com,
        ///        "Password": "Abc123.",
        ///     }
        ///     
        /// </remarks>
        /// <param name="loginUser.Email">User Email</param>
        /// <param name="loginUser.Password">Access Password</param>
        [ProducesResponseType(typeof(Response<IdentityResult>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(Response<IdentityResult>), StatusCodes.Status400BadRequest)]
        [Produces("application/json")]
        [HttpPost("login")]
        public async Task<ActionResult> Login(LoginUser loginUser)
        {
            try
            {
                _logger.LogInformation($"Validing model - {MethodBase.GetCurrentMethod().Name}");

                if (!ModelState.IsValid) return BadRequest(ModelState);

                _logger.LogInformation($"By logging in for the user {loginUser.Email} - {MethodBase.GetCurrentMethod().Name}");

                var result = await _signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, false, false);

                if (result.Succeeded)
                {
                    _logger.LogInformation($"Return JWT for the user {loginUser.Email} - {MethodBase.GetCurrentMethod().Name}");

                    return Ok(GetFullJwt(loginUser.Email));
                }

                if (result.IsLockedOut)
                {
                    _logger.LogInformation($"The user {loginUser.Email} is blocked - {MethodBase.GetCurrentMethod().Name}");

                    return BadRequest("This user is blocked");
                }

                _logger.LogInformation($"Incorrect user {loginUser.Email} or password - {MethodBase.GetCurrentMethod().Name}");

                return BadRequest("Incorrect user or password");
            }
            catch (Exception ex)
            {
                _logger.LogError($"{ex.Message} - {MethodBase.GetCurrentMethod().Name}");

                return BadRequest(ex.Message);
            }
        }

        /// <summary>
        /// Logout - method to invalidate the user's current session
        /// </summary>
        /// <response code="200">Returns Ok when logged in successfully</response>
        /// <response code="500">Returns internal server error when logout fails</response>
        /// <returns>Return a JWT token</returns>
        [ProducesResponseType(typeof(Response<IdentityResult>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(Response<IdentityResult>), StatusCodes.Status500InternalServerError)]
        [Produces("application/json")]
        [HttpPost("logout")]
        public async Task<ActionResult> Logout()
        {
            try
            {
                _logger.LogInformation($"By logging out in for the current user - {MethodBase.GetCurrentMethod().Name}");

                await _signInManager.SignOutAsync();
                return Ok();

            }
            catch (Exception ex)
            {
                _logger.LogError($"{ex.Message} - {MethodBase.GetCurrentMethod().Name}");

                return StatusCode(500, ex.Message);
            }
        }

        /// <summary>
        /// ChangePassword - method to change user password
        /// </summary>
        /// <remarks>
        /// Example:
        /// 
        ///     POST /ChangePassword
        ///     {
        ///        "Email": abc@gmail.com,
        ///        "OldPassword": "Abc123.",
        ///        "NewPassword": "Qwert9876$",
        ///        "ConfirmPassword": "Qwert9876$."
        ///     }
        ///     
        /// </remarks>
        /// <param name="model.Email">User Email</param>
        /// <param name="model.OldPassword">Current Access Password</param>
        /// <param name="model.NewPassword">New Access Password</param>
        /// <param name="model.ConfirmPassword">Confirm the new Access Password</param>
        [ProducesResponseType(typeof(Response<IdentityResult>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(Response<IdentityResult>), StatusCodes.Status400BadRequest)]
        [Produces("application/json")]
        [HttpPost("ChangePassword")]
        public async Task<ActionResult> ChangePassword(ChangePasswordModel model)
        {
            try
            {
                _logger.LogInformation($"Validing model - {MethodBase.GetCurrentMethod().Name}");

                if (!ModelState.IsValid) return BadRequest(ModelState);

                _logger.LogInformation($"Checking if the user {model.Email} exists - {MethodBase.GetCurrentMethod().Name}");

                var userId = await _signInManager.UserManager.FindByEmailAsync(model.Email);


                if (userId is null)
                {
                    _logger.LogInformation($"User {model.Email} not found - {MethodBase.GetCurrentMethod().Name}");

                    return BadRequest("User does not exist");
                }

                _logger.LogInformation($"updating password for user {model.Email} - {MethodBase.GetCurrentMethod().Name}");

                var result = await _userManager.ChangePasswordAsync(userId, model.OldPassword, model.NewPassword);

                if (result.Succeeded)
                {
                    _logger.LogInformation($"Password changed successfully - {MethodBase.GetCurrentMethod().Name}");

                    return Ok("Password changed successfully");
                }

                var message = result.Errors.Select(x => x.Description).FirstOrDefault();

                _logger.LogWarning($"{message} - {MethodBase.GetCurrentMethod().Name}");

                return BadRequest(message);
            }
            catch (Exception ex)
            {
                _logger.LogError($"{ex.Message} - {MethodBase.GetCurrentMethod().Name}");

                return BadRequest(ex.Message);
            }
        }

        /// <summary>
        /// CreateRoles - method to register a new user role
        /// </summary>
        /// <remarks>
        /// Example:
        /// 
        ///     POST /CreateRoles?roleName={{roleName}}
        ///     
        /// </remarks>
        /// <param name="roleName">Role to be created</param>
        [ProducesResponseType(typeof(Response<IdentityResult>), StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(Response<IdentityResult>), StatusCodes.Status400BadRequest)]
        [HttpPost("CreateRoles")]
        public async Task<ActionResult> CreateRoles(string roleName)
        {
            try
            {
                if (string.IsNullOrEmpty(roleName))
                    return BadRequest($"RoleName required");

                _logger.LogInformation($"Verify if roleName exist - {MethodBase.GetCurrentMethod().Name}");

                var exist = await _roleManager.RoleExistsAsync(roleName);
                if (exist)
                    return BadRequest($"Role {roleName} exist");

                _logger.LogInformation($"Creating roleName {roleName} - {MethodBase.GetCurrentMethod().Name}");

                var result = await _roleManager.CreateAsync(new IdentityRole { Name = roleName });

                if (result.Succeeded)
                    return Ok(result);

                return BadRequest(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }

        }

        /// <summary>
        /// UpdateRoleUser - method to update the user role
        /// </summary>
        /// <remarks>
        /// Example:
        /// 
        ///     PUT /UpdateRoleUser?userName={{email}}?roleName={{role}}
        ///     
        /// </remarks>
        /// <param name="userName">User Email</param>
        /// <param name="roleName">Access Password</param>
        [ProducesResponseType(typeof(Response<IdentityResult>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(Response<IdentityResult>), StatusCodes.Status400BadRequest)]
        [Produces("application/json")]
        [HttpPut("UpdateRoleUser")]
        public async Task<ActionResult> UpdateRoleUser(string userName, string roleName)
        {
            try
            {
                if (string.IsNullOrEmpty(roleName))
                    return BadRequest($"RoleName required");
                
                if (string.IsNullOrEmpty(userName))
                    return BadRequest($"RoleName required");

                _logger.LogInformation($"Verify if roleName exist - {MethodBase.GetCurrentMethod().Name}");

                    var oldUser = await _userManager.FindByNameAsync(userName);
                var oldRoleName= _userManager.GetRolesAsync(oldUser).Result.FirstOrDefault();

                if (oldRoleName != roleName)
                {
                    if (!string.IsNullOrEmpty(oldRoleName))                    
                        _ = await _userManager.RemoveFromRoleAsync(oldUser, oldRoleName);
                    
                    var resultRole = await _userManager.AddToRoleAsync(oldUser, roleName);

                    if (resultRole.Succeeded)
                        return Ok(resultRole);
                    
                    return BadRequest(resultRole);
                }

                return BadRequest("Role is assign");

            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        private UserResponse GetFullJwt(string email)
        {
            _logger.LogInformation($"Building JWT for the user {email} into {MethodBase.GetCurrentMethod().Name}");

            return new JwtBuilder()
                .WithUserManager(_userManager)
                .WithJwtSettings(_appJwtSettings)
                .WithEmail(email)
                .WithJwtClaims()
                .WithUserClaims()
                .WithUserRoles()
                .BuildUserResponse();
        }

        private UserResponse GetUserResponse(string email)
        {
            return new JwtBuilder()
                .WithUserManager(_userManager)
                .WithJwtSettings(_appJwtSettings)
                .WithEmail(email)
                .WithJwtClaims()
                .WithUserClaims()
                .WithUserRoles()
                .BuildUserResponse();
        }
    }
}
