using Microsoft.AspNetCore.Mvc;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Model;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{


    private readonly ILogger<AuthController> _logger;
    private readonly IConfiguration _config;
    private UserRepository _userRepository;

    public AuthController(ILogger<AuthController> logger, IConfiguration config, UserRepository userRepository)
    {
        _config = config;
        _logger = logger;
        _userRepository = userRepository;

    }


    [HttpPost("addNewUser"), DisableRequestSizeLimit]
    public async Task<IActionResult> Post([FromBody] User? user)
    {
        _logger.LogInformation("AddNewUser funk ramt");

        var newUser = new User
        {
            UserName = user.UserName,
            UserPassword = user.UserPassword,
            UserEmail = user.UserEmail,
            UserPhone = user.UserPhone,
            UserAddress = user.UserAddress
        };
        _logger.LogInformation("Nyt user objekt lavet");


        _userRepository.AddNewUser(user);
        _logger.LogInformation("nyt user objekt added til User list");


        return Ok(newUser);

    }


    private string GenerateJwtToken(string username)
    {
        var securityKey =
        new
       SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Secret"]));

        var credentials =
        new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
 new Claim(ClaimTypes.NameIdentifier, username)
 };
        var token = new JwtSecurityToken(
        _config["Issuer"],
        "http://localhost",
        claims,
        expires: DateTime.Now.AddMinutes(60),
        signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }



    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] User user) // her skal hentes bruger fra mongo
    {
        _logger.LogInformation("Login metode ramt");

        var loginUser = await _userRepository.FindUserByUsernameAndPassword(user.UserName, user.UserPassword); // henter bruger
        _logger.LogInformation(user.UserName);

        if (user == null)
        {
            return Unauthorized();
        }

        var token = GenerateJwtToken(user.UserName);
        return Ok(new { token });
    }



    [AllowAnonymous]
    [HttpPost("validate")]
    public async Task<IActionResult> ValidateJwtToken([FromBody] string? token)
    {
        if (token.IsNullOrEmpty())
            return BadRequest("Invalid token submited.");
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_config["Secret"]!);
        try
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);
            var jwtToken = (JwtSecurityToken)validatedToken;
            var accountId = jwtToken.Claims.First(
            x => x.Type == ClaimTypes.NameIdentifier).Value;
            return Ok(accountId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, ex.Message);
            return StatusCode(404);
        }
    }
}