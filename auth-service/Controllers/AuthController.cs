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

    public AuthController(ILogger<AuthController> logger, IConfiguration config)
    {
        _config = config;
        _logger = logger;


        //Logger host information
        var hostName = System.Net.Dns.GetHostName();
        var ips = System.Net.Dns.GetHostAddresses(hostName);
        var _ipaddr = ips.First().MapToIPv4().ToString();
        _logger.LogInformation(1, $"Auth service responding from {_ipaddr}");

        _logger.LogInformation($"Connecting to rabbitMQ on {_config["rabbithostname"]}");

        _logger.LogInformation($"USER_SERVICE_URL: {_config["USER_SERVICE_URL"]}");
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
        expires: DateTime.Now.AddMonths(1),
        signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }



    [AllowAnonymous]
    [HttpPost("login/{userId}")]
    public async Task<IActionResult> Login([FromBody] UserDTO user, int userId) // her skal hentes bruger fra mongo
    {
        _logger.LogInformation("AuthService - Login function hit");

        using (HttpClient client = new HttpClient())
        {
            _logger.LogInformation("HTTPClient intialized");

            string userServiceUrl = Environment.GetEnvironmentVariable("USER_SERVICE_URL"); // retreives URL to UserService from docker-compose.yml file
            string getUserEndpoint = "/user/getUser/" + userId;

            _logger.LogInformation($"AuthService - {userServiceUrl + getUserEndpoint}");

            HttpResponseMessage response = await client.GetAsync(userServiceUrl + getUserEndpoint); // calls the UserService endpoint

            if (!response.IsSuccessStatusCode)
            {
                return StatusCode((int)response.StatusCode, "AuthService - Failed to retrieve UserId from UserService");
            }

            var userResponse = await response.Content.ReadFromJsonAsync<UserDTO>(); // deserializes the response from UserService

            var loginuser = userResponse;
            _logger.LogInformation(user.UserName);

            if (user == null)
            {
                return Unauthorized();
            }

            var token = GenerateJwtToken(user.UserName);
            return Ok(new { token });
        }
        return BadRequest("Failed to authenticate User with userId: + " + userId);
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