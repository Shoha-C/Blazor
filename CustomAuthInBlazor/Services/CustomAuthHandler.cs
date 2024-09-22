using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;

namespace CustomAuthInBlazor.Services;

public class CustomAuthHandler(ILocalStorageService localStorageService) : AuthenticationStateProvider
{
    private readonly ILocalStorageService _localStorageService = localStorageService;

    public override async Task<AuthenticationState> 
        GetAuthenticationStateAsync()
    {

        var (userId, username, role) = await ReadJwtToken();

        var claimsPrincipal = await SetClaims(userId,username,role);
        
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(
            user: claimsPrincipal)));

        return await Task.FromResult(new AuthenticationState(
            user: claimsPrincipal));
    }



    public async Task<ClaimsPrincipal> 
        SetClaims(string? userId, string? username, string? role)
    {

        if (userId == null || username == null || role == null)
            return new ClaimsPrincipal();

        var claimsPrincipal = new ClaimsPrincipal(
            new ClaimsIdentity(
                new List<Claim>()
                {
                    new Claim(ClaimTypes.NameIdentifier,userId),
                    new Claim(ClaimTypes.Name,username),
                    new Claim(ClaimTypes.Role,role)
                }, authenticationType: "JwtAuth"));

        return claimsPrincipal;
    }


    public async Task<Tuple<string?,string?,string?>> ReadJwtToken()
    {
        var token = await _localStorageService.GetItemAsync<string>("token");

        if (string.IsNullOrEmpty(token))
        {
            return new(null, null, null);
        }

        var security = new JwtSecurityTokenHandler();

        var parsedToken = security.ReadJwtToken(token);

        string userId = parsedToken.Claims.
            FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier).Value;

        string username = parsedToken.Claims.
            FirstOrDefault(c => c.Type == ClaimTypes.Name).Value;

        string role = parsedToken.Claims.
            FirstOrDefault(c => c.Type == ClaimTypes.Role).Value;

        return new(userId, username, role);


    }
}