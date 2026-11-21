using System.Text.Json;

namespace VertexTweaks.Server;

public class Program
{
    public static void Main(string[] args)
    {
        // Załaduj .env jeśli istnieje
        var envPath = Path.Combine(Directory.GetCurrentDirectory(), ".env");
        if (File.Exists(envPath))
        {
            foreach (var line in File.ReadAllLines(envPath))
            {
                var trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("#")) continue;
                var parts = trimmed.Split('=', 2);
                if (parts.Length == 2)
                    Environment.SetEnvironmentVariable(parts[0].Trim(), parts[1].Trim());
            }
        }

        var builder = WebApplication.CreateBuilder(args);
        var app = builder.Build();

        // Konfiguracja z zmiennych środowiskowych
        var clientId = Environment.GetEnvironmentVariable("DISCORD_CLIENT_ID") ?? "";
        var clientSecret = Environment.GetEnvironmentVariable("DISCORD_CLIENT_SECRET") ?? "";
        var guildId = Environment.GetEnvironmentVariable("DISCORD_GUILD_ID") ?? "";
        var requiredRoleId = Environment.GetEnvironmentVariable("DISCORD_REQUIRED_ROLE_ID") ?? "";
        var jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? "change-me-in-production";
        var apiUrl = Environment.GetEnvironmentVariable("API_URL") ?? "http://localhost:5000";

        app.MapGet("/auth/discord", (HttpContext ctx) =>
        {
            int port = int.TryParse(ctx.Request.Query["port"], out var p) ? p : 17342;
            string state = $"{port}:{Guid.NewGuid()}";
            // Zapisz state w pamięci (lub bazie) — uproszczone: state zawiera port
            string redirectUri = $"{apiUrl}/auth/callback";
            string url = $"https://discord.com/api/oauth2/authorize?client_id={clientId}&redirect_uri={Uri.EscapeDataString(redirectUri)}&response_type=code&scope=identify%20guilds.members.read&state={state}";
            return Results.Redirect(url);
        });

        app.MapGet("/auth/callback", async (HttpContext ctx) =>
        {
            string? code = ctx.Request.Query["code"];
            string? state = ctx.Request.Query["state"];
            int port = 17342;
            if (state is not null && state.Contains(':'))
                int.TryParse(state.Split(':')[0], out port);

            if (string.IsNullOrWhiteSpace(code))
            {
                return Results.Redirect($"http://localhost:{port}/?error=Brak+kodu+autoryzacji");
            }

            // Wymień code na access token
            using var http = new HttpClient();
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = $"{apiUrl}/auth/callback"
            });

            var tokenResponse = await http.PostAsync("https://discord.com/api/oauth2/token", tokenRequest);
            if (!tokenResponse.IsSuccessStatusCode)
            {
                return Results.Redirect($"http://localhost:{port}/?error=Nie+udało+się+pobrać+tokenu");
            }

            var tokenJson = await tokenResponse.Content.ReadAsStringAsync();
            using var tokenDoc = JsonDocument.Parse(tokenJson);
            string accessToken = tokenDoc.RootElement.GetProperty("access_token").GetString() ?? "";

            // Pobierz dane użytkownika
            http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            var userResponse = await http.GetAsync("https://discord.com/api/users/@me");
            if (!userResponse.IsSuccessStatusCode)
            {
                return Results.Redirect($"http://localhost:{port}/?error=Nie+udało+się+pobrać+danych+użytkownika");
            }

            var userJson = await userResponse.Content.ReadAsStringAsync();
            using var userDoc = JsonDocument.Parse(userJson);
            string userId = userDoc.RootElement.GetProperty("id").GetString() ?? "";
            string username = userDoc.RootElement.GetProperty("username").GetString() ?? "";

            // Sprawdź członkostwo i rolę na serwerze
            var memberResponse = await http.GetAsync($"https://discord.com/api/users/@me/guilds/{guildId}/member");
            if (!memberResponse.IsSuccessStatusCode)
            {
                return Results.Redirect($"http://localhost:{port}/?error=Nie+jesteś+członkiem+serwera+Discord");
            }

            var memberJson = await memberResponse.Content.ReadAsStringAsync();
            using var memberDoc = JsonDocument.Parse(memberJson);
            var roles = memberDoc.RootElement.GetProperty("roles").EnumerateArray()
                .Select(r => r.GetString() ?? "").ToList();

            if (!roles.Contains(requiredRoleId))
            {
                return Results.Redirect($"http://localhost:{port}/?error=Brak+wymaganej+roli+na+serwerze+Discord");
            }

            // Wygeneruj JWT
            var jwt = GenerateJwt(userId, username, jwtSecret);
            return Results.Redirect($"http://localhost:{port}/?token={Uri.EscapeDataString(jwt)}");
        });

        app.MapGet("/api/verify", (HttpContext ctx) =>
        {
            string? auth = ctx.Request.Headers.Authorization.FirstOrDefault();
            if (string.IsNullOrWhiteSpace(auth) || !auth.StartsWith("Bearer "))
                return Results.Unauthorized();

            string token = auth.Substring("Bearer ".Length);
            if (!ValidateJwt(token, jwtSecret))
                return Results.Unauthorized();

            // Zwróć dane użytkownika z tokenu
            var claims = ParseJwt(token);
            return Results.Ok(new { username = claims.GetValueOrDefault("username", ""), valid = true });
        });

        app.Run();
    }

    private static string GenerateJwt(string userId, string username, string secret)
    {
        // Prosty JWT (HMAC-SHA256) — w produkcji użyj biblioteki (System.IdentityModel.Tokens.Jwt)
        var header = Base64UrlEncode("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        var payload = Base64UrlEncode($"{{\"sub\":\"{userId}\",\"username\":\"{username}\",\"exp\":{DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds()}}}");
        var signature = Base64UrlEncode(HmacSha256($"{header}.{payload}", secret));
        return $"{header}.{payload}.{signature}";
    }

    private static bool ValidateJwt(string token, string secret)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3) return false;
            var expectedSig = Base64UrlEncode(HmacSha256($"{parts[0]}.{parts[1]}", secret));
            if (parts[2] != expectedSig) return false;

            var payload = JsonDocument.Parse(Base64UrlDecode(parts[1]));
            if (payload.RootElement.TryGetProperty("exp", out var exp))
            {
                if (DateTimeOffset.FromUnixTimeSeconds(exp.GetInt64()) < DateTimeOffset.UtcNow)
                    return false;
            }
            return true;
        }
        catch { return false; }
    }

    private static Dictionary<string, string> ParseJwt(string token)
    {
        try
        {
            var parts = token.Split('.');
            var payload = JsonDocument.Parse(Base64UrlDecode(parts[1]));
            var dict = new Dictionary<string, string>();
            foreach (var p in payload.RootElement.EnumerateObject())
                dict[p.Name] = p.Value.ToString();
            return dict;
        }
        catch { return new(); }
    }

    private static string Base64UrlEncode(string input)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(input);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string Base64UrlDecode(string input)
    {
        string padded = input.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(padded));
    }

    private static byte[] HmacSha256(string data, string secret)
    {
        using var hmac = new System.Security.Cryptography.HMACSHA256(System.Text.Encoding.UTF8.GetBytes(secret));
        return hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data));
    }
}
