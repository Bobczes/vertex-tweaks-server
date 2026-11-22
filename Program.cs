using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace VertexTweaks.Server;

public class Program
{
    private sealed class OAuthState
    {
        public int Port { get; set; }
        public DateTimeOffset Expires { get; set; }
    }

    private sealed class Session
    {
        public string Sid { get; set; } = "";
        public string UserId { get; set; } = "";
        public string Username { get; set; } = "";
        public string AccessToken { get; set; } = "";
        public string? RefreshToken { get; set; }
        public DateTimeOffset AccessTokenExpires { get; set; }
        public object Sync { get; } = new();
    }

    private static readonly ConcurrentDictionary<string, OAuthState> OAuthStates = new(StringComparer.Ordinal);
    private static readonly ConcurrentDictionary<string, Session> Sessions = new(StringComparer.Ordinal);

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
                    Environment.SetEnvironmentVariable(parts[0].Trim(), parts[1].Trim().Trim('"'));
            }
        }

        var builder = WebApplication.CreateBuilder(args);
        var app = builder.Build();

        // Konfiguracja z zmiennych środowiskowych — brak konfiguracji = serwer nie startuje.
        var clientId = Environment.GetEnvironmentVariable("DISCORD_CLIENT_ID") ?? "";
        var clientSecret = Environment.GetEnvironmentVariable("DISCORD_CLIENT_SECRET") ?? "";
        var guildId = Environment.GetEnvironmentVariable("DISCORD_GUILD_ID") ?? "";
        var requiredRoleId = Environment.GetEnvironmentVariable("DISCORD_REQUIRED_ROLE_ID") ?? "";
        var jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? "";
        var apiUrl = Environment.GetEnvironmentVariable("API_URL") ?? "http://localhost:5000";

        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret) ||
            string.IsNullOrWhiteSpace(guildId) || string.IsNullOrWhiteSpace(requiredRoleId))
            throw new InvalidOperationException("Brak konfiguracji Discord (DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_GUILD_ID, DISCORD_REQUIRED_ROLE_ID).");

        if (jwtSecret.Length < 16 || jwtSecret.Contains("change-me", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("JWT_SECRET musi być ustawiony i mieć co najmniej 16 znaków.");

        if (!Uri.TryCreate(apiUrl, UriKind.Absolute, out var apiUri) ||
            (apiUri.Scheme != Uri.UriSchemeHttp && apiUri.Scheme != Uri.UriSchemeHttps))
            throw new InvalidOperationException("API_URL jest nieprawidłowy.");

        var redirectUri = new Uri(apiUri, "/auth/callback").ToString();

        app.MapGet("/auth/discord", (HttpContext ctx) =>
        {
            string? state = ctx.Request.Query["state"];
            if (string.IsNullOrWhiteSpace(state))
                return Results.BadRequest("Brak parametru state.");

            if (!int.TryParse(ctx.Request.Query["port"], out var port) || port < 1024 || port > 65535)
                port = 17342;

            foreach (var key in OAuthStates.Keys)
            {
                if (OAuthStates.TryGetValue(key, out var old) && old.Expires < DateTimeOffset.UtcNow)
                    OAuthStates.TryRemove(key, out _);
            }

            OAuthStates[state] = new OAuthState { Port = port, Expires = DateTimeOffset.UtcNow.AddMinutes(10) };

            string url = $"https://discord.com/api/oauth2/authorize?client_id={Uri.EscapeDataString(clientId)}" +
                         $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                         "&response_type=code&scope=identify%20guilds.members.read" +
                         $"&state={Uri.EscapeDataString(state)}";
            return Results.Redirect(url);
        });

        app.MapGet("/auth/callback", async (HttpContext ctx) =>
        {
            string? code = ctx.Request.Query["code"];
            string? state = ctx.Request.Query["state"];

            if (string.IsNullOrWhiteSpace(state) ||
                !OAuthStates.TryRemove(state, out var oauth) ||
                oauth.Expires < DateTimeOffset.UtcNow)
                return Results.BadRequest("Nieprawidłowy lub wygasły stan logowania.");

            int port = oauth.Port;

            if (string.IsNullOrWhiteSpace(code))
                return CallbackRedirect(port, "Brak kodu autoryzacji", state);

            using var http = new HttpClient();
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = redirectUri
            });

            var tokenResponse = await http.PostAsync("https://discord.com/api/oauth2/token", tokenRequest);
            if (!tokenResponse.IsSuccessStatusCode)
                return CallbackRedirect(port, "Nie udało się pobrać tokenu", state);

            var tokenJson = await tokenResponse.Content.ReadAsStringAsync();
            using var tokenDoc = JsonDocument.Parse(tokenJson);
            var root = tokenDoc.RootElement;
            string accessToken = GetString(root, "access_token") ?? "";
            string? refreshToken = GetString(root, "refresh_token");
            int expiresIn = root.TryGetProperty("expires_in", out var exp) && exp.TryGetInt32(out int e) ? e : 3600;

            if (string.IsNullOrWhiteSpace(accessToken))
                return CallbackRedirect(port, "Nie udało się pobrać tokenu", state);

            using var userRequest = new HttpRequestMessage(HttpMethod.Get, "https://discord.com/api/users/@me");
            userRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            var userResponse = await http.SendAsync(userRequest);
            if (!userResponse.IsSuccessStatusCode)
                return CallbackRedirect(port, "Nie udało się pobrać danych użytkownika", state);

            var userJson = await userResponse.Content.ReadAsStringAsync();
            using var userDoc = JsonDocument.Parse(userJson);
            string userId = GetString(userDoc.RootElement, "id") ?? "";
            string username = GetString(userDoc.RootElement, "username") ?? "Użytkownik";

            string? error = await CheckRoleAsync(http, accessToken, userId, guildId, requiredRoleId);
            if (error is not null)
                return CallbackRedirect(port, error, state);

            var session = new Session
            {
                Sid = Guid.NewGuid().ToString("N"),
                UserId = userId,
                Username = username,
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                AccessTokenExpires = DateTimeOffset.UtcNow.AddSeconds(Math.Max(60, expiresIn))
            };
            Sessions[session.Sid] = session;

            var jwt = GenerateJwt(userId, username, session.Sid, jwtSecret);
            return Redirect(port, new Dictionary<string, string>
            {
                ["token"] = jwt,
                ["state"] = state
            });
        });

        app.MapGet("/api/verify", async (HttpContext ctx) =>
        {
            string? token = BearerToken(ctx);
            if (token is null || !ValidateJwt(token, jwtSecret, out var claims))
                return Results.Unauthorized();

            string sid = claims.GetValueOrDefault("sid", "");
            if (string.IsNullOrWhiteSpace(sid) || !Sessions.TryGetValue(sid, out var session))
                return Results.Unauthorized();

            // Token ważny 30 dni nie wystarcza — przy każdej weryfikacji sprawdzamy rolę na Discordzie.
            using var http = new HttpClient();
            string? error = await CheckRoleAsync(http, session.AccessToken, session.UserId, guildId, requiredRoleId);
            if (error is not null)
            {
                Sessions.TryRemove(sid, out _);
                return Results.Unauthorized();
            }

            return Results.Ok(new
            {
                username = claims.GetValueOrDefault("username", session.Username),
                valid = true
            });
        });

        app.MapPost("/api/logout", (HttpContext ctx) =>
        {
            string? token = BearerToken(ctx);
            if (token is null || !ValidateJwt(token, jwtSecret, out var claims))
                return Results.Unauthorized();

            string sid = claims.GetValueOrDefault("sid", "");
            if (!string.IsNullOrWhiteSpace(sid))
                Sessions.TryRemove(sid, out _);
            return Results.Ok(new { ok = true });
        });

        app.Run();
    }

    private static IResult CallbackRedirect(int port, string error, string state) =>
        Redirect(port, new Dictionary<string, string>
        {
            ["error"] = error,
            ["state"] = state
        });

    private static IResult Redirect(int port, IEnumerable<KeyValuePair<string, string>> query)
    {
        var parts = query.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}");
        return Results.Redirect($"http://localhost:{port}/?{string.Join('&', parts)}");
    }

    private static string? BearerToken(HttpContext ctx)
    {
        string? auth = ctx.Request.Headers.Authorization.FirstOrDefault();
        return auth is not null && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? auth["Bearer ".Length..].Trim()
            : null;
    }

    private static string? GetString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) ? value.GetString() : null;

    /// <summary>Sprawduje członkostwo i rolę. Zwraca null przy sukcesie, inaczej komunikat błędu.</summary>
    private static async Task<string?> CheckRoleAsync(
        HttpClient http, string accessToken, string userId, string guildId, string requiredRoleId)
    {
        string token = accessToken;
        var (error, roles) = await FetchRolesAsync(http, token, guildId);
        if (error == "unauthorized")
        {
            token = await RefreshAccessTokenAsync(http, accessToken) ?? "";
            if (string.IsNullOrWhiteSpace(token)) return "Token Discord wygasł. Zaloguj się ponownie.";
            (error, roles) = await FetchRolesAsync(http, token, guildId);
        }

        if (error is not null)
            return "Nie udało się sprawdzić roli na serwerze Discord.";

        return roles.Contains(requiredRoleId, StringComparer.Ordinal)
            ? null
            : "Brak wymaganej roli na serwerze Discord";
    }

    private static async Task<(string? Error, List<string> Roles)> FetchRolesAsync(
        HttpClient http, string token, string guildId)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get,
                $"https://discord.com/api/users/@me/guilds/{guildId}/member");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var response = await http.SendAsync(request);
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                return ("unauthorized", new List<string>());
            if (!response.IsSuccessStatusCode) return ("error", new List<string>());

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            if (!doc.RootElement.TryGetProperty("roles", out var arr))
                return ("error", new List<string>());
            var roles = arr.EnumerateArray().Select(r => r.GetString() ?? "").ToList();
            return (null, roles);
        }
        catch { return ("error", new List<string>()); }
    }

    private static async Task<string?> RefreshAccessTokenAsync(HttpClient http, string oldAccessToken)
    {
        // Sesja jest identyfikowana po tokenie — odnajdź ją i odśwież z refresh tokenu.
        var session = Sessions.Values.FirstOrDefault(s =>
            string.Equals(s.AccessToken, oldAccessToken, StringComparison.Ordinal));
        if (session is null || string.IsNullOrWhiteSpace(session.RefreshToken)) return null;

        lock (session.Sync)
        {
            if (DateTimeOffset.UtcNow < session.AccessTokenExpires.AddMinutes(-5) &&
                !string.IsNullOrWhiteSpace(session.AccessToken))
                return session.AccessToken;
        }

        var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = Environment.GetEnvironmentVariable("DISCORD_CLIENT_ID") ?? "",
            ["client_secret"] = Environment.GetEnvironmentVariable("DISCORD_CLIENT_SECRET") ?? "",
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = session.RefreshToken
        });

        try
        {
            var response = await http.PostAsync("https://discord.com/api/oauth2/token", form);
            if (!response.IsSuccessStatusCode) return null;

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            string? access = GetString(doc.RootElement, "access_token");
            if (string.IsNullOrWhiteSpace(access)) return null;

            string? refresh = GetString(doc.RootElement, "refresh_token") ?? session.RefreshToken;
            int expiresIn = doc.RootElement.TryGetProperty("expires_in", out var exp) && exp.TryGetInt32(out int e)
                ? e
                : 3600;

            lock (session.Sync)
            {
                session.AccessToken = access;
                session.RefreshToken = refresh;
                session.AccessTokenExpires = DateTimeOffset.UtcNow.AddSeconds(Math.Max(60, expiresIn));
            }
            return access;
        }
        catch { return null; }
    }

    private static string GenerateJwt(string userId, string username, string sid, string secret)
    {
        var header = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new { alg = "HS256", typ = "JWT" }));
        var payload = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new
        {
            sub = userId,
            username,
            sid,
            exp = DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds()
        }));
        var signature = Base64UrlEncode(HmacSha256($"{header}.{payload}", secret));
        return $"{header}.{payload}.{signature}";
    }

    private static bool ValidateJwt(string token, string secret, out Dictionary<string, string> claims)
    {
        claims = new Dictionary<string, string>();
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3) return false;

            var expected = HmacSha256($"{parts[0]}.{parts[1]}", secret);
            var actual = Base64UrlDecodeBytes(parts[2]);
            if (!CryptographicOperations.FixedTimeEquals(expected, actual)) return false;

            using var doc = JsonDocument.Parse(Base64UrlDecodeBytes(parts[1]));
            foreach (var p in doc.RootElement.EnumerateObject())
                claims[p.Name] = p.Value.ToString();

            if (!claims.ContainsKey("sid") || !claims.ContainsKey("exp")) return false;
            return DateTimeOffset.FromUnixTimeSeconds(long.Parse(claims["exp"])) >= DateTimeOffset.UtcNow;
        }
        catch { return false; }
    }

    private static string Base64UrlEncode(byte[] input) =>
        Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecodeBytes(string input)
    {
        string padded = input.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }

    private static byte[] HmacSha256(string data, string secret)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
    }
}
