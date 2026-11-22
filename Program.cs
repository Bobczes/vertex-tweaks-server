using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;

namespace VertexTweaks.Server;

public class Program
{
    private const string JwtIssuer = "vertex-tweaks-server";
    private const string JwtAudience = "vertex-tweaks-client";
    private const int MaxJwtLength = 8192;
    private const int MaxOAuthStates = 512;
    private const string OAuthCookieName = "vtw_oauth";
    private const int DefaultClientPort = 17342;
    private const string DiscordIssuer = "https://discord.com";

    private static readonly TimeSpan JwtLifetime = TimeSpan.FromHours(2);
    private static readonly TimeSpan OAuthTtl = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan RoleCacheTtl = TimeSpan.FromSeconds(45);
    private static readonly TimeSpan MaxRetryAfter = TimeSpan.FromMinutes(1);
    private const int MaxDiscordResponseBytes = 64 * 1024;
    private const int MaxTokenExpiresInSeconds = 7 * 24 * 60 * 60;
    private static readonly HttpClient DiscordHttp = new() { Timeout = TimeSpan.FromSeconds(10) };

    private static readonly ConcurrentDictionary<string, OAuthState> OAuthStates = new(StringComparer.Ordinal);
    private static readonly ConcurrentDictionary<string, Session> Sessions = new(StringComparer.Ordinal);

    private sealed record DiscordConfig(
        string ClientId,
        string ClientSecret,
        string GuildId,
        string RequiredRoleId,
        string JwtSecret,
        string RedirectUri,
        bool SecureCookies);

    private sealed class OAuthState
    {
        public string State { get; set; } = "";
        public string ClientState { get; set; } = "";
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
        public DateTimeOffset Expires { get; set; }
        public bool CachedHasRole { get; set; }
        public DateTimeOffset RoleCheckedAt { get; set; } = DateTimeOffset.MinValue;
        public DateTimeOffset RetryAfterUntil { get; set; } = DateTimeOffset.MinValue;
        public Task<RefreshOutcome>? RefreshTask { get; set; }
        public object Sync { get; } = new();
    }

    private enum VerifyFailure { None, RoleMissing, Expired, Technical }

    private sealed record VerifyResult(VerifyFailure Failure, string Message)
    {
        public static readonly VerifyResult Ok = new(VerifyFailure.None, "");
    }

    private enum RefreshStatus { Ok, InvalidGrant, Technical }
    private sealed record RefreshOutcome(RefreshStatus Status, string? AccessToken);

    // Forbidden obejmuje 403/404 z Discorda: użytkownik nie jest członkiem guildu
    // lub nie ma dostępu do określonego serwera — to definitywna utrata roli.
    private enum RoleFetchStatus { Ok, Unauthorized, Forbidden, RateLimited, Technical }
    private sealed record RoleFetch(RoleFetchStatus Status, List<string> Roles, TimeSpan? RetryAfter);

    public static void Main(string[] args)
    {
        var baseEnv = Path.Combine(AppContext.BaseDirectory, ".env");
        var baseEnvLoaded = File.Exists(baseEnv);
        if (baseEnvLoaded) LoadEnvFile(baseEnv);
        var cwdEnv = Path.Combine(Directory.GetCurrentDirectory(), ".env");
        if (!baseEnvLoaded &&
            !string.Equals(Path.GetFullPath(cwdEnv), Path.GetFullPath(baseEnv), StringComparison.OrdinalIgnoreCase))
            LoadEnvFile(cwdEnv);

        // Konfiguracja jest walidowana przed zbudowaniem pipeline — fail-closed.
        var clientId = Environment.GetEnvironmentVariable("DISCORD_CLIENT_ID") ?? "";
        var clientSecret = Environment.GetEnvironmentVariable("DISCORD_CLIENT_SECRET") ?? "";
        var guildId = Environment.GetEnvironmentVariable("DISCORD_GUILD_ID") ?? "";
        var requiredRoleId = Environment.GetEnvironmentVariable("DISCORD_REQUIRED_ROLE_ID") ?? "";
        var jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? "";
        var apiUrl = Environment.GetEnvironmentVariable("API_URL") ?? "";

        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret) ||
            string.IsNullOrWhiteSpace(guildId) || string.IsNullOrWhiteSpace(requiredRoleId))
            throw new InvalidOperationException("Brak konfiguracji Discord (DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_GUILD_ID, DISCORD_REQUIRED_ROLE_ID).");

        if (IsPlaceholder(clientSecret))
            throw new InvalidOperationException("DISCORD_CLIENT_SECRET zawiera wartość przykładową — ustaw prawdziwy secret.");

        ValidateJwtSecret(jwtSecret);

        if (string.IsNullOrWhiteSpace(apiUrl))
            throw new InvalidOperationException("Brak konfiguracji API_URL (wymagany publiczny adres serwera).");

        if (!Uri.TryCreate(apiUrl, UriKind.Absolute, out var apiUri) ||
            (apiUri.Scheme != Uri.UriSchemeHttp && apiUri.Scheme != Uri.UriSchemeHttps) ||
            string.IsNullOrWhiteSpace(apiUri.Host) ||
            !string.IsNullOrEmpty(apiUri.UserInfo) ||
            apiUri.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(apiUri.Query) ||
            !string.IsNullOrEmpty(apiUri.Fragment))
            throw new InvalidOperationException("API_URL jest nieprawidłowy — podaj sam origin (np. https://host), bez ścieżki, userinfo, query i fragmentu.");

        var loopbackHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "localhost", "127.0.0.1", "::1", "[::1]" };
        if (apiUri.Scheme != Uri.UriSchemeHttps && !loopbackHosts.Contains(apiUri.Host))
            throw new InvalidOperationException("API_URL musi używać https dla adresów zdalnych.");

        var config = new DiscordConfig(
            clientId, clientSecret, guildId, requiredRoleId, jwtSecret,
            new Uri(apiUri, "/auth/callback").ToString(),
            apiUri.Scheme == Uri.UriSchemeHttps);

        var builder = WebApplication.CreateBuilder(args);

        // ASPNETCORE_URLS ma najwyższy priorytet; PORT jest wygodny dla Render/Railway.
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ASPNETCORE_URLS")) &&
            int.TryParse(Environment.GetEnvironmentVariable("PORT"), NumberStyles.Integer,
                CultureInfo.InvariantCulture, out var port) && port is >= 1 and <= 65535)
            builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = async (context, token) =>
            {
                var response = context.HttpContext.Response;
                SetNoStoreHeaders(context.HttpContext);
                response.StatusCode = StatusCodes.Status429TooManyRequests;
                response.Headers["Retry-After"] = "60";
                await response.WriteAsJsonAsync(new
                {
                    valid = false,
                    error = "rate_limited",
                    message = "Zbyt wiele żądań. Spróbuj ponownie za minutę."
                }, cancellationToken: token);
            };
            options.AddPolicy("auth", ctx => RateLimitPartition.GetFixedWindowLimiter(
                RatePartition(ctx, "auth", config),
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 12,
                    Window = TimeSpan.FromMinutes(1),
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0
                }));
            options.AddPolicy("api", ctx => RateLimitPartition.GetFixedWindowLimiter(
                RatePartition(ctx, "api", config),
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 120,
                    Window = TimeSpan.FromMinutes(1),
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0
                }));
        });

        var app = builder.Build();
        app.UseRateLimiter();

        using var cleanupCts = new CancellationTokenSource();
        app.Lifetime.ApplicationStopping.Register(() => cleanupCts.Cancel());
        _ = Task.Run(() => CleanupLoopAsync(cleanupCts.Token));

        app.MapGet("/auth/discord", (HttpContext ctx) =>
        {
            string? clientState = ctx.Request.Query["state"].ToString();
            if (string.IsNullOrWhiteSpace(clientState)) clientState = null;
            if (clientState is not null && !IsHex(clientState, 32, 128))
                return Results.BadRequest("Nieprawidłowy parametr state.");

            string portText = ctx.Request.Query["port"].ToString();
            if (!int.TryParse(portText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var clientPort) ||
                clientPort < 1024 || clientPort > 65535)
                clientPort = DefaultClientPort;

            PruneOAuthStates();
            if (OAuthStates.Count >= MaxOAuthStates)
                return Results.StatusCode(StatusCodes.Status429TooManyRequests);

            // Stan OAuth jest generowany przez serwer — klient nie może go narzucić.
            string serverState = RandomNumberGenerator.GetHexString(32, lowercase: true);
            var expires = DateTimeOffset.UtcNow.Add(OAuthTtl);
            var entry = new OAuthState
            {
                State = serverState,
                ClientState = clientState ?? "",
                Port = clientPort,
                Expires = expires
            };
            OAuthStates[serverState] = entry;

            // Podpisujemy stan, port, ważność i stan klienta kluczem JWT_SECRET.
            var payload = $"{serverState}.{clientPort}.{expires.ToUnixTimeSeconds()}.{entry.ClientState}";
            var cookieValue = Base64UrlEncode(Encoding.UTF8.GetBytes(payload)) + "." +
                              Base64UrlEncode(HmacSha256(payload, config.JwtSecret));
            ctx.Response.Cookies.Append(OAuthCookieName, cookieValue, new CookieOptions
            {
                HttpOnly = true,
                Secure = config.SecureCookies,
                SameSite = SameSiteMode.Lax,
                Path = "/auth",
                MaxAge = OAuthTtl,
                IsEssential = true
            });

            string url = $"https://discord.com/api/oauth2/authorize?client_id={Uri.EscapeDataString(config.ClientId)}" +
                         $"&redirect_uri={Uri.EscapeDataString(config.RedirectUri)}" +
                         "&response_type=code&scope=identify%20guilds.members.read" +
                         $"&state={Uri.EscapeDataString(serverState)}";
            return Results.Redirect(url);
        }).RequireRateLimiting("auth");

        app.MapGet("/auth/callback", async (HttpContext ctx) =>
        {
            SetNoStoreHeaders(ctx);

            string? code = ctx.Request.Query["code"].ToString();
            string? state = ctx.Request.Query["state"].ToString();
            string? issuer = ctx.Request.Query["iss"].ToString();

            if (string.IsNullOrWhiteSpace(state) || !IsHex(state, 32, 128))
            {
                DeleteOAuthCookie(ctx, config);
                return CallbackHtmlError(ctx, "Nieprawidłowy stan logowania.");
            }

            // RFC 9207 — odrzucamy mix-up, jeśli Discord zwróci obcy issuer.
            if (!string.IsNullOrWhiteSpace(issuer) && !string.Equals(issuer, DiscordIssuer, StringComparison.Ordinal))
            {
                DeleteOAuthCookie(ctx, config);
                return CallbackHtmlError(ctx, "Nieprawidłowe źródło logowania.");
            }

            if (!TryReadOAuthCookie(ctx, config.JwtSecret, out var cookieState, out var cookiePort,
                    out var clientState, out var cookieExpiry) ||
                !string.Equals(state, cookieState, StringComparison.Ordinal) ||
                cookieExpiry <= DateTimeOffset.UtcNow)
            {
                DeleteOAuthCookie(ctx, config);
                return CallbackRedirect(ctx, DefaultClientPort, "Nieprawidłowy lub wygasły stan logowania.", state);
            }

            if (!OAuthStates.TryRemove(state, out var oauth) ||
                oauth.Expires <= DateTimeOffset.UtcNow ||
                oauth.Port != cookiePort ||
                !string.Equals(oauth.ClientState, clientState, StringComparison.Ordinal))
            {
                DeleteOAuthCookie(ctx, config);
                return CallbackRedirect(ctx, cookiePort, "Nieprawidłowy lub wygasły stan logowania.", clientState);
            }

            int port = oauth.Port;
            DeleteOAuthCookie(ctx, config);

            if (string.IsNullOrWhiteSpace(code))
                return CallbackRedirect(ctx, port, "Brak kodu autoryzacji", ReturnedState(oauth, state));

            using var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = config.ClientId,
                ["client_secret"] = config.ClientSecret,
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = config.RedirectUri
            });

            using var tokenHttpMessage = new HttpRequestMessage(HttpMethod.Post, "https://discord.com/api/oauth2/token")
            {
                Content = tokenRequest
            };
            using var tokenResponse = await DiscordHttp.SendAsync(
                tokenHttpMessage, HttpCompletionOption.ResponseHeadersRead, ctx.RequestAborted);
            if (!tokenResponse.IsSuccessStatusCode)
                return CallbackRedirect(ctx, port, "Nie udało się pobrać tokenu", ReturnedState(oauth, state));

            var tokenJson = await ReadBoundedStringAsync(tokenResponse, ctx.RequestAborted);
            if (tokenJson is null ||
                !TryParseTokenResponse(tokenJson, out var accessToken, out var refreshToken, out var expiresIn) ||
                string.IsNullOrWhiteSpace(accessToken))
                return CallbackRedirect(ctx, port, "Nie udało się pobrać tokenu", ReturnedState(oauth, state));

            using var userRequest = new HttpRequestMessage(HttpMethod.Get, "https://discord.com/api/users/@me");
            userRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            using var userResponse = await DiscordHttp.SendAsync(
                userRequest, HttpCompletionOption.ResponseHeadersRead, ctx.RequestAborted);
            if (!userResponse.IsSuccessStatusCode)
                return CallbackRedirect(ctx, port, "Nie udało się pobrać danych użytkownika", ReturnedState(oauth, state));

            var userJson = await ReadBoundedStringAsync(userResponse, ctx.RequestAborted);
            if (userJson is null)
                return CallbackRedirect(ctx, port, "Nie udało się pobrać danych użytkownika", ReturnedState(oauth, state));
            string? userId;
            string? username;
            try
            {
                using var userDoc = JsonDocument.Parse(userJson);
                if (userDoc.RootElement.ValueKind != JsonValueKind.Object ||
                    !TryGetJsonString(userDoc.RootElement, "id", out userId) || string.IsNullOrWhiteSpace(userId))
                    return CallbackRedirect(ctx, port, "Nie udało się pobrać danych użytkownika", ReturnedState(oauth, state));
                if (!TryGetJsonString(userDoc.RootElement, "username", out username) || string.IsNullOrWhiteSpace(username))
                    username = "Użytkownik";
            }
            catch (JsonException)
            {
                return CallbackRedirect(ctx, port, "Nie udało się pobrać danych użytkownika", ReturnedState(oauth, state));
            }
            catch (InvalidOperationException)
            {
                return CallbackRedirect(ctx, port, "Nie udało się pobrać danych użytkownika", ReturnedState(oauth, state));
            }

            var session = new Session
            {
                Sid = Guid.NewGuid().ToString("N"),
                UserId = userId!,
                Username = username!,
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                AccessTokenExpires = TokenExpiry(expiresIn),
                Expires = DateTimeOffset.UtcNow.Add(JwtLifetime)
            };

            var roleResult = await CheckRoleAsync(session, config, ctx.RequestAborted);
            if (roleResult.Failure != VerifyFailure.None)
            {
                var message = roleResult.Failure == VerifyFailure.Technical
                    ? "Nie udało się sprawdzić roli na serwerze Discord."
                    : roleResult.Message;
                return CallbackRedirect(ctx, port, message, ReturnedState(oauth, state));
            }

            Sessions[session.Sid] = session;

            var jwt = GenerateJwt(session.UserId, session.Username, session.Sid, config);
            return RedirectToClient(ctx, port, new Dictionary<string, string>
            {
                ["token"] = jwt,
                ["state"] = ReturnedState(oauth, state)
            });
        }).RequireRateLimiting("auth");

        app.MapGet("/api/verify", async (HttpContext ctx) =>
        {
            SetNoStoreHeaders(ctx);
            string? token = BearerToken(ctx);
            if (token is null || !ValidateJwt(token, config, out var claims))
                return VerifyUnauthorized(ctx, "Token nieprawidłowy lub wygasł.");

            string sid = claims.GetValueOrDefault("sid", "");
            if (string.IsNullOrWhiteSpace(sid) || !Sessions.TryGetValue(sid, out var session))
                return VerifyUnauthorized(ctx, "Sesja wygasła. Zaloguj się ponownie.");

            lock (session.Sync)
            {
                if (session.Expires <= DateTimeOffset.UtcNow)
                {
                    Sessions.TryRemove(sid, out _);
                    return VerifyUnauthorized(ctx, "Sesja wygasła. Zaloguj się ponownie.");
                }
            }

            // 401 wyłącznie przy definitywnym braku roli / wygaśnięciu odświeżania.
            // Błędy techniczne Discorda (w tym 429) zwracają 503 — klient nie czyści tokenu.
            var result = await CheckRoleAsync(session, config, ctx.RequestAborted);
            if (result.Failure == VerifyFailure.Technical)
                return Results.Json(new { valid = false, error = "discord_unavailable", message = result.Message },
                    statusCode: StatusCodes.Status503ServiceUnavailable);

            if (result.Failure != VerifyFailure.None)
            {
                RevokeUserSessions(session.UserId);
                return VerifyUnauthorized(ctx, result.Message);
            }

            return Results.Ok(new
            {
                username = claims.GetValueOrDefault("username", session.Username),
                valid = true
            });
        }).RequireRateLimiting("api");

        // Usunięcie sesji jest idempotentne: wielokrotne wywołanie (również po wygaśnięciu
        // JWT, ale z poprawnym podpisem) zwraca 200 i nie może usunąć cudzej sesji.
        app.MapPost("/api/logout", (HttpContext ctx) =>
        {
            SetNoStoreHeaders(ctx);
            string? token = BearerToken(ctx);
            if (token is null || !ValidateJwt(token, config, out var claims, allowExpired: true))
                return VerifyUnauthorized(ctx, "Token nieprawidłowy.");

            string sid = claims.GetValueOrDefault("sid", "");
            if (string.IsNullOrWhiteSpace(sid))
                return VerifyUnauthorized(ctx, "Token nieprawidłowy.");

            Sessions.TryRemove(sid, out _);
            return Results.Ok(new { ok = true });
        }).RequireRateLimiting("api");

        app.Run();
    }

    private static string ReturnedState(OAuthState oauth, string serverState) =>
        string.IsNullOrEmpty(oauth.ClientState) ? serverState : oauth.ClientState;

    private static void SetNoStoreHeaders(HttpContext ctx)
    {
        ctx.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private";
        ctx.Response.Headers["Pragma"] = "no-cache";
        ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    }

    private static IResult VerifyUnauthorized(HttpContext ctx, string message)
    {
        SetNoStoreHeaders(ctx);
        ctx.Response.Headers["WWW-Authenticate"] = "Bearer";
        return Results.Json(new { valid = false, error = "unauthorized", message },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    private static void DeleteOAuthCookie(HttpContext ctx, DiscordConfig config) =>
        ctx.Response.Cookies.Delete(OAuthCookieName, new CookieOptions
        {
            HttpOnly = true,
            Secure = config.SecureCookies,
            SameSite = SameSiteMode.Lax,
            Path = "/auth"
        });

    private static IResult CallbackRedirect(HttpContext ctx, int port, string error, string state) =>
        RedirectToClient(ctx, port, new Dictionary<string, string>
        {
            ["error"] = error,
            ["state"] = state
        });

    private static IResult CallbackHtmlError(HttpContext ctx, string error)
    {
        SetNoStoreHeaders(ctx);
        var safeError = WebUtility.HtmlEncode(error);
        var html =
            "<!doctype html><html lang=\"pl\"><head><meta charset=\"utf-8\">" +
            "<meta name=\"referrer\" content=\"no-referrer\"><title>Vertex Tweaks</title></head>" +
            "<body style=\"font-family:sans-serif;text-align:center;padding:50px\">" +
            $"<h2>Błąd logowania</h2><p>{safeError}</p></body>" +
            "<script>try{history.replaceState(null,'',location.pathname);}catch(e){}</script></html>";
        return Results.Content(html, "text/html; charset=utf-8");
    }

    private static IResult RedirectToClient(HttpContext ctx, int port, IEnumerable<KeyValuePair<string, string>> query)
    {
        SetNoStoreHeaders(ctx);
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

    private static bool TryGetJsonString(JsonElement root, string name, out string? value)
    {
        value = null;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty(name, out var element) ||
            element.ValueKind != JsonValueKind.String)
            return false;
        value = element.GetString();
        return value is not null;
    }

    private static bool TryParseTokenResponse(string json, out string accessToken, out string? refreshToken, out int expiresIn)
    {
        accessToken = "";
        refreshToken = null;
        expiresIn = 3600;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object ||
                !TryGetJsonString(doc.RootElement, "access_token", out var access) ||
                string.IsNullOrWhiteSpace(access))
                return false;
            accessToken = access;
            if (TryGetJsonString(doc.RootElement, "refresh_token", out var refresh))
                refreshToken = refresh;
            if (doc.RootElement.TryGetProperty("expires_in", out var exp) &&
                exp.ValueKind == JsonValueKind.Number && exp.TryGetInt32(out var seconds) && seconds > 0)
                expiresIn = Math.Min(seconds, MaxTokenExpiresInSeconds);
            return true;
        }
        catch (JsonException) { return false; }
        catch (InvalidOperationException) { return false; }
    }

    /// <summary>Ogranicza nonce z Discorda, aby złe dane nie spowodowały przepełnienia daty.</summary>
    private static DateTimeOffset TokenExpiry(int expiresIn) =>
        DateTimeOffset.UtcNow.AddSeconds(Math.Clamp(expiresIn, 60, MaxTokenExpiresInSeconds));

    /// <summary>Czyta odpowiedź Discorda z twardym limitem rozmiaru (również dla chunked).</summary>
    private static async Task<string?> ReadBoundedStringAsync(HttpResponseMessage response, CancellationToken ct)
    {
        if (response.Content.Headers.ContentLength is long declared && declared > MaxDiscordResponseBytes)
            return null;

        using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var collected = new MemoryStream();
        var buffer = new byte[8192];
        int total = 0;
        while (true)
        {
            int allowed = Math.Min(buffer.Length, MaxDiscordResponseBytes - total + 1);
            int read = await stream.ReadAsync(buffer.AsMemory(0, allowed), ct);
            if (read == 0) break;
            total += read;
            if (total > MaxDiscordResponseBytes) return null;
            collected.Write(buffer, 0, read);
        }
        return Encoding.UTF8.GetString(collected.GetBuffer(), 0, (int)collected.Length);
    }

    /// <summary>Retry-After z nagłówka Discorda lub z pola retry_after w JSON.</summary>
    private static async Task<TimeSpan?> ParseRetryAfterAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            var retry = response.Headers.RetryAfter;
            if (retry?.Delta is { } delta) return delta;
            if (retry?.Date is { } date)
            {
                var until = date - DateTimeOffset.UtcNow;
                return until > TimeSpan.Zero ? until : TimeSpan.Zero;
            }
        }
        catch (FormatException) { /* uszkodzony nagłówek — spróbujemy body */ }

        var body = await ReadBoundedStringAsync(response, ct);
        if (body is null) return null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                doc.RootElement.TryGetProperty("retry_after", out var element) &&
                element.ValueKind == JsonValueKind.Number &&
                element.TryGetDouble(out var seconds) &&
                double.IsFinite(seconds) && seconds >= 0 && seconds <= MaxRetryAfter.TotalSeconds)
                return TimeSpan.FromSeconds(seconds);
        }
        catch (JsonException) { }
        catch (InvalidOperationException) { }
        return null;
    }

    private static bool IsInvalidGrant(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.ValueKind == JsonValueKind.Object &&
                   TryGetJsonString(doc.RootElement, "error", out var error) &&
                   string.Equals(error, "invalid_grant", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static bool TryReadOAuthCookie(HttpContext ctx, string secret, out string state, out int port,
        out string clientState, out DateTimeOffset expires)
    {
        state = "";
        port = 0;
        clientState = "";
        expires = DateTimeOffset.MinValue;

        if (!ctx.Request.Cookies.TryGetValue(OAuthCookieName, out var cookie) || string.IsNullOrEmpty(cookie))
            return false;

        var parts = cookie.Split('.');
        if (parts.Length != 2)
            return false;

        byte[] signature;
        string payload;
        try
        {
            signature = Base64UrlDecodeBytes(parts[1]);
            payload = Encoding.UTF8.GetString(Base64UrlDecodeBytes(parts[0]));
        }
        catch (FormatException) { return false; }
        catch (ArgumentException) { return false; }

        if (!CryptographicOperations.FixedTimeEquals(HmacSha256(payload, secret), signature))
            return false;

        var fields = payload.Split('.');
        if (fields.Length != 4 || !IsHex(fields[0], 32, 128))
            return false;
        if (!int.TryParse(fields[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out port) ||
            port < 1024 || port > 65535)
            return false;
        if (!long.TryParse(fields[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var unixExpiry))
            return false;
        clientState = fields[3];
        if (clientState.Length != 0 && !IsHex(clientState, 32, 128))
            return false;

        try
        {
            expires = DateTimeOffset.FromUnixTimeSeconds(unixExpiry);
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
        state = fields[0];
        return true;
    }

    /// <summary>Sprawdza rolę z krótkim cache; rozróżnia błąd techniczny od definitywnej utraty roli.</summary>
    private static async Task<VerifyResult> CheckRoleAsync(Session session, DiscordConfig config, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        string accessToken;
        lock (session.Sync)
        {
            // Świeży cache jest autorytatywny — chwilowy 429 Discorda nie może
            // zamienić ważnej, właśnie sprawdzonej roli w błąd techniczny.
            if (session.RoleCheckedAt > DateTimeOffset.MinValue && now - session.RoleCheckedAt < RoleCacheTtl)
                return session.CachedHasRole
                    ? VerifyResult.Ok
                    : new VerifyResult(VerifyFailure.RoleMissing, "Brak wymaganej roli na serwerze Discord");
            if (session.RetryAfterUntil > now)
                return new VerifyResult(VerifyFailure.Technical, "Discord ogranicza żądania. Spróbuj ponownie później.");
            accessToken = session.AccessToken;
        }

        var fetch = await FetchRolesAsync(accessToken, config.GuildId, ct);
        if (fetch.Status == RoleFetchStatus.Unauthorized)
        {
            var refresh = await RefreshAccessTokenAsync(session, config, ct);
            if (refresh.Status == RefreshStatus.InvalidGrant)
                return new VerifyResult(VerifyFailure.Expired, "Token Discord wygasł. Zaloguj się ponownie.");
            if (refresh.Status != RefreshStatus.Ok || string.IsNullOrWhiteSpace(refresh.AccessToken))
                return new VerifyResult(VerifyFailure.Technical, "Nie udało się odświeżyć tokenu Discord.");

            accessToken = refresh.AccessToken!;
            fetch = await FetchRolesAsync(accessToken, config.GuildId, ct);
        }

        if (fetch.Status == RoleFetchStatus.Forbidden)
        {
            // 403/404 z /users/@me/guilds/{id}/member = definitywny brak członkostwa/dostępu.
            lock (session.Sync)
            {
                session.CachedHasRole = false;
                session.RoleCheckedAt = DateTimeOffset.UtcNow;
            }
            return new VerifyResult(VerifyFailure.RoleMissing, "Użytkownik nie jest członkiem serwera Discord lub nie ma wymaganej roli");
        }

        if (fetch.Status == RoleFetchStatus.RateLimited)
        {
            var delay = ClampRetry(fetch.RetryAfter ?? TimeSpan.FromSeconds(30));
            lock (session.Sync) session.RetryAfterUntil = DateTimeOffset.UtcNow + delay;
            return new VerifyResult(VerifyFailure.Technical, "Discord ogranicza żądania. Spróbuj ponownie później.");
        }

        if (fetch.Status != RoleFetchStatus.Ok)
            return new VerifyResult(VerifyFailure.Technical, "Nie udało się sprawdzić roli na serwerze Discord.");

        bool hasRole = fetch.Roles.Contains(config.RequiredRoleId, StringComparer.Ordinal);
        lock (session.Sync)
        {
            session.CachedHasRole = hasRole;
            session.RoleCheckedAt = DateTimeOffset.UtcNow;
        }
        return hasRole
            ? VerifyResult.Ok
            : new VerifyResult(VerifyFailure.RoleMissing, "Brak wymaganej roli na serwerze Discord");
    }

    private static async Task<RoleFetch> FetchRolesAsync(string token, string guildId, CancellationToken ct)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get,
                $"https://discord.com/api/users/@me/guilds/{Uri.EscapeDataString(guildId)}/member");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var response = await DiscordHttp.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
                return new RoleFetch(RoleFetchStatus.Unauthorized, new List<string>(), null);
            if (response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound)
                return new RoleFetch(RoleFetchStatus.Forbidden, new List<string>(), null);
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
                return new RoleFetch(RoleFetchStatus.RateLimited, new List<string>(),
                    await ParseRetryAfterAsync(response, ct));
            if (!response.IsSuccessStatusCode)
                return new RoleFetch(RoleFetchStatus.Technical, new List<string>(), null);

            var json = await ReadBoundedStringAsync(response, ct);
            if (json is null)
                return new RoleFetch(RoleFetchStatus.Technical, new List<string>(), null);
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object ||
                !doc.RootElement.TryGetProperty("roles", out var arr) ||
                arr.ValueKind != JsonValueKind.Array)
                return new RoleFetch(RoleFetchStatus.Technical, new List<string>(), null);

            var roles = new List<string>();
            foreach (var role in arr.EnumerateArray())
            {
                if (role.ValueKind == JsonValueKind.String)
                {
                    var value = role.GetString();
                    if (value is not null) roles.Add(value);
                }
            }
            return new RoleFetch(RoleFetchStatus.Ok, roles, null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or HttpRequestException or OperationCanceledException)
        {
            return new RoleFetch(RoleFetchStatus.Technical, new List<string>(), null);
        }
    }

    private static async Task<RefreshOutcome> RefreshAccessTokenAsync(Session session, DiscordConfig config, CancellationToken ct)
    {
        Task<RefreshOutcome> task;
        lock (session.Sync)
        {
            if (session.RefreshTask is not null)
            {
                task = session.RefreshTask;
            }
            else if (DateTimeOffset.UtcNow < session.AccessTokenExpires.AddMinutes(-5) &&
                     !string.IsNullOrWhiteSpace(session.AccessToken))
            {
                return new RefreshOutcome(RefreshStatus.Ok, session.AccessToken);
            }
            else
            {
                // Jedno odświeżanie na sesję — równoległe /api/verify nie wykonują rotacji 2×.
                task = RefreshCoreAsync(session, config);
                session.RefreshTask = task;
            }
        }

        try
        {
            return await task.WaitAsync(ct);
        }
        finally
        {
            lock (session.Sync)
            {
                if (ReferenceEquals(session.RefreshTask, task)) session.RefreshTask = null;
            }
        }
    }

    private static async Task<RefreshOutcome> RefreshCoreAsync(Session session, DiscordConfig config)
    {
        string? refreshToken;
        lock (session.Sync) refreshToken = session.RefreshToken;
        if (string.IsNullOrWhiteSpace(refreshToken))
            return new RefreshOutcome(RefreshStatus.InvalidGrant, null);

        try
        {
            using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = config.ClientId,
                ["client_secret"] = config.ClientSecret,
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken
            });
            using var refreshRequest = new HttpRequestMessage(HttpMethod.Post, "https://discord.com/api/oauth2/token")
            {
                Content = form
            };
            using var response = await DiscordHttp.SendAsync(
                refreshRequest, HttpCompletionOption.ResponseHeadersRead, CancellationToken.None);

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                var delay = ClampRetry(
                    await ParseRetryAfterAsync(response, CancellationToken.None) ?? TimeSpan.FromSeconds(30));
                lock (session.Sync) session.RetryAfterUntil = DateTimeOffset.UtcNow + delay;
                return new RefreshOutcome(RefreshStatus.Technical, null);
            }
            if (!response.IsSuccessStatusCode)
            {
                var body = await ReadBoundedStringAsync(response, CancellationToken.None);
                return body is not null && IsInvalidGrant(body)
                    ? new RefreshOutcome(RefreshStatus.InvalidGrant, null)
                    : new RefreshOutcome(RefreshStatus.Technical, null);
            }

            var json = await ReadBoundedStringAsync(response, CancellationToken.None);
            if (json is null ||
                !TryParseTokenResponse(json, out var access, out var rotatedRefresh, out var expiresIn) ||
                string.IsNullOrWhiteSpace(access))
                return new RefreshOutcome(RefreshStatus.Technical, null);

            lock (session.Sync)
            {
                session.AccessToken = access;
                session.RefreshToken = rotatedRefresh ?? session.RefreshToken;
                session.AccessTokenExpires = TokenExpiry(expiresIn);
            }
            return new RefreshOutcome(RefreshStatus.Ok, access);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or HttpRequestException or OperationCanceledException)
        {
            return new RefreshOutcome(RefreshStatus.Technical, null);
        }
    }

    private static TimeSpan ClampRetry(TimeSpan retry) =>
        retry < TimeSpan.Zero ? TimeSpan.Zero : retry > MaxRetryAfter ? MaxRetryAfter : retry;

    private static void RevokeUserSessions(string userId)
    {
        foreach (var pair in Sessions)
            if (string.Equals(pair.Value.UserId, userId, StringComparison.Ordinal))
                Sessions.TryRemove(pair.Key, out _);
    }

    private static string GenerateJwt(string userId, string username, string sid, DiscordConfig config)
    {
        var now = DateTimeOffset.UtcNow;
        var header = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new { alg = "HS256", typ = "JWT" }));
        var payload = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new
        {
            sub = userId,
            username,
            sid,
            iss = JwtIssuer,
            aud = JwtAudience,
            iat = now.ToUnixTimeSeconds(),
            exp = now.Add(JwtLifetime).ToUnixTimeSeconds(),
            jti = Guid.NewGuid().ToString("N")
        }));
        var signature = Base64UrlEncode(HmacSha256($"{header}.{payload}", config.JwtSecret));
        return $"{header}.{payload}.{signature}";
    }

    private static bool ValidateJwt(string token, DiscordConfig config, out Dictionary<string, string> claims,
        bool allowExpired = false)
    {
        claims = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(token) || token.Length > MaxJwtLength)
            return false;

        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3 || parts.Any(p => string.IsNullOrEmpty(p)))
                return false;

            using var headerDoc = JsonDocument.Parse(Base64UrlDecodeBytes(parts[0]));
            if (headerDoc.RootElement.ValueKind != JsonValueKind.Object ||
                !TryGetJsonString(headerDoc.RootElement, "alg", out var alg) ||
                !string.Equals(alg, "HS256", StringComparison.Ordinal) ||
                !TryGetJsonString(headerDoc.RootElement, "typ", out var typ) ||
                !string.Equals(typ, "JWT", StringComparison.OrdinalIgnoreCase))
                return false;

            var expected = HmacSha256($"{parts[0]}.{parts[1]}", config.JwtSecret);
            var actual = Base64UrlDecodeBytes(parts[2]);
            if (!CryptographicOperations.FixedTimeEquals(expected, actual))
                return false;

            using var doc = JsonDocument.Parse(Base64UrlDecodeBytes(parts[1]));
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return false;

            foreach (var p in doc.RootElement.EnumerateObject())
                claims[p.Name] = p.Value.ValueKind == JsonValueKind.String
                    ? p.Value.GetString() ?? ""
                    : p.Value.GetRawText();

            if (!claims.TryGetValue("sid", out var sid) || string.IsNullOrWhiteSpace(sid)) return false;
            if (!claims.TryGetValue("jti", out var jti) || string.IsNullOrWhiteSpace(jti)) return false;
            if (!claims.TryGetValue("iss", out var iss) || !string.Equals(iss, JwtIssuer, StringComparison.Ordinal)) return false;
            if (!claims.TryGetValue("aud", out var aud) || !string.Equals(aud, JwtAudience, StringComparison.Ordinal)) return false;
            if (!claims.TryGetValue("exp", out var expText) ||
                !long.TryParse(expText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var exp)) return false;
            if (!claims.TryGetValue("iat", out var iatText) ||
                !long.TryParse(iatText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var iat)) return false;

            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (!allowExpired && exp <= now) return false;
            // 60 s tolerancji dla przyszłego iat (clock skew); brak refresh endpointu.
            if (iat > now + 60 || exp - iat > (long)JwtLifetime.TotalSeconds + 60)
                return false;
            return true;
        }
        catch (JsonException) { return false; }
        catch (InvalidOperationException) { return false; }
        catch (FormatException) { return false; }
        catch (ArgumentException) { return false; }
    }

    private static string RatePartition(HttpContext ctx, string bucket, DiscordConfig config)
    {
        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (bucket != "api") return $"{bucket}:{ip}";
        // sid musi pochodzić z podpisanego tokenu — inaczej napastnik mógłby
        // dowolnym payloadem JWT resetować limit dla tego samego IP.
        var sid = PeekSid(ctx, config);
        return string.IsNullOrEmpty(sid) ? $"{bucket}:{ip}" : $"{bucket}:{ip}:{sid}";
    }

    /// <summary>Tylko do klucza rate limitu — nie używamy tego do autoryzacji.</summary>
    private static string PeekSid(HttpContext ctx, DiscordConfig config)
    {
        var token = BearerToken(ctx);
        if (token is null || !ValidateJwt(token, config, out var claims)) return "";
        return claims.GetValueOrDefault("sid", "");
    }

    private static bool IsHex(string value, int minLength, int maxLength)
    {
        if (value.Length < minLength || value.Length > maxLength) return false;
        foreach (var c in value)
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        return true;
    }

    private static void PruneOAuthStates()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var key in OAuthStates.Keys)
            if (OAuthStates.TryGetValue(key, out var state) && state.Expires <= now)
                OAuthStates.TryRemove(key, out _);
    }

    private static async Task CleanupLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        try
        {
            while (await timer.WaitForNextTickAsync(ct))
            {
                PruneOAuthStates();
                var now = DateTimeOffset.UtcNow;
                foreach (var pair in Sessions)
                    if (pair.Value.Expires <= now)
                        Sessions.TryRemove(pair.Key, out _);

                if (OAuthStates.Count > MaxOAuthStates)
                {
                    var excess = OAuthStates.Count - MaxOAuthStates;
                    var oldest = OAuthStates
                        .OrderBy(p => p.Value.Expires)
                        .Take(excess)
                        .Select(p => p.Key)
                        .ToList();
                    foreach (var key in oldest)
                        OAuthStates.TryRemove(key, out _);
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    private static bool IsPlaceholder(string value)
    {
        var lower = value.ToLowerInvariant();
        foreach (var marker in new[] { "replace-with", "change-", "example", "your-", "xxx" })
            if (lower.Contains(marker, StringComparison.Ordinal)) return true;
        return lower is "secret" or "changeme";
    }

    private static void ValidateJwtSecret(string secret)
    {
        if (string.IsNullOrWhiteSpace(secret) || Encoding.UTF8.GetByteCount(secret) < 32)
            throw new InvalidOperationException("JWT_SECRET musi mieć co najmniej 32 bajty entropii.");

        var lower = secret.ToLowerInvariant();
        if (IsPlaceholder(secret) || lower.Contains("secret", StringComparison.Ordinal))
            throw new InvalidOperationException("JWT_SECRET zawiera wartość przykładową — wygeneruj nowy, losowy sekret.");

        if (secret.Distinct().Count() < 12)
            throw new InvalidOperationException("JWT_SECRET ma zbyt mało entropii.");
    }

    /// <summary>Ładuje .env bez nadpisywania ustawionych zmiennych; obsługuje komentarze i cudzysłowy.</summary>
    private static void LoadEnvFile(string path)
    {
        if (!File.Exists(path)) return;
        foreach (var raw in File.ReadLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            var separator = line.IndexOf('=');
            if (separator <= 0) continue;

            var key = line[..separator].Trim();
            if (key.Length == 0 || Environment.GetEnvironmentVariable(key) is not null) continue;

            var value = line[(separator + 1)..].Trim();
            if (value.Length >= 2 && (value[0] == '"' || value[0] == '\''))
            {
                var quote = value[0];
                var end = 1;
                while (end < value.Length)
                {
                    if (quote == '"' && value[end] == '\\' && end + 1 < value.Length) end++;
                    if (value[end] == quote) break;
                    end++;
                }
                value = end < value.Length ? value[1..end] : value[1..];
                if (quote == '"')
                    value = value.Replace("\\\"", "\"", StringComparison.Ordinal)
                                 .Replace("\\\\", "\\", StringComparison.Ordinal);
            }
            else
            {
                var comment = value.IndexOf('#');
                if (comment >= 0) value = value[..comment].TrimEnd();
            }
            Environment.SetEnvironmentVariable(key, value);
        }
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
