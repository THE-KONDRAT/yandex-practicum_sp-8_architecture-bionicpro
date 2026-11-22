using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;

namespace bionicpro_auth.Session;

public class SessionStore
{
    private readonly IMemoryCache _cache;
    private readonly IDataProtector _protector;
    private readonly TimeSpan _ttl;
    private readonly ILogger _logger;

    public SessionStore(IMemoryCache cache, IDataProtectionProvider provider, IConfiguration config, ILogger<SessionStore>  logger)
    {
        _cache = cache;
        _protector = provider.CreateProtector("bionicpro.refresh-tokens");
        var accessTokenLifespan = config.GetValue<int>("KC_ACCESS_TOKEN_LIFESPAN");
        if (accessTokenLifespan <= 0) accessTokenLifespan = 120;
        var ttlSeconds = config.GetValue<int>("SESSION_TTL_SECONDS");
        if (ttlSeconds <= accessTokenLifespan)
            throw new InvalidOperationException($"SESSION_TTL_SECONDS must be > {accessTokenLifespan}, got {ttlSeconds}");
        _ttl = TimeSpan.FromSeconds(ttlSeconds);
        _logger = logger;
    }

    public string Create(string accessToken, DateTimeOffset expiresAt, string refreshToken)
    {
        var sessionId = GenerateSessionId();
        var protectedRefreshToken = _protector.Protect(refreshToken);
        var session = new SessionData(accessToken, expiresAt, protectedRefreshToken);
        Store(sessionId, session);
        _logger.LogDebug("Session created {SessionId}", sessionId[..8]);
        return sessionId;
    }

    public SessionData? Get(string sessionId)
        => _cache.TryGetValue(sessionId, out SessionData? session) ? session : null;

    public void Update(string sessionId, string accessToken, DateTimeOffset expiresAt, string refreshToken)
    {
        var protectedRefreshToken = _protector.Protect(refreshToken);
        var session = new SessionData(accessToken, expiresAt, protectedRefreshToken);
        Store(sessionId, session);
        _logger.LogDebug("Session {SessionId} updated with new access token", sessionId[..8]);
    }
    public string Rotate(string oldSessionId)
    {
        if (!_cache.TryGetValue(oldSessionId, out SessionData? session) || session == null)
            throw new KeyNotFoundException(oldSessionId);
        _cache.Remove(oldSessionId);
        var newSessionId = GenerateSessionId();
        Store(newSessionId, session);
        _logger.LogDebug("Session rotated: {OldSessionId} -> {NewSessionId}", oldSessionId[..8], newSessionId[..8]);
        return newSessionId;
    }

    public void Remove(string sessionId) => _cache.Remove(sessionId);
    
    public string ExtractRefreshToken(SessionData session) => _protector.Unprotect(session.ProtectedRefreshToken);

    private void Store(string sessionId, SessionData  session) => _cache.Set(sessionId, session, _ttl);

    private static string GenerateSessionId()
    {
        var sessionId = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        return sessionId;
    }
    
    internal static bool TryGetPreferredUsername(string accessToken, [NotNullWhen(true)]out string? userName)
    {
        try
        {
            var parts = accessToken.Split('.');
            if (parts.Length < 2)
            {
                userName = null;
                return false;
            }
            var padded = parts[1].Replace('-', '+').Replace('_', '/');
            switch (padded.Length % 4) { case 2: padded += "=="; break; case 3: padded += "="; break; }
            var json = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(padded));
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var result = doc.RootElement.TryGetProperty("preferred_username", out var el) ? el.GetString() : null;
            if (result != null)
            {
                userName = result;
                return true;
            }

            userName = null;
            return false;
        }
        catch
        {
            userName = null;
            return false;
        }
    }
}