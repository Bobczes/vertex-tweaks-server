# Vertex Tweaks Server — Backend Discord OAuth

Backend dla logowania Discord w aplikacji Vertex Tweaks.

## Konfiguracja

Ustaw zmienne środowiskowe przed uruchomieniem:

| Zmienna | Opis |
| --- | --- |
| `DISCORD_CLIENT_ID` | ID aplikacji Discord (z Discord Developer Portal) |
| `DISCORD_CLIENT_SECRET` | Secret aplikacji Discord |
| `DISCORD_GUILD_ID` | ID Twojego serwera Discord |
| `DISCORD_REQUIRED_ROLE_ID` | ID roli wymaganej do korzystania z aplikacji |
| `JWT_SECRET` | Tajny klucz do podpisywania tokenów (min. 16 znaków; wartość domyślna jest odrzucana) |
| `API_URL` | Publiczny adres serwera (np. https://vertex-tweaks-api.onrender.com) |

Serwer nie uruchomi się, jeśli którejkolwiek z tych zmiennych brakuje lub `JWT_SECRET` jest zbyt krótki.

## Model bezpieczeństwa

- `state` OAuth jest generowany przez aplikację, zapisywany na serwerze i sprawdzany przy callbacku
  oraz po stronie klienta — chroni to przed logowaniem CSRF.
- Token JWT zawiera identyfikator sesji (`sid`). Przy każdym `/api/verify` serwer ponownie pyta Discord
  o członkostwo i rolę **Vertex**, więc cofnięcie roli blokuje dostęp natychmiast.
- Access token Discord jest przechowywany tylko w pamięci serwera i jest odświeżany z refresh tokenu.
  Po restarcie serwera trzeba zalogować się ponownie.
- `POST /api/logout` unieważnia sesję po stronie serwera (nie tylko lokalnie w aplikacji).

## Uruchomienie lokalne

```bash
cd Server
dotnet run
```

Serwer nasłuchuje na `http://localhost:5000`.

## Deploy (darmowy hosting)

### Render.com (zalecane)
1. Utwórz konto na render.com
2. New → Web Service → połącz z repozytorium GitHub
3. Root Directory: `Server`
4. Build Command: `dotnet publish -c Release -o out`
5. Start Command: `dotnet out/VertexTweaks.Server.dll`
6. Dodaj zmienne środowiskowe (DISCORD_*, JWT_SECRET, API_URL)
7. Deploy

### Railway.app
1. Utwórz konto na railway.app
2. New Project → Deploy from GitHub
3. Ustaw zmienne środowiskowe
4. Railway automatycznie wykryje .NET

## Konfiguracja Discord

1. Wejdź na https://discord.com/developers/applications
2. New Application → nazwa "Vertex Tweaks"
3. OAuth2 → Redirects → dodaj: `https://twoj-serwer.com/auth/callback`
4. Skopiuj Client ID i Client Secret
5. Bot → Add Bot → skopiuj token (jeśli potrzebny)
6. Włącz "Server Members Intent" w Privileged Gateway Intents

## Zmiana adresu API w aplikacji

W pliku `Views/LoginView.xaml.cs` zmień:
```csharp
private const string ApiUrl = "http://localhost:5000";
```
na adres swojego serwera, np.:
```csharp
private const string ApiUrl = "https://vertex-tweaks-api.onrender.com";
```

## Endpointy

| Endpoint | Opis |
| --- | --- |
| GET /auth/discord | Redirect do Discord OAuth |
| GET /auth/callback | Callback po autoryzacji Discord |
| GET /api/verify | Weryfikacja tokenu (Bearer) + ponowne sprawdzenie roli Discord |
| POST /api/logout | Unieważnienie sesji serwerowej (Bearer) |
