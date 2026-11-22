# Vertex Tweaks Server — Backend Discord OAuth

Backend dla logowania Discord w aplikacji Vertex Tweaks.

## Konfiguracja

Wszystkie poniższe zmienne są **wymagane** — serwer nie uruchomi się, jeśli którejkolwiek brakuje.

| Zmienna | Opis |
| --- | --- |
| `DISCORD_CLIENT_ID` | ID aplikacji Discord (z Discord Developer Portal) |
| `DISCORD_CLIENT_SECRET` | Secret aplikacji Discord |
| `DISCORD_GUILD_ID` | ID Twojego serwera Discord |
| `DISCORD_REQUIRED_ROLE_ID` | ID roli wymaganej do korzystania z aplikacji |
| `JWT_SECRET` | Losowy sekret do podpisywania tokenów: min. 32 bajty, bez wartości przykładowych |
| `API_URL` | Wymagany publiczny adres serwera, np. `https://vertex-tweaks-api.onrender.com`. Dla hostów innych niż `localhost`/`127.0.0.1`/`::1` wymagany jest `https`. |
| `PORT` | Opcjonalny. Port nasłuchiwania — serwer wiąże `http://0.0.0.0:{PORT}`. Gdy ustawiony jest `ASPNETCORE_URLS`, ma on wyższy priorytet. Render/Railway ustawiają `PORT` automatycznie. |

### Generowanie `JWT_SECRET`

```bash
openssl rand -hex 32
```

PowerShell:

```powershell
[Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
```

Wklej wynik jako `JWT_SECRET`. Sekrety z wzorcami `replace-with-`, `change-`, `example` lub `secret` są odrzucane.

### Plik `.env`

Serwer ładuje `.env` z katalogu aplikacji (`AppContext.BaseDirectory`, czyli np. `bin/Debug/net8.0/`
lub katalogu opublikowanego DLL), a gdy go tam nie ma — z bieżącego katalogu. Kopiuj `.env` obok
pliku wykonywalnego/DLL albo ustaw zmienne bezpośrednio w środowisku. Obsługiwane są komentarze
(`#`), wartości w cudzysłowie oraz komentarze w tej samej linii. **Zmienne już ustawione w środowisku
nie są nadpisywane.**

## Model bezpieczeństwa

- `GET /auth/discord` **ignoruje** przekazany `state` jako wartość OAuth: serwer generuje własny,
  losowy stan (64 znaki hex), podpisuje go kluczem `JWT_SECRET` razem z portem, czasem wygaśnięcia
  i stanem klienta, zapisuje w ciasteczku `HttpOnly` + `SameSite=Lax` (i `Secure` dla `https`)
  oraz w magazynie z TTL 10 minut i limitem 512 wpisów.
- Klient może nadal wysyłać `?port=<p>&state=<x>` — `port` jest włączony do podpisu, a `state`
  klienta jest zwracany w callbacku jako `state` (dla zgodności wstecznej). Podmiana parametru
  przez napastnika nie zmienia portu ani stanu zapisanego po stronie serwera.
- Callback akceptuje tylko stan zgodny z ciasteczkiem i podpisem, jednorazowy i nieprzedawniony.
  `/auth/*` i `/api/*` mają ograniczenie liczby żądań per IP (oraz per `sid` dla `/api/*`).
- Token JWT ważny jest **2 godziny** i zawiera `sub`, `username`, `sid`, `iat`, `exp`, `iss`, `aud`,
  `jti`. Walidacja sprawdza algorytm HS256, typ JWT, issuer/audience, liczby w formacie
  niezależnym od kultury i maksymalną długość tokenu. Sesja serwerowa wygasa razem z tokenem;
  wygasłe sesje i stany OAuth są okresowo usuwane.
- Access token Discord jest przechowywany tylko w pamięci serwera; odświeżanie refresh tokenem
  odbywa się co najwyżej raz na sesję (single-flight), nawet przy równoległych weryfikacjach.
- Role jest buforowana przez 45 sekund na sesję, aby nie przeciążać Discorda. Przy definitywnym
  braku roli lub wygaśnięciu refresh tokenu wszystkie sesje użytkownika są unieważniane.
- `POST /api/logout` unieważnia sesję po stronie serwera (nie tylko lokalnie w aplikacji).

## Uruchomienie lokalne

```bash
cd Server
dotnet run
```

Domyślnie serwer nasłuchuje na `http://localhost:5000` (ustaw `API_URL=http://localhost:5000`).
Aby zmienić port i wiązać wszystkie interfejsy:

```powershell
$env:PORT = 8080
dotnet run
```

Wtedy serwer nasłuchuje na `http://0.0.0.0:8080`.

## Deploy (darmowy hosting)

### Render.com (zalecane)
1. Utwórz konto na render.com
2. New → Web Service → połącz z repozytorium GitHub
3. Root Directory: `Server`
4. Build Command: `dotnet publish -c Release -o out`
5. Start Command: `dotnet out/VertexTweaks.Server.dll`
6. Dodaj zmienne środowiskowe: `DISCORD_*`, `JWT_SECRET`, `API_URL` (publiczny `https://...`).
   Render sam ustawia `PORT` — serwer automatycznie wiąże `0.0.0.0` na tym porcie.
7. Deploy

### Railway.app
1. Utwórz konto na railway.app
2. New Project → Deploy from GitHub
3. Ustaw zmienne środowiskowe (w tym `API_URL` z `https`)
4. Railway automatycznie wykryje .NET i ustawi `PORT`

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
| `GET /auth/discord?port=<p>&state=<x>` | Redirect do Discord OAuth. `port` (1024–65535, domyślnie 17342) i `state` (32–128 hex) są opcjonalne i podpisywane po stronie serwera. |
| `GET /auth/callback?code=<c>&state=<s>` | Callback po autoryzacji Discord. Redirect na `http://localhost:<port>/?token=...&state=...` lub `?error=...&state=...`. Odpowiedzi mają `Cache-Control: no-store` i `Referrer-Policy: no-referrer`. |
| `GET /api/verify` | Weryfikacja tokenu (Bearer) + sprawdzenie roli Discord (z 45-sekundowym cache). |
| `POST /api/logout` | Unieważnienie sesji serwerowej (Bearer). |

### Kody odpowiedzi `/api/verify`

| Kod | Znaczenie | Zachowanie klienta |
| --- | --- | --- |
| `200` | Token i rola ważne. Odpowiedź: `{"username":"...","valid":true}` | Licencja aktywna |
| `401` | Definitywna utrata roli, wygaśnięcie tokenu/sesji lub odmowa odświeżania | Wyczyść token i poproś o ponowne logowanie |
| `429` | Przekroczenie limitu żądań (per IP / per `sid`) | Nie czyścić tokenu, spróbować później |
| `503` | Błąd techniczny Discorda, w tym HTTP 429 z Discorda (honorowane `Retry-After`) | Nie czyścić tokenu — to nie jest utrata licencji |

## Uwagi dla klienta desktopowego

- Przekazuj `port` i własny `state` (32–128 hex) w `/auth/discord`; serwer zwróci wygenerowany
  przez siebie stan do Discorda, ale w redirectcie z powrotem zwróci `state` klienta — dotychczasowe
  porównanie `returnedState == state` pozostaje ważne.
- Token nadal przychodzi w query string (`?token=...`). Strona HTML wyświetlana przez klienta
  powinna wyczyścić adres z `history.replaceState(null, '', location.pathname)` i ustawiać
  `Cache-Control: no-store` / `Referrer-Policy: no-referrer`.
- Klient powinien wywoływać `/api/verify` cyklicznie (np. co 30–60 s), aby wykryć cofnięcie roli.
  Po 2 h JWT wygasa i wymagane jest ponowne logowanie (serwer odświeża jedynie token Discorda).
