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
| `API_URL` | Wymagany publiczny origin serwera, np. `https://vertex-tweaks-api.onrender.com` — bez ścieżki, query, fragmentu i userinfo. Dla hostów innych niż `localhost`/`127.0.0.1`/`::1` wymagany jest `https`. |
| `PORT` | Opcjonalny. Port nasłuchiwania — serwer wiąże `http://0.0.0.0:{PORT}`. Gdy ustawiony jest `ASPNETCORE_URLS`, ma on wyższy priorytet. Render/Railway ustawiają `PORT` automatycznie. |

### Generowanie `JWT_SECRET`

```bash
openssl rand -hex 32
```

PowerShell:

```powershell
[Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
```

Wklej wynik jako `JWT_SECRET`. Sekrety z wzorcami `replace-with-`, `change-`, `example`, `your-`, `xxx`,
`secret` lub `changeme` są odrzucane (dotyczy też `DISCORD_CLIENT_SECRET`).

### Plik `.env`

Serwer ładuje `.env` z katalogu aplikacji (`AppContext.BaseDirectory`, czyli np. `bin/Debug/net8.0/`
lub katalogu opublikowanego DLL). **Jeśli tam go nie ma**, ładuje `.env` z bieżącego katalogu.
Kopiuj `.env` obok pliku wykonywalnego/DLL albo ustaw zmienne bezpośrednio w środowisku. Obsługiwane
są komentarze (`#`), wartości w cudzysłowie oraz komentarze w tej samej linii. **Zmienne już ustawione
w środowisku nie są nadpisywane.** Konfiguracja jest sprawdzana przed startem — błąd lub brak
wymaganej zmiennej kończy uruchomienie.

## Model bezpieczeństwa

- `GET /auth/discord` **ignoruje** przekazany `state` jako wartość OAuth: serwer generuje własny,
  losowy stan (64 znaki hex), podpisuje go kluczem `JWT_SECRET` razem z portem, czasem wygaśnięcia
  i stanem klienta, zapisuje w ciasteczku `HttpOnly` + `SameSite=Lax` (i `Secure` dla `https`)
  oraz w magazynie z TTL 10 minut i limitem 512 wpisów.
- Klient może nadal wysyłać `?port=<p>&state=<x>` — `port` jest włączony do podpisu, a `state`
  klienta jest zwracany w callbacku jako `state` (dla zgodności wstecznej). Podmiana parametru
  przez napastnika nie zmienia portu ani stanu zapisanego po stronie serwera.
- Callback akceptuje tylko stan zgodny z ciasteczkiem i podpisem, jednorazowy i nieprzedawniony.
  Sprawdzany jest też `iss=https://discord.com` (gdy Discord go prześle), aby wykluczyć mix-up.
  Nie stosujemy osobnego PKCE: klient jest poufny (client secret), a podpisany, jednorazowy stan
  w `HttpOnly`-ciasteczku pełni rolę równoważnika PKCE.
- `/auth/*` i `/api/*` mają limit 12 / 120 żądań na minutę. Klucz `/api/*` zawiera IP oraz `sid`
  **zweryfikowany podpisem JWT** — podmiana niepodpisanego payloadu nie pozwala obejść limitu.
  Odrzucenie to `429` z JSON-em i nagłówkiem `Retry-After: 60`.
- Token JWT ważny jest **2 godziny** i zawiera `sub`, `username`, `sid`, `iat`, `exp`, `iss`, `aud`,
  `jti`. Walidacja sprawdza algorytm HS256, typ JWT, issuer/audience, liczby w formacie
  niezależnym od kultury, maksymalną długość tokenu oraz 60-sekundową tolerancję `iat`.
  Sesja serwerowa wygasa razem z tokenem; wygasłe sesje i stany OAuth są okresowo usuwane.
  Nie ma endpointu odświeżającego JWT — po 2 h wymagane jest ponowne logowanie.
- Access token Discord jest przechowywany tylko w pamięci serwera; odświeżanie refresh tokenem
  odbywa się co najwyżej raz na sesję (single-flight), nawet przy równoległych weryfikacjach.
  Odpowiedzi Discorda są czytane z limitem 64 KiB; `Retry-After` jest brany z nagłówka lub pola
  `retry_after` i ograniczany do 60 s.
- Role jest buforowana przez 45 sekund na sesję, aby nie przeciążać Discorda. Przy definitywnym
  braku roli, wyjściu użytkownika z guildu (HTTP 403/404 z Discorda) lub wygaśnięciu refresh tokenu
  wszystkie sesje użytkownika są unieważniane. Błędy techniczne i 429 Discorda dają `503`.
- `POST /api/logout` unieważnia sesję po stronie serwera; jest idempotentne — kolejne wywołania
  (nawet z wygasłym, ale poprawnie podpisanym JWT) zwracają `200`.

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

Limitowanie liczby żądań korzysta z `RemoteIpAddress`. Za reverseproxy (Render/Railway) wszystkie
żądania mogą mieć ten sam adres proxy — serwer nie ufa nagłówkom `X-Forwarded-For` bez konfiguracji,
żeby nie dopuścić do spoofingu. Jeśli chcesz limitować per prawdziwy IP, włącz forwards z zaufaną
siecią (`ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` i `ASPNETCORE_KNOWNNETWORKS`/`KNOWNPROXIES`
zgodnie z dokumentacją hosta). Bez tego limit jest bezpieczny, ale może zbyt agresywnie dławić
użytkowników współdzielących wyjściowe IP proxy.

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

Adres API jest rozwiązywany w czasie działania klienta (nie ma już stałej w kodzie). Ustaw go jedną z metod:

1. Zmienna środowiskowa `VERTEX_API_URL=https://twoj-serwer.onrender.com`, albo
2. Plik `VertexTweaks.json` obok EXE: `{"apiUrl":"https://twoj-serwer.onrender.com"}`, albo
3. Plik `%AppData%\VertexTweaks\api-url.txt` zawierający sam adres.

Domyślnie klient używa `https://vertex-tweaks-api.onrender.com`. HTTP jest akceptowane tylko dla
`localhost`/loopback; dla zdalnych hostów wymagane jest HTTPS. Adres serwera (`API_URL` po stronie
serwera) i adres klienta muszą wskazywać na ten sam publiczny origin — callback jest rejestrowany
jako `{API_URL}/auth/callback`.

## Endpointy

| Endpoint | Opis |
| --- | --- |
| `GET /auth/discord?port=<p>&state=<x>` | Redirect do Discord OAuth. `port` (1024–65535, domyślnie 17342) i `state` (32–128 hex) są opcjonalne i podpisywane po stronie serwera. |
| `GET /auth/callback?code=<c>&state=<s>&iss=<iss>` | Callback po autoryzacji Discord. Redirect na `http://localhost:<port>/?token=...&state=...` lub `?error=...&state=...`. Odpowiedzi mają `Cache-Control: no-store` i `Referrer-Policy: no-referrer`. |
| `GET /api/verify` | Weryfikacja tokenu (Bearer) + sprawdzenie roli Discord (z 45-sekundowym cache). |
| `POST /api/logout` | Idempotentne unieważnienie sesji serwerowej (Bearer; akceptuje też wygasły podpisany token). |

Wszystkie odpowiedzi `/api/*` mają `Cache-Control: no-store`, `Pragma: no-cache`,
`Referrer-Policy: no-referrer` i `X-Content-Type-Options: nosniff`. Odpowiedzi `401` zawierają
dodatkowo `WWW-Authenticate: Bearer`.

### Kody odpowiedzi `/api/verify`

| Kod | Znaczenie | Odpowiedź JSON | Zachowanie klienta |
| --- | --- | --- | --- |
| `200` | Token i rola ważne | `{"username":"...","valid":true}` | Licencja aktywna |
| `401` | Definitywna utrata roli / brak członkostwa w guildzie, wygaśnięcie tokenu/sesji lub odmowa odświeżania | `{"valid":false,"error":"unauthorized","message":"..."}` | Wyczyść token i poproś o ponowne logowanie |
| `429` | Przekroczenie limitu żądań (per IP / per zweryfikowany `sid`); nagłówek `Retry-After: 60` | `{"valid":false,"error":"rate_limited","message":"..."}` | Nie czyścić tokenu, spróbować później |
| `503` | Błąd techniczny Discorda, w tym HTTP 429 z Discorda (honorowane `Retry-After` z nagłówka lub JSON) | `{"valid":false,"error":"discord_unavailable","message":"..."}` | Nie czyścić tokenu — to nie jest utrata licencji |

`POST /api/logout` zwraca `{"ok":true}` dla poprawnego (również wygasłego) tokenu oraz `401` z powyższym
JSON-em dla tokenu nieprawidłowego; `429` ma ten sam kształt co dla `/api/verify`.

## Uwagi dla klienta desktopowego

- Przekazuj `port` i własny `state` (32–128 hex) w `/auth/discord`; serwer zwróci wygenerowany
  przez siebie stan do Discorda, ale w redirectcie z powrotem zwróci `state` klienta — dotychczasowe
  porównanie `returnedState == state` pozostaje ważne.
- Token nadal przychodzi w query string (`?token=...`). Strona HTML wyświetlana przez klienta
  powinna wyczyścić adres z `history.replaceState(null, '', location.pathname)` i ustawiać
  `Cache-Control: no-store` / `Referrer-Policy: no-referrer`.
- Klient powinien wywoływać `/api/verify` cyklicznie (np. co 30–60 s), aby wykryć cofnięcie roli.
  Po 2 h JWT wygasa i wymagane jest ponowne logowanie (serwer odświeża jedynie token Discorda).
