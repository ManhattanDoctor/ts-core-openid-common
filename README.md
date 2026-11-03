# @ts-core/openid-common

TypeScript библиотека для работы с OpenID Connect провайдерами (Keycloak и др.).

## Содержание

- [Установка](#установка)
- [Быстрый старт](#быстрый-старт)
- [API Reference](#api-reference)
  - [KeycloakService](#keycloakservice)
  - [KeycloakClient](#keycloakclient)
  - [KeycloakTokenManager](#keycloaktokenmanager)
  - [KeycloakAdministratorTransport](#keycloakadministratortransport)
  - [OpenIdTokenRefreshableTransport](#openidtokenrefreshabletransport)
- [Интерфейсы](#интерфейсы)
- [Обработка ошибок](#обработка-ошибок)
- [Примеры](#примеры)
- [Архитектура](#архитектура)

## Установка

```bash
npm install @ts-core/openid-common
```

### Зависимости

- `@ts-core/common` (~3.0.57)

## Быстрый старт

### Инициализация

```typescript
import { KeycloakService, IKeycloakSettings } from '@ts-core/openid-common';

const settings: IKeycloakSettings = {
    url: 'https://keycloak.example.com',
    realm: 'my-realm',
    clientId: 'my-client',
    clientSecret: 'my-secret',
    realmPublicKey: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----'
};

const service = new KeycloakService(settings);
```

### Получение токена по коду авторизации

```typescript
const tokens = await service.getTokenByCode({
    code: 'authorization-code-from-callback',
    redirectUri: 'https://your-app.com/callback'
});

console.log('Access Token:', tokens.access);
console.log('Refresh Token:', tokens.refresh);
```

### Получение информации о пользователе

```typescript
// Online (запрос к серверу)
const user = await service.getUserInfo(tokens.access);

// Offline (из токена)
const userOffline = await service.getUserInfo(tokens.access, true);

console.log('User ID:', user.sub);
```

### Валидация токена

```typescript
// Online валидация (через introspection endpoint)
await service.validateToken(accessToken);

// Offline валидация (проверка подписи локально)
await service.validateToken(accessToken, {
    publicKey: settings.realmPublicKey,
    clientId: settings.clientId,
    iss: `${settings.url}/realms/${settings.realm}`
});
```

Локальная валидация учитывает необязательный JWT claim `nbf` (Unix-время в секундах).
До наступления `nbf` возвращается `OPEN_ID_TOKEN_NOT_ACTIVE`; нечисловое или неконечное
значение отклоняется как `OPEN_ID_TOKEN_INVALID`. На точной границе `nbf` токен уже
может быть принят. Отсутствие `nbf` сохраняет прежнее поведение. Настройка
`notBefore` по-прежнему отдельно проверяет время выпуска `iat`.

Регрессионные тесты с подписанными RSA-токенами: `npm test` (Node.js 20+).

### Публичные ключи Keycloak (JWKS)

Если для локальной валидации не задан ни `options.publicKey`, ни `settings.realmPublicKey`,
`KeycloakClient` получает ключи из `/realms/{realm}/protocol/openid-connect/certs`.
Адрес формируется только из настроек приложения; URL из JWT не используется.
Выбирается RSA/RS256-ключ подписи по `kid`. Явно переданный PEM сохраняет приоритет.

`KeycloakService` разделяет кеш между запросами: срок кеша 5 минут, параллельные
загрузки объединяются. Неизвестный `kid` вызывает обновление не чаще раза в 30 секунд;
поэтому новый ключ сразу после предыдущего запроса может стать доступен с задержкой
до 30 секунд. После истечения кеша недоступность или некорректный ответ JWKS приводят
к `OPEN_ID_JWKS_UNAVAILABLE` (503). Неподходящий `kid` — ошибка подписи (401).
Токены, пользовательские сессии и приватные ключи не кешируются.

Вызов `validateToken(token)` без options по-прежнему использует introspection.
При локальной проверке задавайте `iss`, `type: 'Bearer'`, `isVerifyAudience: true`
и `clientId`, соответствующий audience API. Получение JWKS не заменяет эти проверки.

### Проверка ролей

```typescript
// Роли указываются в формате "type:role"
// realm:admin - роль уровня realm
// client:editor - роль уровня client (resource_access)

// Проверка одной роли
await service.validateRole(accessToken, { role: 'realm:admin' });

// Проверка нескольких ролей (все обязательны)
await service.validateRole(accessToken, { role: ['realm:admin', 'client:editor'] });

// Проверка любой из ролей (isAny: true)
await service.validateRole(accessToken, {
    role: ['realm:admin', 'realm:moderator'],
    isAny: true
});

// Проверка без исключения (возвращает boolean)
const isAdmin = await service.hasRole(accessToken, { role: 'realm:admin' });
```

### Проверка доступа к ресурсам

```typescript
// Проверка доступа к ресурсу
await service.validateResource(accessToken, { name: 'api-resource' });

// Проверка конкретного scope
await service.validateResource(accessToken, {
    name: 'api-resource',
    scope: 'read'
});

// Проверка нескольких scopes
await service.validateResource(accessToken, {
    name: 'api-resource',
    scope: ['read', 'write']
});

// Любой из scopes (isAny: true)
await service.validateResource(accessToken, {
    name: 'api-resource',
    scope: ['read', 'write', 'delete'],
    isAny: true
});

// Проверка без исключения
const hasAccess = await service.hasResourceScope(accessToken, {
    name: 'api-resource',
    scope: 'write'
});
```

### Получение доступных ресурсов

```typescript
const resources = await service.getResources(accessToken);

// resources - это Map<string, IOpenIdResource>
resources.forEach((resource, name) => {
    console.log(`Resource: ${name}`);
    console.log(`  ID: ${resource.id}`);
    console.log(`  Scopes: ${resource.scopes.join(', ')}`);
});
```

### Обновление токена

```typescript
const newTokens = await service.getTokenByRefreshToken(tokens.refresh);
console.log('New Access Token:', newTokens.access);
```

### Выход из системы

```typescript
await service.logoutByRefreshToken(tokens.refresh);
```

---

## API Reference

### KeycloakService

Основной сервис для работы с Keycloak. Наследует абстрактный класс `OpenIdService`.

#### Конструктор

```typescript
constructor(settings: IKeycloakSettings)
```

#### Методы

| Метод | Описание |
|-------|----------|
| `getUserInfo<T>(token, isOffline?)` | Получение информации о пользователе |
| `getTokenByCode<T>(code)` | Обмен кода авторизации на токены |
| `getTokenByRefreshToken<T>(token)` | Обновление токенов |
| `getResources(token, options?, claim?)` | Получение доступных ресурсов |
| `logoutByRefreshToken(token)` | Завершение сессии |
| `validateToken(token, options?)` | Валидация токена (online/offline) |
| `validateRole(token, options)` | Проверка роли с исключением |
| `validateResource(token, options)` | Проверка ресурса с исключением |
| `hasRole(token, options)` | Проверка роли (boolean) |
| `hasResourceScope(token, options)` | Проверка ресурса (boolean) |

---

### KeycloakClient

Низкоуровневый HTTP-клиент для работы с Keycloak API. Наследует `DestroyableContainer`.

```typescript
const client = new KeycloakClient(accessToken, settings);

// Получение информации о пользователе
const user = await client.getUserInfo();
const userOffline = await client.getUserInfo(true);

// Токены
const tokens = await client.getTokenByCode(code);
const newTokens = await client.getTokenByRefreshToken(refreshToken);

// Ресурсы
const resources = await client.getResources(options, claim);

// Валидация
await client.validateToken();  // online
await client.validateToken(offlineOptions);  // offline
await client.validateResource(options);

// Logout
await client.logoutByRefreshToken(refreshToken);
```

---

### KeycloakTokenManager

Менеджер токенов с автоматическим отслеживанием состояния. Наследует `OpenIdTokenRefreshableManager`.

```typescript
import { KeycloakTokenManager } from '@ts-core/openid-common';

const manager = new KeycloakTokenManager();

// Установка токена
manager.value = { access: accessToken, refresh: refreshToken };

// Проверка состояния
console.log('Is Valid:', manager.isValid);
console.log('Is Expired:', manager.isExpired);

// Доступ к распарсенным токенам
const accessTokenParsed = manager.access;  // KeycloakAccessToken
const refreshTokenParsed = manager.refresh; // KeycloakToken

// Подписка на изменения
manager.changed.subscribe(token => {
    console.log('Token changed:', token);
});

// Очистка
manager.destroy();
```

#### Свойства

| Свойство | Тип | Описание |
|----------|-----|----------|
| `value` | `IOpenIdTokenRefreshable` | Текущие токены (access + refresh) |
| `access` | `KeycloakAccessToken` | Распарсенный access token |
| `refresh` | `KeycloakToken` | Распарсенный refresh token |
| `isValid` | `boolean` | Есть ли валидное значение |
| `isExpired` | `boolean` | Истёк ли access token |
| `changed` | `Observable<IOpenIdTokenRefreshable>` | События изменения токена |

---

### KeycloakAdministratorTransport

HTTP-транспорт с автоматической аутентификацией для административного API Keycloak.

```typescript
import { KeycloakAdministratorTransport, IKeycloakAdministratorSettings } from '@ts-core/openid-common';

const settings: IKeycloakAdministratorSettings = {
    url: 'https://keycloak.example.com',
    realm: 'master',
    clientId: 'admin-cli',
    clientSecret: 'secret',
    realmPublicKey: '...',
    scope: 'openid',
    login: 'admin',
    password: 'admin-password'
};

const transport = new KeycloakAdministratorTransport(logger, settings);

// Токен будет получен автоматически при первом запросе
const users = await transport.call('admin/realms/my-realm/users', {
    method: 'get'
});

// Принудительное обновление токена
await transport.refresh(true);
```

---

### OpenIdTokenRefreshableTransport

Базовый класс для создания HTTP-транспортов с автоматическим обновлением токенов.

```typescript
import { OpenIdTokenRefreshableTransport } from '@ts-core/openid-common';

class MyApiTransport extends OpenIdTokenRefreshableTransport {
    protected async getRefreshable(): Promise<IOpenIdTokenRefreshable> {
        // Логика обновления токена
        const response = await this.refreshTokenFromServer();
        return { access: response.access_token, refresh: response.refresh_token };
    }

    protected isSkipCheckRefreshable(path: string): boolean {
        // Пути, которые не требуют авторизации
        return path.includes('/public/');
    }
}
```

#### Ключевые методы

| Метод | Описание |
|-------|----------|
| `call(path, request?, options?)` | HTTP-запрос с автоматической авторизацией |
| `refresh(isForce?)` | Обновление токена |
| `authorization` | Геттер для заголовка `Bearer {token}` |

---

## Интерфейсы

### IKeycloakSettings

```typescript
interface IKeycloakSettings {
    url: string;           // URL сервера Keycloak
    realm: string;         // Название realm
    clientId: string;      // ID клиента
    clientSecret: string;  // Секрет клиента
    realmPublicKey: string; // Публичный ключ realm (для offline валидации)
}
```

### IKeycloakAdministratorSettings

```typescript
interface IKeycloakAdministratorSettings extends IKeycloakSettings {
    scope: string;     // Scope для токена (например, 'openid')
    login: string;     // Логин администратора
    password: string;  // Пароль администратора
}
```

### IOpenIdCode

```typescript
interface IOpenIdCode {
    code: string;        // Код авторизации
    redirectUri: string; // Redirect URI
}
```

### IOpenIdTokenRefreshable

```typescript
interface IOpenIdTokenRefreshable {
    access: string;  // Access token
    refresh: string; // Refresh token
}
```

### IOpenIdUser

```typescript
interface IOpenIdUser {
    sub: string;        // Subject (ID пользователя)
    [key: string]: any; // Дополнительные поля
}
```

### IOpenIdResource

```typescript
interface IOpenIdResource<T = Record<string, any>> {
    id: string;                // ID ресурса
    name: string;              // Название ресурса
    scopes: Array<string>;     // Доступные scopes
    type?: string;             // Тип ресурса
    attributes?: T;            // Атрибуты
}

type OpenIdResources = Map<string, IOpenIdResource>;
```

### IOpenIdToken

```typescript
interface IOpenIdToken {
    value: string;             // Сырое значение токена
    readonly isExpired: boolean; // Истёк ли токен
}
```

### Опции валидации

```typescript
// Offline валидация токена
interface IOpenIdOfflineValidationOptions {
    iss?: string;              // Ожидаемый issuer
    type?: string;             // Ожидаемый тип токена
    notBefore?: number;        // Минимальное время создания (iat)
    isVerifyAudience?: boolean; // Проверять audience
    clientId?: string;         // Ожидаемый client ID
    publicKey?: string;        // Публичный ключ для проверки подписи
}

// Проверка ролей
interface IOpenIdRoleValidationOptions {
    role: string | Array<string>; // Роль(и) в формате "type:name"
    isAny?: boolean;              // Любая из ролей (по умолчанию все)
}

// Проверка ресурсов
interface IOpenIdResourceValidationOptions {
    name: string;                    // Название ресурса
    scope?: string | Array<string>;  // Требуемые scopes
    isAny?: boolean;                 // Любой из scopes
}

type OpenIdResourceValidationOptions =
    | IOpenIdResourceValidationOptions
    | Array<IOpenIdResourceValidationOptions>;
```

---

## Обработка ошибок

Все ошибки наследуют базовый класс `OpenIdError` и содержат HTTP-код статуса.

### Классы ошибок

| Класс | Код | HTTP | Описание |
|-------|-----|------|----------|
| `OpenIdTokenUndefinedError` | `TOKEN_UNDEFINED` | 401 | Токен не передан |
| `OpenIdTokenInvalidError` | `TOKEN_INVALID` | 401 | Невалидный формат токена |
| `OpenIdTokenExpiredError` | `TOKEN_EXPIRED` | 401 | Токен истёк |
| `OpenIdTokenNotActiveError` | `TOKEN_NOT_ACTIVE` | 401 | Токен неактивен |
| `OpenIdTokenStaleError` | `TOKEN_STALE` | 401 | Токен устарел (iat < notBefore) |
| `OpenIdTokenNotSignedError` | `TOKEN_NOT_SIGNED` | 403 | Токен не подписан |
| `OpenIdTokenSignatureInvalidError` | `TOKEN_SIGNATURE_INVALID` | 401 | Неверная подпись |
| `OpenIdTokenSignatureAlgorithmUnknownError` | `TOKEN_SIGNATURE_ALGORITHM_UNKNOWN` | 401 | Неизвестный алгоритм |
| `OpenIdTokenWrongIssError` | `TOKEN_WRONG_ISS` | 403 | Неверный issuer |
| `OpenIdTokenWrongTypeError` | `TOKEN_WRONG_TYPE` | 403 | Неверный тип токена |
| `OpenIdTokenWrongAudienceError` | `TOKEN_WRONG_AUDIENCE` | 403 | Неверный audience |
| `OpenIdTokenWrongClientIdError` | `TOKEN_WRONG_CLIENT_ID` | 403 | Неверный client ID |
| `OpenIdTokenRoleForbiddenError` | `TOKEN_ROLE_FORBIDDEN` | 403 | Роль отсутствует |
| `OpenIdTokenRoleInvalidTypeError` | `TOKEN_ROLE_INVALID_TYPE` | 403 | Неверный тип роли |
| `OpenIdTokenResourceForbiddenError` | `TOKEN_RESOURCE_FORBIDDEN` | 403 | Нет доступа к ресурсу |
| `OpenIdTokenResourcesUndefinedError` | `TOKEN_RESOURCES_UNDEFINED` | 403 | Ресурсы не определены |
| `OpenIdTokenResourceScopeForbiddenError` | `TOKEN_RESOURCE_SCOPE_FORBIDDEN` | 403 | Нет scope для ресурса |
| `OpenIdOptionsPublicKeyUndefinedError` | `OPTIONS_PUBLIC_KEY_UNDEFINED` | 403 | Публичный ключ не задан |
| `OpenIdAccessDeniedNotAuthorizedError` | `ACCESS_DENIED_NOT_AUTHORIZED` | 403 | Доступ запрещён |
| `OpenIdInvalidGrantTokenNotActiveError` | `INVALID_GRANT_TOKEN_NOT_ACTIVE` | 401 | Токен неактивен (Keycloak) |
| `OpenIdInvalidGrantSessionNotActiveError` | `INVALID_GRANT_SESSION_NOT_ACTIVE` | 401 | Сессия неактивна (Keycloak) |

### Пример обработки

```typescript
import {
    OpenIdErrorCode,
    OpenIdTokenExpiredError,
    OpenIdTokenRoleForbiddenError
} from '@ts-core/openid-common';

try {
    await service.validateRole(token, { role: 'realm:admin' });
} catch (error) {
    if (error instanceof OpenIdTokenExpiredError) {
        // Обновить токен
        const newTokens = await service.getTokenByRefreshToken(refreshToken);
    } else if (error instanceof OpenIdTokenRoleForbiddenError) {
        // Недостаточно прав
        console.log('Missing role:', error.details);
    } else if (error.code === OpenIdErrorCode.TOKEN_INVALID) {
        // Требуется повторная авторизация
        redirectToLogin();
    }
}
```

### Проверка типа ошибки

```typescript
import { OpenIdError } from '@ts-core/openid-common';

if (OpenIdError.instanceOf(error)) {
    console.log('OpenID Error:', error.code, error.status);
}
```

---

## Примеры

### Express.js Middleware

```typescript
import express from 'express';
import { KeycloakService, OpenIdError, OpenIdErrorCode } from '@ts-core/openid-common';

const app = express();
const authService = new KeycloakService(settings);

// Извлечение токена
function extractToken(req: express.Request): string | null {
    const auth = req.headers.authorization;
    return auth?.startsWith('Bearer ') ? auth.slice(7) : null;
}

// Middleware аутентификации
async function requireAuth(
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
) {
    const token = extractToken(req);
    if (!token) {
        return res.status(401).json({ error: 'Token required' });
    }

    try {
        await authService.validateToken(token, {
            publicKey: settings.realmPublicKey,
            clientId: settings.clientId
        });
        req.user = await authService.getUserInfo(token, true);
        next();
    } catch (error) {
        const status = OpenIdError.instanceOf(error) ? error.status : 500;
        res.status(status).json({ error: error.message, code: error.code });
    }
}

// Middleware проверки роли
function requireRole(...roles: string[]) {
    return async (req: express.Request, res: express.Response, next: express.NextFunction) => {
        const token = extractToken(req);
        try {
            await authService.validateRole(token, { role: roles, isAny: true });
            next();
        } catch (error) {
            res.status(403).json({ error: 'Forbidden' });
        }
    };
}

// Маршруты
app.get('/api/profile', requireAuth, (req, res) => {
    res.json(req.user);
});

app.get('/api/admin', requireAuth, requireRole('realm:admin'), (req, res) => {
    res.json({ message: 'Admin area' });
});

app.post('/auth/callback', async (req, res) => {
    try {
        const tokens = await authService.getTokenByCode({
            code: req.body.code,
            redirectUri: req.body.redirectUri
        });
        res.json(tokens);
    } catch (error) {
        res.status(400).json({ error: 'Authentication failed' });
    }
});

app.post('/auth/refresh', async (req, res) => {
    try {
        const tokens = await authService.getTokenByRefreshToken(req.body.refreshToken);
        res.json(tokens);
    } catch (error) {
        res.status(401).json({ error: 'Refresh failed' });
    }
});

app.post('/auth/logout', async (req, res) => {
    try {
        await authService.logoutByRefreshToken(req.body.refreshToken);
        res.json({ success: true });
    } catch (error) {
        res.status(400).json({ error: 'Logout failed' });
    }
});
```

### NestJS Guard

```typescript
import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { KeycloakService } from '@ts-core/openid-common';

@Injectable()
export class AuthGuard implements CanActivate {
    constructor(private readonly authService: KeycloakService) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const token = this.extractToken(request);

        if (!token) {
            throw new UnauthorizedException('Token required');
        }

        try {
            await this.authService.validateToken(token);
            request.user = await this.authService.getUserInfo(token, true);
            return true;
        } catch (error) {
            throw new UnauthorizedException(error.message);
        }
    }

    private extractToken(request: any): string | null {
        const auth = request.headers.authorization;
        return auth?.startsWith('Bearer ') ? auth.slice(7) : null;
    }
}
```

### Автоматическое обновление токенов (браузер)

```typescript
import { KeycloakService, KeycloakTokenManager } from '@ts-core/openid-common';

class AuthManager {
    private tokenManager = new KeycloakTokenManager();
    private refreshTimeout?: NodeJS.Timeout;

    constructor(private service: KeycloakService) {
        // Подписка на изменения токена
        this.tokenManager.changed.subscribe(() => this.scheduleRefresh());
    }

    async login(code: string, redirectUri: string): Promise<void> {
        const tokens = await this.service.getTokenByCode({ code, redirectUri });
        this.tokenManager.value = tokens;
    }

    async logout(): Promise<void> {
        if (this.tokenManager.isValid) {
            await this.service.logoutByRefreshToken(this.tokenManager.value.refresh);
        }
        this.clearRefresh();
        this.tokenManager.value = null;
    }

    get accessToken(): string | null {
        return this.tokenManager.access?.value ?? null;
    }

    get isAuthenticated(): boolean {
        return this.tokenManager.isValid && !this.tokenManager.isExpired;
    }

    private scheduleRefresh(): void {
        this.clearRefresh();

        if (!this.tokenManager.isValid) return;

        // Обновляем за 30 секунд до истечения
        const expiresAt = this.tokenManager.access.content.exp * 1000;
        const refreshAt = expiresAt - Date.now() - 30000;

        if (refreshAt > 0) {
            this.refreshTimeout = setTimeout(() => this.refresh(), refreshAt);
        }
    }

    private async refresh(): Promise<void> {
        try {
            const tokens = await this.service.getTokenByRefreshToken(
                this.tokenManager.value.refresh
            );
            this.tokenManager.value = tokens;
        } catch (error) {
            console.error('Token refresh failed:', error);
            this.tokenManager.value = null;
            // Redirect to login
        }
    }

    private clearRefresh(): void {
        if (this.refreshTimeout) {
            clearTimeout(this.refreshTimeout);
            this.refreshTimeout = undefined;
        }
    }
}
```

---

## Архитектура

### Структура проекта

```
src/
├── error/
│   ├── OpenIdError.ts              # Базовый класс ошибок
│   ├── OpenIdErrorCode.ts          # Enum кодов ошибок
│   └── index.ts
├── lib/
│   ├── IOpenIdCode.ts              # Интерфейс кода авторизации
│   ├── IOpenIdClaim.ts             # Интерфейс claims
│   ├── IOpenIdResource.ts          # Интерфейс ресурса
│   ├── IOpenIdToken.ts             # Базовый класс токена
│   ├── IOpenIdTokenRefreshable.ts  # Интерфейс пары токенов
│   ├── IOpenIdTokenRefreshableManager.ts  # Менеджер токенов
│   ├── IOpenIdUser.ts              # Интерфейс пользователя
│   ├── OpenIdTokenRefreshableTransport.ts # HTTP-транспорт
│   └── index.ts
├── service/
│   ├── IOpenIdOptions.ts           # Интерфейсы опций
│   ├── OpenIdService.ts            # Абстрактный сервис
│   ├── keycloak/
│   │   ├── IKeycloakSettings.ts    # Настройки Keycloak
│   │   ├── KeycloakAccessToken.ts  # Access token
│   │   ├── KeycloakAdministratorTransport.ts # Admin API
│   │   ├── KeycloakClient.ts       # HTTP-клиент
│   │   ├── KeycloakService.ts      # Сервис Keycloak
│   │   ├── KeycloakToken.ts        # Базовый токен
│   │   ├── KeycloakTokenManager.ts # Менеджер токенов
│   │   ├── KeycloakUtil.ts         # Утилиты
│   │   └── index.ts
│   └── index.ts
└── public-api.ts                   # Публичный API
```

### Диаграмма классов

```
OpenIdService (abstract)
    └── KeycloakService
            └── uses KeycloakClient

OpenIdToken
    └── KeycloakToken
            └── KeycloakAccessToken

OpenIdTokenRefreshableManager (abstract)
    └── KeycloakTokenManager

OpenIdTokenRefreshableTransport (abstract)
    └── KeycloakAdministratorTransport

OpenIdError (base)
    ├── OpenIdTokenExpiredError
    ├── OpenIdTokenInvalidError
    ├── OpenIdTokenRoleForbiddenError
    └── ... (и другие)
```

---

## Лицензия

ISC

## Автор

**Renat Gubaev** - [renat.gubaev@gmail.com](mailto:renat.gubaev@gmail.com)

## Ссылки

- [GitHub](https://github.com/ManhattanDoctor/ts-core-openid-common)
- [Issues](https://github.com/ManhattanDoctor/ts-core-openid-common/issues)
- [OpenID Connect](https://openid.net/connect/)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
