# @ts-core/openid-common

Библиотека для работы с системами аутентификации и авторизации на основе протокола OpenID Connect.

## 📋 Содержание

- [Описание](#описание)
- [Установка](#установка)
- [Основные возможности](#основные-возможности)
- [Быстрый старт](#быстрый-старт)
- [API](#api)
- [Архитектура](#архитектура)
- [Обработка ошибок](#обработка-ошибок)
- [Примеры использования](#примеры-использования)
- [Разработка](#разработка)
- [Лицензия](#лицензия)

## Описание

`@ts-core/openid-common` — это TypeScript библиотека, предназначенная для работы с системами аутентификации и авторизации на основе протокола OpenID Connect. Она предоставляет полный набор инструментов для взаимодействия с провайдерами OpenID, такими как Keycloak, и значительно упрощает управление токенами доступа, проверку прав доступа и аутентификацию пользователей.

### Основное назначение

Библиотека создана для упрощения интеграции систем, основанных на OpenID Connect, в ваши приложения. Она предоставляет возможности для:
- Аутентификации пользователей через OpenID провайдеров
- Получения профилей пользователей
- Проверки ролей и прав доступа
- Валидации токенов (online и offline)
- Управления refresh-токенами
- Обеспечения безопасности через проверку подписей токенов

## Установка

```bash
npm install @ts-core/openid-common
```

### Зависимости

Библиотека требует установки следующей зависимости:
- `@ts-core/common` (версия ~3.0.57)

## Основные возможности

### 1. 🔐 Аутентификация и авторизация

- **Получение токенов по коду авторизации** — метод `getTokenByCode` позволяет обменять код авторизации на токен доступа в рамках стандартного потока OAuth 2.0/OpenID Connect
- **Обновление токенов** — метод `getTokenByRefreshToken` для получения нового токена доступа с помощью refresh-токена
- **Выход из системы** — метод `logoutByRefreshToken` для безопасного завершения сессии

### 2. 👤 Работа с данными пользователя

- **Получение информации о пользователе** — метод `getUserInfo` позволяет получить профиль пользователя на основе токена доступа
- **Online и offline режимы** — поддержка получения данных как через запросы к серверу, так и из самого токена

### 3. 🛡️ Валидация токенов

- **Online валидация** — проверка токена через обращение к серверу OpenID провайдера
- **Offline валидация** — проверка подписи токена с использованием публичного ключа без обращения к серверу
- **Проверка срока действия** — автоматическая валидация времени жизни токена
- **Проверка audience и issuer** — валидация параметров токена для обеспечения безопасности

### 4. 🔑 Управление ролями и ресурсами

- **Проверка ролей** — методы `validateRole` и `hasRole` для проверки наличия у пользователя определенных ролей
- **Проверка доступа к ресурсам** — методы `validateResource` и `hasResourceScope` для проверки прав доступа к конкретным ресурсам
- **Получение списка ресурсов** — метод `getResources` возвращает доступные пользователю ресурсы и области видимости (scopes)

### 5. ⚠️ Обработка ошибок

Библиотека определяет детальную систему ошибок для различных сценариев:
- `TOKEN_EXPIRED` — токен истек
- `TOKEN_INVALID` — токен невалиден
- `TOKEN_NOT_ACTIVE` — токен еще не активен
- `TOKEN_ROLE_FORBIDDEN` — недостаточно прав (роль)
- `TOKEN_RESOURCE_FORBIDDEN` — недостаточно прав (ресурс)
- `TOKEN_SIGNATURE_INVALID` — неверная подпись токена
- И многие другие (см. раздел [Обработка ошибок](#обработка-ошибок))

### 6. 🔧 Утилитарные функции

- Извлечение токена из HTTP-запросов
- Работа с датами и временными метками
- Парсинг и преобразование данных токенов
- Работа с JWT токенами

## Быстрый старт

### Инициализация Keycloak Service

```typescript
import { KeycloakService, IKeycloakSettings } from '@ts-core/openid-common';

// Настройка подключения к Keycloak
const settings: IKeycloakSettings = {
    url: 'https://your-keycloak-server.com',
    realm: 'your-realm',
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret', // опционально
    publicKey: 'your-public-key' // для offline валидации
};

// Создание экземпляра сервиса
const openIdService = new KeycloakService(settings);
```

### Получение токена по коду авторизации

```typescript
const code = {
    code: 'authorization-code',
    redirectUri: 'https://your-app.com/callback'
};

try {
    const token = await openIdService.getTokenByCode(code);
    console.log('Access Token:', token.accessToken);
    console.log('Refresh Token:', token.refreshToken);
} catch (error) {
    console.error('Ошибка получения токена:', error);
}
```

### Получение информации о пользователе

```typescript
try {
    const userInfo = await openIdService.getUserInfo(accessToken);
    console.log('Информация о пользователе:', userInfo);
} catch (error) {
    console.error('Ошибка получения данных пользователя:', error);
}
```

### Валидация токена

```typescript
try {
    // Online валидация (с обращением к серверу)
    await openIdService.validateToken(accessToken);
    
    // Offline валидация (без обращения к серверу)
    await openIdService.validateToken(accessToken, { isOffline: true });
    
    console.log('Токен валиден');
} catch (error) {
    console.error('Токен невалиден:', error);
}
```

### Проверка ролей

```typescript
// Проверка с выбросом исключения при отсутствии роли
try {
    await openIdService.validateRole(accessToken, {
        role: 'admin',
        isRealmRole: true // роль уровня realm
    });
    console.log('Пользователь является администратором');
} catch (error) {
    console.error('Недостаточно прав');
}

// Проверка с возвратом boolean
const isAdmin = await openIdService.hasRole(accessToken, {
    role: 'admin',
    isRealmRole: true
});

if (isAdmin) {
    console.log('Пользователь является администратором');
}
```

### Проверка доступа к ресурсам

```typescript
// Проверка доступа с выбросом исключения
try {
    await openIdService.validateResource(accessToken, {
        resource: 'api-resource',
        scope: 'read'
    });
    console.log('Доступ разрешен');
} catch (error) {
    console.error('Доступ запрещен');
}

// Проверка доступа с возвратом boolean
const hasAccess = await openIdService.hasResourceScope(accessToken, {
    resource: 'api-resource',
    scope: 'write'
});
```

### Получение доступных ресурсов

```typescript
try {
    const resources = await openIdService.getResources(accessToken);
    console.log('Доступные ресурсы:', resources);
} catch (error) {
    console.error('Ошибка получения ресурсов:', error);
}
```

## API

### OpenIdService (абстрактный класс)

Базовый класс, определяющий интерфейс для работы с OpenID Connect провайдерами.

#### Методы аутентификации

##### `getUserInfo<T extends IOpenIdUser>(token: string, isOffline?: boolean): Promise<T>`
Получение информации о пользователе на основе токена доступа.

**Параметры:**
- `token` — токен доступа
- `isOffline` — получить данные из токена без обращения к серверу (опционально)

**Возвращает:** Promise с объектом пользователя

---

##### `getTokenByCode<T extends IOpenIdTokenRefreshable>(code: IOpenIdCode): Promise<T>`
Обмен кода авторизации на токен доступа.

**Параметры:**
- `code` — объект с кодом авторизации и redirect URI

**Возвращает:** Promise с объектом токена (access token и refresh token)

---

##### `getTokenByRefreshToken<T extends IOpenIdTokenRefreshable>(token: string): Promise<T>`
Получение нового токена доступа с помощью refresh-токена.

**Параметры:**
- `token` — refresh-токен

**Возвращает:** Promise с новым объектом токена

---

##### `getResources(token: string, options?: OpenIdResourceValidationOptions, claim?: IOpenIdClaim): Promise<OpenIdResources>`
Получение списка ресурсов, доступных пользователю.

**Параметры:**
- `token` — токен доступа
- `options` — параметры фильтрации ресурсов (опционально)
- `claim` — дополнительные claims для проверки (опционально)

**Возвращает:** Promise с объектом ресурсов и их областей видимости

---

##### `logoutByRefreshToken(token: string): Promise<void>`
Завершение сессии пользователя.

**Параметры:**
- `token` — refresh-токен

**Возвращает:** Promise<void>

---

#### Методы валидации

##### `validateToken(token: string, options?: IOpenIdOfflineValidationOptions): Promise<void>`
Валидация токена доступа.

**Параметры:**
- `token` — токен доступа
- `options` — параметры валидации (online/offline режим, публичный ключ и др.)

**Выбрасывает:** OpenIdError при невалидном токене

---

##### `validateRole(token: string, options: IOpenIdRoleValidationOptions): Promise<void>`
Проверка наличия у пользователя определенной роли.

**Параметры:**
- `token` — токен доступа
- `options` — параметры проверки роли (название роли, уровень realm/resource)

**Выбрасывает:** OpenIdError при отсутствии необходимой роли

---

##### `validateResource(token: string, options: OpenIdResourceValidationOptions): Promise<void>`
Проверка доступа пользователя к ресурсу.

**Параметры:**
- `token` — токен доступа
- `options` — параметры проверки (название ресурса, scope)

**Выбрасывает:** OpenIdError при отсутствии доступа

---

##### `hasRole(token: string, options: IOpenIdRolePermissionOptions): Promise<boolean>`
Проверка наличия роли без выброса исключения.

**Параметры:**
- `token` — токен доступа
- `options` — параметры проверки роли

**Возвращает:** Promise<boolean> — true, если роль есть, false — если нет

---

##### `hasResourceScope(token: string, options: OpenIdResourceValidationOptions): Promise<boolean>`
Проверка доступа к ресурсу без выброса исключения.

**Параметры:**
- `token` — токен доступа
- `options` — параметры проверки

**Возвращает:** Promise<boolean> — true, если доступ есть, false — если нет

---

### KeycloakService

Реализация OpenIdService для работы с Keycloak.

```typescript
const service = new KeycloakService(settings: IKeycloakSettings);
```

**Конфигурация IKeycloakSettings:**
```typescript
interface IKeycloakSettings {
    url: string;              // URL Keycloak сервера
    realm: string;            // Название realm
    clientId: string;         // ID клиента
    clientSecret?: string;    // Секрет клиента (опционально)
    publicKey?: string;       // Публичный ключ для offline валидации
}
```

### KeycloakClient

Низкоуровневый клиент для прямой работы с Keycloak API.

```typescript
const client = new KeycloakClient(accessToken: string, settings: IKeycloakSettings);
```

### KeycloakTokenManager

Менеджер для управления жизненным циклом токенов с автоматическим обновлением.

```typescript
const tokenManager = new KeycloakTokenManager(service: KeycloakService);
```

### KeycloakAdministratorTransport

Транспорт для выполнения административных операций в Keycloak.

```typescript
const adminTransport = new KeycloakAdministratorTransport(settings: IKeycloakSettings);
```

## Архитектура

### Структура проекта

```
src/
├── error/                          # Классы ошибок
│   ├── OpenIdError.ts             # Базовый класс ошибок
│   └── OpenIdErrorCode.ts         # Коды ошибок
├── lib/                           # Интерфейсы и типы
│   ├── IOpenIdCode.ts            # Интерфейс кода авторизации
│   ├── IOpenIdToken.ts           # Интерфейс токена
│   ├── IOpenIdUser.ts            # Интерфейс пользователя
│   ├── IOpenIdResource.ts        # Интерфейс ресурса
│   ├── IOpenIdClaim.ts           # Интерфейс claims
│   ├── IOpenIdTokenRefreshable.ts        # Интерфейс обновляемого токена
│   ├── IOpenIdTokenRefreshableManager.ts # Интерфейс менеджера токенов
│   └── OpenIdTokenRefreshableTransport.ts # Базовый транспорт для работы с токенами
├── service/                       # Сервисы
│   ├── OpenIdService.ts          # Абстрактный базовый сервис
│   ├── IOpenIdOptions.ts         # Интерфейсы опций
│   └── keycloak/                 # Реализация для Keycloak
│       ├── KeycloakService.ts    # Основной сервис Keycloak
│       ├── KeycloakClient.ts     # HTTP клиент для Keycloak API
│       ├── KeycloakToken.ts      # Класс токена
│       ├── KeycloakAccessToken.ts # Класс access токена
│       ├── KeycloakTokenManager.ts # Менеджер токенов
│       ├── KeycloakUtil.ts       # Утилиты
│       ├── KeycloakAdministratorTransport.ts # Административный транспорт
│       └── IKeycloakSettings.ts  # Интерфейс настроек
└── public-api.ts                  # Публичный API библиотеки
```

### Ключевые компоненты

#### OpenIdService
Абстрактный класс, определяющий контракт для всех реализаций OpenID Connect провайдеров. Содержит методы для:
- Аутентификации и получения токенов
- Валидации токенов
- Работы с пользовательскими данными
- Проверки ролей и ресурсов

#### KeycloakService
Конкретная реализация OpenIdService для работы с Keycloak. Использует KeycloakClient для выполнения HTTP запросов к Keycloak API.

#### KeycloakClient
Низкоуровневый клиент, инкапсулирующий всю логику взаимодействия с REST API Keycloak. Обрабатывает:
- Получение и обновление токенов
- Валидацию токенов (online и offline)
- Работу с пользовательскими данными
- Проверку ролей и ресурсов

#### KeycloakTokenManager
Менеджер для автоматического управления жизненным циклом токенов. Поддерживает:
- Автоматическое обновление токенов при истечении
- Кэширование токенов
- Обработку ошибок обновления

#### KeycloakUtil
Набор утилитарных функций для:
- Парсинга JWT токенов
- Извлечения claims из токенов
- Проверки ролей
- Работы с датами и временными метками

## Обработка ошибок

Библиотека использует собственную систему ошибок на основе класса `OpenIdError`. Все ошибки содержат код ошибки из перечисления `OpenIdErrorCode`.

### Коды ошибок токена

| Код | Описание |
|-----|----------|
| `TOKEN_EXPIRED` | Токен истек |
| `TOKEN_INVALID` | Токен невалиден |
| `TOKEN_NOT_ACTIVE` | Токен еще не активен (nbf > текущее время) |
| `TOKEN_UNDEFINED` | Токен не передан |
| `TOKEN_STALE` | Токен устарел |
| `TOKEN_WRONG_ISS` | Неверный issuer токена |
| `TOKEN_WRONG_TYPE` | Неверный тип токена |
| `TOKEN_WRONG_AUDIENCE` | Неверный audience |
| `TOKEN_WRONG_CLIENT_ID` | Неверный client ID |

### Коды ошибок ролей и ресурсов

| Код | Описание |
|-----|----------|
| `TOKEN_ROLE_FORBIDDEN` | Недостаточно прав (отсутствует требуемая роль) |
| `TOKEN_ROLE_INVALID_TYPE` | Неверный тип роли |
| `TOKEN_RESOURCE_FORBIDDEN` | Нет доступа к ресурсу |
| `TOKEN_RESOURCES_UNDEFINED` | Ресурсы не определены в токене |
| `TOKEN_RESOURCE_SCOPE_FORBIDDEN` | Нет требуемого scope для ресурса |

### Коды ошибок подписи

| Код | Описание |
|-----|----------|
| `TOKEN_NOT_SIGNED` | Токен не подписан |
| `TOKEN_SIGNATURE_INVALID` | Неверная подпись токена |
| `TOKEN_SIGNATURE_ALGORITHM_UNKNOWN` | Неизвестный алгоритм подписи |

### Коды ошибок конфигурации

| Код | Описание |
|-----|----------|
| `OPTIONS_PUBLIC_KEY_UNDEFINED` | Публичный ключ не определен (для offline валидации) |

### Коды ошибок авторизации

| Код | Описание |
|-----|----------|
| `ACCESS_DENIED_NOT_AUTHORIZED` | Доступ запрещен (не авторизован) |
| `INVALID_GRANT_TOKEN_NOT_ACTIVE` | Токен неактивен |
| `INVALID_GRANT_SESSION_NOT_ACTIVE` | Сессия неактивна |

### Пример обработки ошибок

```typescript
import { OpenIdErrorCode } from '@ts-core/openid-common';

try {
    await openIdService.validateToken(accessToken);
} catch (error) {
    if (error.code === OpenIdErrorCode.TOKEN_EXPIRED) {
        // Токен истек, попробуем обновить
        try {
            const newToken = await openIdService.getTokenByRefreshToken(refreshToken);
            // Используем новый токен
        } catch (refreshError) {
            // Не удалось обновить токен, требуется повторная аутентификация
            redirectToLogin();
        }
    } else if (error.code === OpenIdErrorCode.TOKEN_INVALID) {
        // Токен невалиден, требуется повторная аутентификация
        redirectToLogin();
    } else {
        // Другие ошибки
        console.error('Ошибка валидации:', error);
    }
}
```

## Примеры использования

### Полный пример аутентификации

```typescript
import { KeycloakService, IKeycloakSettings, OpenIdErrorCode } from '@ts-core/openid-common';

// 1. Настройка сервиса
const settings: IKeycloakSettings = {
    url: 'https://keycloak.example.com',
    realm: 'my-realm',
    clientId: 'my-app',
    clientSecret: 'secret',
    publicKey: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----'
};

const authService = new KeycloakService(settings);

// 2. Обработка callback после редиректа с Keycloak
async function handleAuthCallback(code: string, redirectUri: string) {
    try {
        // Получаем токены
        const tokens = await authService.getTokenByCode({ code, redirectUri });
        
        // Сохраняем токены
        sessionStorage.setItem('access_token', tokens.accessToken);
        sessionStorage.setItem('refresh_token', tokens.refreshToken);
        
        // Получаем информацию о пользователе
        const user = await authService.getUserInfo(tokens.accessToken);
        console.log('Авторизован пользователь:', user);
        
        return user;
    } catch (error) {
        console.error('Ошибка аутентификации:', error);
        throw error;
    }
}

// 3. Middleware для проверки авторизации
async function authMiddleware(accessToken: string) {
    try {
        // Валидируем токен
        await authService.validateToken(accessToken, { isOffline: true });
        return true;
    } catch (error) {
        if (error.code === OpenIdErrorCode.TOKEN_EXPIRED) {
            // Пытаемся обновить токен
            const refreshToken = sessionStorage.getItem('refresh_token');
            if (refreshToken) {
                try {
                    const newTokens = await authService.getTokenByRefreshToken(refreshToken);
                    sessionStorage.setItem('access_token', newTokens.accessToken);
                    sessionStorage.setItem('refresh_token', newTokens.refreshToken);
                    return true;
                } catch (refreshError) {
                    return false;
                }
            }
        }
        return false;
    }
}

// 4. Проверка прав доступа
async function checkAdminAccess(accessToken: string): Promise<boolean> {
    const isAdmin = await authService.hasRole(accessToken, {
        role: 'admin',
        isRealmRole: true
    });
    
    return isAdmin;
}

// 5. Выход из системы
async function logout(refreshToken: string) {
    try {
        await authService.logoutByRefreshToken(refreshToken);
        sessionStorage.clear();
    } catch (error) {
        console.error('Ошибка при выходе:', error);
    }
}
```

### Использование с Express.js

```typescript
import express from 'express';
import { KeycloakService } from '@ts-core/openid-common';

const app = express();
const authService = new KeycloakService(settings);

// Middleware для извлечения токена
function extractToken(req: express.Request): string | null {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        return authHeader.substring(7);
    }
    return null;
}

// Middleware для проверки аутентификации
async function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
    const token = extractToken(req);
    
    if (!token) {
        return res.status(401).json({ error: 'Токен не предоставлен' });
    }
    
    try {
        await authService.validateToken(token);
        req.user = await authService.getUserInfo(token, true);
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Невалидный токен' });
    }
}

// Middleware для проверки роли
function requireRole(role: string) {
    return async (req: express.Request, res: express.Response, next: express.NextFunction) => {
        const token = extractToken(req);
        
        try {
            await authService.validateRole(token, { role, isRealmRole: true });
            next();
        } catch (error) {
            return res.status(403).json({ error: 'Недостаточно прав' });
        }
    };
}

// Защищенный маршрут
app.get('/api/protected', requireAuth, async (req, res) => {
    res.json({ message: 'Защищенные данные', user: req.user });
});

// Маршрут только для администраторов
app.get('/api/admin', requireAuth, requireRole('admin'), async (req, res) => {
    res.json({ message: 'Административная панель' });
});

// Callback для OAuth
app.get('/auth/callback', async (req, res) => {
    const { code } = req.query;
    const redirectUri = 'http://localhost:3000/auth/callback';
    
    try {
        const tokens = await authService.getTokenByCode({ 
            code: code as string, 
            redirectUri 
        });
        
        // В реальном приложении используйте более безопасный способ хранения токенов
        res.json(tokens);
    } catch (error) {
        res.status(400).json({ error: 'Ошибка аутентификации' });
    }
});

app.listen(3000);
```

### Автоматическое обновление токенов

```typescript
import { KeycloakTokenManager, KeycloakService } from '@ts-core/openid-common';

class TokenService {
    private tokenManager: KeycloakTokenManager;
    private currentTokens: any;
    
    constructor(authService: KeycloakService) {
        this.tokenManager = new KeycloakTokenManager(authService);
    }
    
    async initialize(code: string, redirectUri: string) {
        // Получаем начальные токены
        this.currentTokens = await this.tokenManager.getTokenByCode({ code, redirectUri });
        
        // Настраиваем автоматическое обновление
        this.setupTokenRefresh();
    }
    
    private setupTokenRefresh() {
        // Обновляем токен за 30 секунд до истечения
        const expiresIn = this.currentTokens.expiresIn || 300;
        const refreshTime = (expiresIn - 30) * 1000;
        
        setTimeout(async () => {
            try {
                this.currentTokens = await this.tokenManager.getTokenByRefreshToken(
                    this.currentTokens.refreshToken
                );
                this.setupTokenRefresh(); // Планируем следующее обновление
            } catch (error) {
                console.error('Не удалось обновить токен:', error);
                // Перенаправляем на страницу входа
            }
        }, refreshTime);
    }
    
    getAccessToken(): string {
        return this.currentTokens.accessToken;
    }
    
    async logout() {
        await this.tokenManager.logoutByRefreshToken(this.currentTokens.refreshToken);
        this.currentTokens = null;
    }
}
```

## Разработка

### Требования

- Node.js >= 14
- TypeScript >= 4.x
- npm или yarn

### Сборка проекта

Проект поддерживает сборку в форматах CommonJS и ES Modules:

```bash
# Сборка CommonJS
npx tsc -p tsconfig.cjs.json

# Сборка ES Modules
npx tsc -p tsconfig.esm.json
```

### Структура сборки

После сборки создаются следующие директории:
- `cjs/` — CommonJS модули
- `esm/` — ES модули

### Использование Makefile

Проект включает Makefile для автоматизации задач разработки.

## Лицензия

ISC

## Автор

**Renat Gubaev**
- Email: renat.gubaev@gmail.com
- GitHub: [ManhattanDoctor](https://github.com/ManhattanDoctor)

## Ссылки

- [Репозиторий на GitHub](https://github.com/ManhattanDoctor/ts-core-openid-common)
- [Сообщить о проблеме](https://github.com/ManhattanDoctor/ts-core-openid-common/issues)
- [Документация OpenID Connect](https://openid.net/connect/)
- [Документация Keycloak](https://www.keycloak.org/documentation)

---

© 2025 Renat Gubaev. Все права защищены.
