
export enum OpenIdErrorCode {
    TOKEN_STALE = 'OPEN_ID_TOKEN_STALE',
    TOKEN_INVALID = 'OPEN_ID_TOKEN_INVALID',
    TOKEN_EXPIRED = 'OPEN_ID_TOKEN_EXPIRED',
    TOKEN_NOT_ACTIVE = 'OPEN_ID_TOKEN_NOT_ACTIVE',
    TOKEN_UNDEFINED = 'OPEN_ID_TOKEN_UNDEFINED',
    TOKEN_WRONG_ISS = 'OPEN_ID_TOKEN_WRONG_ISS',
    TOKEN_WRONG_TYPE = 'OPEN_ID_TOKEN_WRONG_TYPE',
    TOKEN_WRONG_AUDIENCE = 'OPEN_ID_TOKEN_WRONG_AUDIENCE',
    TOKEN_WRONG_CLIENT_ID = 'OPEN_ID_TOKEN_WRONG_CLIENT_ID',

    TOKEN_ROLE_FORBIDDEN = 'OPEN_ID_TOKEN_ROLE_FORBIDDEN',
    TOKEN_ROLE_INVALID_TYPE = 'OPEN_ID_TOKEN_ROLE_INVALID_TYPE',
    TOKEN_RESOURCE_FORBIDDEN = 'OPEN_ID_TOKEN_RESOURCE_FORBIDDEN',
    TOKEN_RESOURCES_UNDEFINED = 'OPEN_ID_TOKEN_RESOURCES_UNDEFINED',
    TOKEN_RESOURCE_SCOPE_FORBIDDEN = 'OPEN_ID_TOKEN_RESOURCE_SCOPE_FORBIDDEN',

    TOKEN_NOT_SIGNED = 'OPEN_ID_TOKEN_NOT_SIGNED',
    TOKEN_SIGNATURE_INVALID = 'OPEN_ID_TOKEN_SIGNATURE_INVALID',
    TOKEN_SIGNATURE_ALGORITHM_UNKNOWN = 'OPEN_ID_TOKEN_SIGNATURE_ALGORITHM_UNKNOWN',

    OPTIONS_PUBLIC_KEY_UNDEFINED = 'OPEN_ID_OPTIONS_PUBLIC_KEY_UNDEFINED',

    ACCESS_DENIED_NOT_AUTHORIZED = 'OPEN_ID_ACCESS_DENIED_NOT_AUTHORIZED',
    INVALID_GRANT_TOKEN_NOT_ACTIVE = 'OPEN_ID_INVALID_GRANT_TOKEN_NOT_ACTIVE',
    INVALID_GRANT_SESSION_NOT_ACTIVE = 'OPEN_ID_INVALID_GRANT_SESSION_NOT_ACTIVE',
}
