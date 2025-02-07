import { OpenIdErrorCode } from './OpenIdErrorCode';
import { ExtendedError } from '@ts-core/common';
import * as _ from 'lodash';

export class OpenIdError<T = void> extends ExtendedError<T, OpenIdErrorCode> {
    // --------------------------------------------------------------------------
    //
    //  Static Methods
    //
    // --------------------------------------------------------------------------

    public static instanceOf(item: any): item is OpenIdError {
        return item instanceof OpenIdError || Object.values(OpenIdErrorCode).includes(item.code);
    }

    // --------------------------------------------------------------------------
    //
    //  Constructor
    //
    // --------------------------------------------------------------------------

    constructor(code: OpenIdErrorCode, public details: T, public status: number = ExtendedError.HTTP_CODE_BAD_REQUEST) {
        super('', code, details);
        this.message = this.constructor.name;
    }
}

// --------------------------------------------------------------------------
//
//  Errors
//
// --------------------------------------------------------------------------

export class OpenIdSessionNotActiveError extends OpenIdError<string> {
    constructor() {
        super(OpenIdErrorCode.SESSION_NOT_ACTIVE, null, ExtendedError.HTTP_CODE_UNAUTHORIZED);
    }
}
export class OpenIdTokenUndefinedError extends OpenIdError {
    constructor() {
        super(OpenIdErrorCode.TOKEN_UNDEFINED, null, ExtendedError.HTTP_CODE_UNAUTHORIZED);
    }
}
export class OpenIdTokenNotActiveError extends OpenIdError {
    constructor() {
        super(OpenIdErrorCode.TOKEN_NOT_ACTIVE, null, ExtendedError.HTTP_CODE_UNAUTHORIZED);
    }
}
export class OpenIdTokenInvalidError extends OpenIdError<string> {
    constructor(message: string) {
        super(OpenIdErrorCode.TOKEN_INVALID, message, ExtendedError.HTTP_CODE_UNAUTHORIZED);
    }
}
export class OpenIdTokenInvalidSignatureError extends OpenIdError {
    constructor() {
        super(OpenIdErrorCode.TOKEN_INVALID_SIGNATURE, null, ExtendedError.HTTP_CODE_UNAUTHORIZED);
    }
}
export class OpenIdTokenExpiredError extends OpenIdError {
    constructor() {
        super(OpenIdErrorCode.TOKEN_EXPIRED, null, ExtendedError.HTTP_CODE_UNAUTHORIZED);
    }
}
export class OpenIdTokenStaleError extends OpenIdError {
    constructor() {
        super(OpenIdErrorCode.TOKEN_STALE, null, ExtendedError.HTTP_CODE_UNAUTHORIZED);
    }
}
export class OpenIdTokenNotSignedError extends OpenIdError {
    constructor() {
        super(OpenIdErrorCode.TOKEN_NOT_SIGNED, null, ExtendedError.HTTP_CODE_FORBIDDEN);
    }
}
export class OpenIdTokenWrongTypeError extends OpenIdError {
    constructor() {
        super(OpenIdErrorCode.TOKEN_WRONG_TYPE, null, ExtendedError.HTTP_CODE_FORBIDDEN);
    }
}
export class OpenIdTokenWrongIssError extends OpenIdError {
    constructor() {
        super(OpenIdErrorCode.TOKEN_WRONG_ISS, null, ExtendedError.HTTP_CODE_FORBIDDEN);
    }
}
export class OpenIdTokenWrongAudienceError extends OpenIdError {
    constructor() {
        super(OpenIdErrorCode.TOKEN_WRONG_AUDIENCE, null, ExtendedError.HTTP_CODE_FORBIDDEN);
    }
}
export class OpenIdTokenWrongClientIdError extends OpenIdError {
    constructor() {
        super(OpenIdErrorCode.TOKEN_WRONG_CLIENT_ID, null, ExtendedError.HTTP_CODE_FORBIDDEN);
    }
}
export class OpenIdTokenRoleForbiddenError extends OpenIdError<string> {
    constructor(role: string) {
        super(OpenIdErrorCode.TOKEN_ROLE_FORBIDDEN, role, ExtendedError.HTTP_CODE_FORBIDDEN);
    }
}
export class OpenIdTokenRoleInvalidTypeError extends OpenIdError<string> {
    constructor(type: string) {
        super(OpenIdErrorCode.TOKEN_ROLE_INVALID_TYPE, type, ExtendedError.HTTP_CODE_FORBIDDEN);
    }
}
export class OpenIdTokenResourceInvalidError extends OpenIdError<any> {
    constructor(details: any) {
        super(OpenIdErrorCode.TOKEN_RESOURCE_INVALID, details, ExtendedError.HTTP_CODE_FORBIDDEN);
    }
}
export class OpenIdTokenResourceForbiddenError extends OpenIdError<string> {
    constructor(resource: string) {
        super(OpenIdErrorCode.TOKEN_RESOURCE_FORBIDDEN, resource, ExtendedError.HTTP_CODE_FORBIDDEN);
    }
}
export class OpenIdTokenResourceScopeForbiddenError extends OpenIdError<string> {
    constructor(scope: string) {
        super(OpenIdErrorCode.TOKEN_RESOURCE_SCOPE_FORBIDDEN, scope, ExtendedError.HTTP_CODE_FORBIDDEN);
    }
}
