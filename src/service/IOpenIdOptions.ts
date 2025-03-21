
export interface IOpenIdRoleValidationOptions extends IOpenIdRolePermissionOptions {
    isAny?: boolean;
}

export interface IOpenIdResourceValidationOptions extends IOpenIdResourceScopePermissionOptions {
    isAny?: boolean;
}

export interface IOpenIdOfflineValidationOptions {
    iss?: string;
    type?: string;
    notBefore?: number;
    isVerifyAudience?: boolean;

    clientId?: string;
    publicKey?: string;
}

export interface IOpenIdRolePermissionOptions {
    role: string | Array<string>;
}

export interface IOpenIdResourceScopePermissionOptions {
    name: string;
    scope?: string | Array<string>;
}

export type OpenIdResourceValidationOptions = IOpenIdResourceValidationOptions | Array<IOpenIdResourceValidationOptions>;
