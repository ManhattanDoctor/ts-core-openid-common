import { IOpenIdOfflineValidationOptions, IOpenIdRolePermissionOptions, IOpenIdRoleValidationOptions, OpenIdResourceValidationOptions } from "./IOpenIdOptions";
import { IOpenIdCode, IOpenIdClaim, IOpenIdClientCredentials, IOpenIdTokenRefreshable, IOpenIdUser, OpenIdResources } from "../lib";

export abstract class OpenIdService {
    // --------------------------------------------------------------------------
    //
    //  Public Methods
    //
    // --------------------------------------------------------------------------

    abstract getUserInfo<T extends IOpenIdUser>(token: string, isOffline?: boolean): Promise<T>;

    abstract getTokenByCode<T extends IOpenIdTokenRefreshable>(code: IOpenIdCode, credentials?: IOpenIdClientCredentials): Promise<T>;

    abstract getTokenByRefreshToken<T extends IOpenIdTokenRefreshable>(token: string, credentials?: IOpenIdClientCredentials, scope?: string): Promise<T>;

    abstract getTokenByClientCredentials(credentials?: IOpenIdClientCredentials, scope?: string): Promise<string>;

    abstract getResources(token: string, options?: OpenIdResourceValidationOptions, claim?: IOpenIdClaim): Promise<OpenIdResources>;

    abstract logoutByRefreshToken(token: string): Promise<void>;

    // --------------------------------------------------------------------------
    //
    //  Validate Methods
    //
    // --------------------------------------------------------------------------

    abstract hasRole(token: string, options: IOpenIdRolePermissionOptions): Promise<boolean>;

    abstract hasResourceScope(token: string, options: OpenIdResourceValidationOptions): Promise<boolean>;

    abstract validateRole(token: string, options: IOpenIdRoleValidationOptions): Promise<void>;

    abstract validateToken(token: string, options?: IOpenIdOfflineValidationOptions): Promise<void>;

    abstract validateResource(token: string, options: OpenIdResourceValidationOptions): Promise<void>;
}