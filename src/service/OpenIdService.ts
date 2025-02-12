import { IOpenIdOfflineValidationOptions, IOpenIdResourceScopePermissionOptions, IOpenIdRolePermissionOptions, IOpenIdRoleValidationOptions, OpenIdResourceValidationOptions } from "./IOpenIdOptions";
import { IOpenIdCode, IOpenIdToken, IOpenIdUser } from "../lib";

export abstract class OpenIdService {
    // --------------------------------------------------------------------------
    //
    //  Public Methods
    //
    // --------------------------------------------------------------------------

    abstract getUserInfo<T extends IOpenIdUser>(token: string, isOffline?: boolean): Promise<T>;

    abstract getTokenByCode<T extends IOpenIdToken>(code: IOpenIdCode): Promise<T>;

    abstract getTokenByRefreshToken<T extends IOpenIdToken>(token: string): Promise<T>;

    abstract logoutByRefreshToken(token: string): Promise<void>;

    // --------------------------------------------------------------------------
    //
    //  Validate Methods
    //
    // --------------------------------------------------------------------------

    abstract hasRole(token: string, permission: IOpenIdRolePermissionOptions): Promise<boolean>;

    abstract hasResourceScope(token: string, permission: IOpenIdResourceScopePermissionOptions): Promise<boolean>;

    abstract validateRole(token: string, options: IOpenIdRoleValidationOptions): Promise<void>;

    abstract validateToken(token: string, options?: IOpenIdOfflineValidationOptions, algorithm?: string): Promise<void>;

    abstract validateResource(token: string, options: OpenIdResourceValidationOptions): Promise<void>;
}