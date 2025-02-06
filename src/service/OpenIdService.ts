import { IOpenIdOfflineValidationOptions, IOpenIdResourceScopePermissionOptions, IOpenIdResourceValidationOptions, IOpenIdRolePermissionOptions, IOpenIdRoleValidationOptions } from "./IOpenIdOptions";
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

    // --------------------------------------------------------------------------
    //
    //  Validate Methods
    //
    // --------------------------------------------------------------------------

    abstract hasRole(token: string, permission: IOpenIdRolePermissionOptions): Promise<boolean>;

    abstract hasResourceScope(token: string, permission: IOpenIdResourceScopePermissionOptions): Promise<boolean>;

    abstract validateRole(token: string, options: IOpenIdRoleValidationOptions): Promise<void>;

    abstract validateToken(token: string, options?: IOpenIdOfflineValidationOptions): Promise<void>;

    abstract validateResource(token: string, options: IOpenIdResourceValidationOptions): Promise<void>;
}