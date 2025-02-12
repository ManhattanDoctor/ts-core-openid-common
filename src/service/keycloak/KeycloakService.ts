import { OpenIdService } from '../OpenIdService';
import { IOpenIdCode, IOpenIdToken, IOpenIdUser } from '../../lib';
import { IKeycloakSettings } from './IKeycloakSettings';
import { KeycloakClient } from './KeycloakClient';
import { IOpenIdOfflineValidationOptions, IOpenIdResourceScopePermissionOptions, IOpenIdRolePermissionOptions, IOpenIdRoleValidationOptions, OpenIdResourceValidationOptions } from '../IOpenIdOptions';
import { KeycloakUtil } from './KeycloakUtil';
import * as _ from 'lodash';

export class KeycloakService extends OpenIdService {
    // --------------------------------------------------------------------------
    //
    //  Constructor
    //
    // --------------------------------------------------------------------------

    constructor(private settings: IKeycloakSettings) {
        super();
    }

    // --------------------------------------------------------------------------
    //
    //  Protected Methods
    //
    // --------------------------------------------------------------------------

    protected client(token: string): KeycloakClient {
        return new KeycloakClient(this.settings, token);
    }

    // --------------------------------------------------------------------------
    //
    //  Client Methods
    //
    // --------------------------------------------------------------------------

    public async getUserInfo<T extends IOpenIdUser>(token: string, isOffline?: boolean): Promise<T> {
        return this.client(token).getUserInfo<T>(isOffline);
    }

    public async getTokenByCode<T extends IOpenIdToken>(code: IOpenIdCode): Promise<T> {
        return this.client(null).getTokenByCode(code);
    }

    public async getTokenByRefreshToken<T extends IOpenIdToken>(token: string): Promise<T> {
        return this.client(null).getTokenByRefreshToken(token);
    }

    public async logoutByRefreshToken(token: string): Promise<void> {
        return this.client(null).logoutByRefreshToken(token);
    }

    // --------------------------------------------------------------------------
    //
    //  Validate Methods
    //
    // --------------------------------------------------------------------------

    public async validateToken(token: string, options?: IOpenIdOfflineValidationOptions): Promise<void> {
        return this.client(token).validateToken(options);
    }

    public async validateRole(token: string, options: IOpenIdRoleValidationOptions): Promise<void> {
        return KeycloakUtil.validateRole(token, options);
    }

    public async validateResource(token: string, options: OpenIdResourceValidationOptions): Promise<void> {
        return this.client(token).validateResource(options);
    }

    public async hasRole(token: string, options: IOpenIdRolePermissionOptions): Promise<boolean> {
        try {
            await this.validateRole(token, options);
            return true;
        }
        catch (error) {
            return false;
        }
    }

    public async hasResourceScope(token: string, options: IOpenIdResourceScopePermissionOptions | Array<IOpenIdResourceScopePermissionOptions>): Promise<boolean> {
        try {
            await this.validateResource(token, options);
            return true;
        }
        catch (error) {
            return false;
        }
    }
}