import { OpenIdService } from '../OpenIdService';
import { IOpenIdCode, IOpenIdClaim, IOpenIdTokenRefreshable, IOpenIdUser, OpenIdResources } from '../../lib';
import { IKeycloakSettings } from './IKeycloakSettings';
import { KeycloakClient } from './KeycloakClient';
import { IOpenIdOfflineValidationOptions, IOpenIdRolePermissionOptions, IOpenIdRoleValidationOptions, OpenIdResourceValidationOptions } from '../IOpenIdOptions';
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
        return new KeycloakClient(token, this.settings);
    }

    // --------------------------------------------------------------------------
    //
    //  Client Methods
    //
    // --------------------------------------------------------------------------

    public async getUserInfo<T extends IOpenIdUser>(token: string, isOffline?: boolean): Promise<T> {
        return this.client(token).getUserInfo<T>(isOffline);
    }

    public async getTokenByCode<T extends IOpenIdTokenRefreshable>(code: IOpenIdCode): Promise<T> {
        return this.client(null).getTokenByCode(code);
    }

    public async getTokenByRefreshToken<T extends IOpenIdTokenRefreshable>(token: string): Promise<T> {
        return this.client(null).getTokenByRefreshToken(token);
    }

    public async getResources(token: string, options?: OpenIdResourceValidationOptions, claim?: IOpenIdClaim): Promise<OpenIdResources> {
        return this.client(token).getResources(options, claim);
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
        KeycloakUtil.validateRole(token, options);
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

    public async hasResourceScope(token: string, options: OpenIdResourceValidationOptions): Promise<boolean> {
        try {
            await this.validateResource(token, options);
            return true;
        }
        catch (error) {
            return false;
        }
    }
}