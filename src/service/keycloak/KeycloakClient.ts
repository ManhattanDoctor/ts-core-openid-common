import { ExtendedError, isAxiosError, ObjectUtil, parseAxiosError } from '@ts-core/common';
import { IOpenIdCode, IOpenIdToken, IOpenIdUser } from '../../lib';
import { OpenIdSessionNotActiveError, OpenIdTokenNotActiveError, OpenIdTokenResourceForbiddenError, OpenIdTokenResourceInvalidError } from '../../error';
import { IKeycloakSettings } from './IKeycloakSettings';
import { KeycloakUtil } from './KeycloakUtil';
import { IOpenIdOfflineValidationOptions, IOpenIdResourceScopePermissionOptions, IOpenIdResourceValidationOptions } from '../IOpenIdOptions';
import axios, { AxiosError } from 'axios';
import * as _ from 'lodash';

export class KeycloakClient {
    // --------------------------------------------------------------------------
    //
    //  Constructor
    //
    // --------------------------------------------------------------------------

    constructor(protected settings: IKeycloakSettings, protected token?: string) { }

    // --------------------------------------------------------------------------
    //
    //  Help Methods
    //
    // --------------------------------------------------------------------------

    protected async post<T>(url: string, body?: any, headers?: any): Promise<T> {
        try {
            let { data } = await axios.post<T>(this.getUrl(url), new URLSearchParams(body), { headers });
            return data;
        }
        catch (error) {
            throw isAxiosError(error) ? this.parseAxiosError(error) : error;
        }
    }

    protected async get<T>(url: string, params?: any, headers?: any): Promise<T> {
        try {
            let { data } = await axios.get<T>(this.getUrl(url), { params, headers });
            return data;
        }
        catch (error) {
            throw isAxiosError(error) ? this.parseAxiosError(error) : error;
        }
    }

    protected getUrl(endpoint: string): string {
        return `${this.settings.url}/realms/${this.settings.realm}/protocol/openid-connect/${endpoint}`;
    }

    protected getResources(options: IOpenIdResourceScopePermissionOptions): Promise<KeycloakResources> {
        let data = {
            audience: this.settings.clientId,
            grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
            permission: KeycloakUtil.buildResourcePermission(options),
            response_mode: 'permissions',
        };
        let headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Bearer ${this.token}`
        }
        if (_.isEmpty(data.permission)) {
            delete data.permission;
        }
        return this.post<KeycloakResources>('token', data, headers);
    }

    protected parseAxiosError<U, V>(axios: AxiosError): ExtendedError<U, V> {
        let item = parseAxiosError<U, V>(axios);
        return ObjectUtil.hasOwnProperties(item.details, ['error', 'error_description']) ? this.parseKeycloakError(item as ExtendedError<IKeycloakError, V>) : item;
    }

    protected parseKeycloakError<V>(item: ExtendedError<IKeycloakError, V>): ExtendedError<any, any> {
        let { error, error_description } = item.details;
        if (error === 'invalid_grant') {
            if (error_description === 'Session not active') {
                return new OpenIdSessionNotActiveError();
            }
            if (error_description === 'Token is not active') {
                return new OpenIdTokenNotActiveError();
            }
        }
        return item;
    }

    // --------------------------------------------------------------------------
    //
    //  Validation Methods
    //
    // --------------------------------------------------------------------------

    protected async validateOnline(): Promise<void> {
        let data = {
            token: this.token,
            token_type_hint: 'requesting_party_token'
        };
        let headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Basic ${Buffer.from(`${this.settings.clientId}:${this.settings.clientSecret}`).toString('base64')}`
        }
        let { active } = await this.post<any>(`token/introspect`, data, headers);
        if (!active) {
            throw new OpenIdTokenNotActiveError();
        }
    }

    protected async validateOffline(options: IOpenIdOfflineValidationOptions): Promise<void> {
        if (_.isNil(options.clientId)) {
            options.clientId = this.settings.clientId;
        }
        if (_.isNil(options.publicKey)) {
            options.publicKey = this.settings.realmPublicKey;
        }
        return KeycloakUtil.validateToken(this.token, options);
    }

    // --------------------------------------------------------------------------
    //
    //  Endpoint Methods
    //
    // --------------------------------------------------------------------------

    public async getUserInfo<T extends IOpenIdUser>(isOffline?: boolean): Promise<T> {
        return isOffline ? KeycloakUtil.getUserInfo<T>(this.token) : this.get('userinfo', null, { 'Authorization': `Bearer ${this.token}` });
    }

    public async getTokenByCode<T extends IOpenIdToken>(code: IOpenIdCode): Promise<T> {
        let data = {
            code: code.code,
            client_id: this.settings.clientId,
            grant_type: 'authorization_code',
            redirect_uri: code.redirectUri,
            client_secret: this.settings.clientSecret,
        };
        return this.post<T>('token', data);
    }

    public getTokenByRefreshToken<T extends IOpenIdToken>(token: string): Promise<T> {
        let data = {
            client_id: this.settings.clientId,
            grant_type: 'refresh_token',
            refresh_token: token,
            client_secret: this.settings.clientSecret,
        };
        let headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        return this.post<T>('token', data, headers);
    }

    public logoutByRefreshToken(token: string): Promise<void> {
        let data = {
            client_id: this.settings.clientId,
            client_secret: this.settings.clientSecret,
            refresh_token: token,
        };
        let headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        return this.post('logout', data, headers);
    }

    public async validateToken(options?: IOpenIdOfflineValidationOptions): Promise<void> {
        return !_.isNil(options) ? this.validateOffline(options) : this.validateOnline();
    }

    public async validateResource(options: IOpenIdResourceValidationOptions): Promise<void> {
        let resources: KeycloakResources = null;
        try {
            resources = await this.getResources(options);
        }
        catch (error) {
            switch (error.code) {
                case ExtendedError.HTTP_CODE_BAD_REQUEST:
                    throw new OpenIdTokenResourceInvalidError(error.details);
                case ExtendedError.HTTP_CODE_FORBIDDEN:
                    throw new OpenIdTokenResourceForbiddenError(KeycloakUtil.buildResourcePermission(options));
                default:
                    throw error;
            }
        }
        await KeycloakUtil.validateResourceScope(resources, options);
    }
}

export interface IKeycloakError {
    error: string;
    error_description: string;
}

export type KeycloakResources = Array<IKeycloakResource>;

export interface IKeycloakResource {
    rsid: string;
    rsname: string;
    scopes: Array<string>;
}