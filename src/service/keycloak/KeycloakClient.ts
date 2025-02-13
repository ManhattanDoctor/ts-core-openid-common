import { DestroyableContainer, ExtendedError, isAxiosError, ObjectUtil, parseAxiosError } from '@ts-core/common';
import { IOpenIdCode, IOpenIdToken, IOpenIdUser } from '../../lib';
import { OpenIdSessionNotActiveError, OpenIdTokenNotActiveError, OpenIdTokenResourceForbiddenError, OpenIdTokenResourceInvalidError } from '../../error';
import { IKeycloakSettings } from './IKeycloakSettings';
import { KeycloakUtil } from './KeycloakUtil';
import { IOpenIdOfflineValidationOptions, OpenIdResourceValidationOptions } from '../IOpenIdOptions';
import axios, { AxiosError } from 'axios';
import * as _ from 'lodash';

export class KeycloakClient extends DestroyableContainer {
    // --------------------------------------------------------------------------
    //
    //  Properties
    //
    // --------------------------------------------------------------------------

    protected _token: string;
    protected _settings: IKeycloakSettings;

    // --------------------------------------------------------------------------
    //
    //  Constructor
    //
    // --------------------------------------------------------------------------

    constructor(token?: string, settings?: IKeycloakSettings) {
        super();
        if (!_.isNil(token)) {
            this.token = token;
        }
        if (!_.isNil(settings)) {
            this.settings = settings;
        }
    }

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
    //  Protected Methods
    //
    // --------------------------------------------------------------------------

    protected commitTokenProperties(): void { }
    protected commitSettingsProperties(): void { }

    // --------------------------------------------------------------------------
    //
    //  Validation Methods
    //
    // --------------------------------------------------------------------------

    protected async validateOnline(): Promise<void> {
        let data = {
            token: this.token,
            token_type_hint: 'requesting_party_token'
        }
        let { active } = await this.post<any>(`token/introspect`, data, {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Basic ${Buffer.from(`${this.settings.clientId}:${this.settings.clientSecret}`).toString('base64')}`
        });
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

    public async getResources(options?: OpenIdResourceValidationOptions): Promise<KeycloakResources> {
        var data = new URLSearchParams();
        data.append('audience', this.settings.clientId);
        data.append('grant_type', 'urn:ietf:params:oauth:grant-type:uma-ticket');
        data.append('response_mode', 'permissions');

        let permissions = KeycloakUtil.buildResourcePermission(options);
        if (!_.isEmpty(permissions)) {
            permissions.forEach(item => data.append('permission', item));
        }
        try {
            return this.post<KeycloakResources>('token', data, {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': `Bearer ${this.token}`
            });
        }
        catch (error) {
            switch (error.code) {
                case ExtendedError.HTTP_CODE_BAD_REQUEST:
                    throw new OpenIdTokenResourceInvalidError(error.details);
                case ExtendedError.HTTP_CODE_FORBIDDEN:
                    throw new OpenIdTokenResourceForbiddenError(permissions);
                default:
                    throw error;
            }
        }
    }

    // --------------------------------------------------------------------------
    //
    //  Endpoint Methods
    //
    // --------------------------------------------------------------------------

    public async getUserInfo<T extends IOpenIdUser>(isOffline?: boolean): Promise<T> {
        return isOffline ? KeycloakUtil.getUserInfo<T>(this.token) : this.get('userinfo', null, {
            'Authorization': `Bearer ${this.token}`
        });
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
        return this.post<T>('token', data, { 'Content-Type': 'application/x-www-form-urlencoded' });
    }

    public logoutByRefreshToken(token: string): Promise<void> {
        let data = {
            client_id: this.settings.clientId,
            client_secret: this.settings.clientSecret,
            refresh_token: token,
        };
        return this.post('logout', data, { 'Content-Type': 'application/x-www-form-urlencoded' });
    }

    public async validateToken(options?: IOpenIdOfflineValidationOptions): Promise<void> {
        return !_.isNil(options) ? this.validateOffline(options) : this.validateOnline();
    }

    public async validateResource(options: OpenIdResourceValidationOptions, resources?: KeycloakResources): Promise<void> {
        await KeycloakUtil.validateResourceScope(options, !_.isNil(resources) ? resources : await this.getResources(options));
    }

    // --------------------------------------------------------------------------
    //
    //  Protected Methods
    //
    // --------------------------------------------------------------------------

    protected get token(): string {
        return this._token;
    }
    protected set token(value: string) {
        if (value === this._token) {
            return;
        }
        this._token = value;
        if (!_.isNil(value)) {
            this.commitTokenProperties();
        }
    }

    protected get settings(): IKeycloakSettings {
        return this._settings;
    }
    protected set settings(value: IKeycloakSettings) {
        if (value === this._settings) {
            return;
        }
        this._settings = value;
        if (!_.isNil(value)) {
            this.commitSettingsProperties();
        }
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