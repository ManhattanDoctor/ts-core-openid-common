import { DestroyableContainer, ExtendedError, isAxiosError, ObjectUtil, parseAxiosError } from '@ts-core/common';
import { IOpenIdClaim, IOpenIdCode, IOpenIdResource, IOpenIdTokenRefreshable, IOpenIdUser, OpenIdResources } from '../../lib';
import { OpenIdAccessDeniedNotAuthorizedError, OpenIdInvalidGrantSessionNotActiveError, OpenIdInvalidGrantTokenNotActiveError, OpenIdTokenNotActiveError } from '../../error';
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

    protected async post<T = any>(url: string, body?: any, headers?: any): Promise<T> {
        try {
            let { data } = await axios.post<T>(this.getUrl(url), KeycloakUtil.toFormData(body), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers }
            });
            return data;
        }
        catch (error) {
            throw isAxiosError(error) ? this.parseAxiosError(error) : error;
        }
    }

    protected async get<T = any>(url: string, params?: any, headers?: any): Promise<T> {
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
        let details = { code: error, description: error_description };
        if (error === 'invalid_grant') {
            if (error_description === 'Token is not active') {
                return new OpenIdInvalidGrantTokenNotActiveError(details);
            }
            if (error_description === 'Session not active') {
                return new OpenIdInvalidGrantSessionNotActiveError(details);
            }
        }
        if (error === 'access_denied') {
            if (error_description === 'not_authorized') {
                return new OpenIdAccessDeniedNotAuthorizedError(details);
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
        let item = await this.post<any>(`token/introspect`, data, { 'Authorization': `Basic ${Buffer.from(`${this.settings.clientId}:${this.settings.clientSecret}`).toString('base64')}` });
        if (!item.active) {
            throw new OpenIdTokenNotActiveError();
        }
    }

    protected async validateOffline(options: IOpenIdOfflineValidationOptions): Promise<void> {
        let clientId = options.clientId;
        let publicKey = options.publicKey;
        if (_.isNil(clientId)) {
            clientId = this.settings.clientId;
        }
        if (_.isNil(publicKey)) {
            publicKey = this.settings.realmPublicKey;
        }
        let item: IOpenIdOfflineValidationOptions = { ...options, clientId, publicKey };
        return KeycloakUtil.validateToken(this.token, item);
    }

    public async getResources(options?: OpenIdResourceValidationOptions, claim?: IOpenIdClaim): Promise<OpenIdResources> {
        let data: any = {
            audience: this.settings.clientId,
            grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
            response_mode: 'permissions',
            client_secret: this.settings.clientSecret,
        };

        if (!_.isEmpty(options)) {
            let permissions = KeycloakUtil.buildResourcePermission(options);
            if (!_.isEmpty(permissions)) {
                data.permission = permissions;
            }
        }
        if (!_.isEmpty(claim)) {
            let { token, format } = KeycloakUtil.buildResourceTokenClaim(claim);
            data.claim_token = token;
            data.claim_token_format = format;
        }

        let items = await this.post<Array<IKeycloakResource>>('token', data, { 'Authorization': `Bearer ${this.token}` });
        let resources = new Map<string, IOpenIdResource>();
        items.forEach(item => resources.set(item.rsname, { id: item.rsid, name: item.rsname, scopes: item.scopes }));
        return resources;
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

    public async getTokenByCode<T extends IOpenIdTokenRefreshable>(code: IOpenIdCode, clientId?: string, clientSecret?: string): Promise<T> {
        if (_.isNil(clientId)) {
            clientId = this.settings.clientId;
        }
        if (_.isNil(clientSecret)) {
            clientSecret = this.settings.clientSecret;
        }
        let data = {
            code: code.code,
            grant_type: 'authorization_code',
            redirect_uri: code.redirectUri,
            client_id: clientId,
            client_secret: clientSecret
        };
        let { access_token, refresh_token } = await this.post('token', data);
        return { access: access_token, refresh: refresh_token } as T;
    }

    public async getTokenByRefreshToken<T extends IOpenIdTokenRefreshable>(token: string, clientId?: string, clientSecret?: string): Promise<T> {
        if (_.isNil(clientId)) {
            clientId = this.settings.clientId;
        }
        if (_.isNil(clientSecret)) {
            clientSecret = this.settings.clientSecret;
        }
        let data = {
            grant_type: 'refresh_token',
            refresh_token: token,
            client_id: clientId,
            client_secret: clientSecret,
        };
        let { access_token, refresh_token } = await this.post('token', data);
        return { access: access_token, refresh: refresh_token } as T;
    }

    public async getTokenByClientCredentials(clientId?: string, clientSecret?: string): Promise<string> {
        if (_.isNil(clientId)) {
            clientId = this.settings.clientId;
        }
        if (_.isNil(clientSecret)) {
            clientSecret = this.settings.clientSecret;
        }
        let data = {
            grant_type: 'client_credentials',
            client_id: clientId,
            client_secret: clientSecret,
        };
        let { access_token } = await this.post('token', data);
        return access_token;
    }

    public logoutByRefreshToken(token: string): Promise<void> {
        let data = {
            client_id: this.settings.clientId,
            client_secret: this.settings.clientSecret,
            refresh_token: token,
        };
        return this.post('logout', data);
    }

    public async validateToken(options?: IOpenIdOfflineValidationOptions): Promise<void> {
        return !_.isNil(options) ? this.validateOffline(options) : this.validateOnline();
    }

    public async validateResource(options: OpenIdResourceValidationOptions): Promise<void> {
        KeycloakUtil.validateResourceScope(options, await this.getResources(options));
    }

    // --------------------------------------------------------------------------
    //
    //  Public Properties
    //
    // --------------------------------------------------------------------------

    public get token(): string {
        return this._token;
    }
    public set token(value: string) {
        if (value === this._token) {
            return;
        }
        this._token = value;
        if (!_.isNil(value)) {
            this.commitTokenProperties();
        }
    }

    public get settings(): IKeycloakSettings {
        return this._settings;
    }
    public set settings(value: IKeycloakSettings) {
        if (value === this._settings) {
            return;
        }
        this._settings = value;
        if (!_.isNil(value)) {
            this.commitSettingsProperties();
        }
    }
}

interface IKeycloakError {
    error: string;
    error_description: string;
}

interface IKeycloakResource {
    rsid: string;
    rsname: string;
    scopes: Array<string>;
}