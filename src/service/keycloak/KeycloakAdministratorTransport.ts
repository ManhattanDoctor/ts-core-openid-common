
import { ITransportHttpRequest, ITransportCommandOptions, ILogger } from '@ts-core/common';
import { IKeycloakAdministratorSettings } from './IKeycloakSettings';
import { IOpenIdTokenRefreshable, OpenIdTokenRefreshableTransport } from '../../lib';
import { OpenIdTokenUndefinedError } from '../../error';
import { KeycloakUtil } from './KeycloakUtil';
import * as _ from 'lodash';

export class KeycloakAdministratorTransport<S extends IKeycloakAdministratorSettings = IKeycloakAdministratorSettings, O extends ITransportCommandOptions = ITransportCommandOptions> extends OpenIdTokenRefreshableTransport<S, O> {

    // --------------------------------------------------------------------------
    //
    //  Protected Methods
    //
    // --------------------------------------------------------------------------

    constructor(logger: ILogger, settings: S) {
        super(logger, Object.assign({ method: 'get', baseURL: settings.url, headers: {} }, settings));
    }

    // --------------------------------------------------------------------------
    //
    //  Protected Methods
    //
    // --------------------------------------------------------------------------

    protected async getRefreshableByToken(): Promise<IOpenIdTokenRefreshable> {
        let data = {
            client_id: this.settings.clientId,
            grant_type: 'refresh_token',
            refresh_token: this.token.refresh.value,
            client_secret: this.settings.clientSecret,
        }
        let { access_token, refresh_token } = await this.call(`realms/${this.settings.realm}/protocol/openid-connect/token`, {
            data: KeycloakUtil.toFormData(data),
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            method: 'post'
        });
        return { access: access_token, refresh: refresh_token };
    }

    protected async getRefreshableByCredentials(): Promise<IOpenIdTokenRefreshable> {
        let { access_token, refresh_token } = await this.call(`realms/${this.settings.realm}/protocol/openid-connect/token`, {
            data: KeycloakUtil.toFormData({
                scope: this.settings.scope,
                username: this.settings.login,
                password: this.settings.password,
                client_id: this.settings.clientId,
                client_secret: this.settings.clientSecret,
                grant_type: 'password',
            }),
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            method: 'post'
        });
        return { access: access_token, refresh: refresh_token };
    }

    // --------------------------------------------------------------------------
    //
    //  Keycloak Methods
    //
    // --------------------------------------------------------------------------

    public async refresh(isForce?: boolean): Promise<boolean> {
        if (_.isNil(this.token)) {
            return false;
        }
        if (this.token.isExpired || isForce) {
            this.token.value = await this.getRefreshable();
        }
        return true;
    }

    protected async checkRefreshable<U = any>(path: string, request?: ITransportHttpRequest<U>, options?: O): Promise<void> {
        if (_.isNil(this.token)) {
            throw new OpenIdTokenUndefinedError();
        }
        if (this.token.isExpired) {
            this.token.value = await this.getRefreshable();
        }
    }

    protected getRefreshable(): Promise<IOpenIdTokenRefreshable> {
        return !this.token.isValid || _.isNil(this.token.refresh) || this.token.refresh.isExpired ? this.getRefreshableByCredentials() : this.getRefreshableByToken();
    }

    protected isSkipCheckRefreshable<U = any>(path: string, request?: ITransportHttpRequest<U>, options?: ITransportCommandOptions): boolean {
        return path.includes(`realms/${this.settings.realm}/protocol/openid-connect/token`);
    }
}
