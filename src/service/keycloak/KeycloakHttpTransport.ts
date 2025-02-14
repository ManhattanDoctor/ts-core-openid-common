
import { TransportHttp, ITransportHttpRequest, ITransportCommandOptions, ITransportCommand, ITransportHttpSettings } from '@ts-core/common';
import { IKeycloakTokenManager } from './KeycloakTokenManager';
import { OpenIdTokenUndefinedError } from '../../error';
import { IOpenIdRefreshable } from '../../lib';
import * as _ from 'lodash';

export abstract class KeycloakHttpTransport<S extends ITransportHttpSettings = ITransportHttpSettings, O extends ITransportCommandOptions = ITransportCommandOptions> extends TransportHttp<S, O> {
    // --------------------------------------------------------------------------
    //
    //  Properties
    //
    // --------------------------------------------------------------------------

    protected _token: IKeycloakTokenManager;

    // --------------------------------------------------------------------------
    //
    //  Protected Methods
    //
    // --------------------------------------------------------------------------

    protected commitTokenProperties(): void { }

    protected abstract getTokenByRefreshToken(token: string): Promise<IOpenIdRefreshable>;

    protected abstract isSkipRefreshToken<U = any>(path: string, request?: ITransportHttpRequest<U>, options?: ITransportCommandOptions): boolean;

    // --------------------------------------------------------------------------
    //
    //  Public Methods
    //
    // --------------------------------------------------------------------------

    public async call<V = any, U = any>(path: string, request?: ITransportHttpRequest<U>, options?: O): Promise<V> {
        if (!this.isSkipRefreshToken(path, request, options)) {
            if (!this.token.isValid) {
                throw new OpenIdTokenUndefinedError();
            }
            if (this.token.isExpired) {
                this.token.value = await this.getTokenByRefreshToken(this.token.refresh.value);
            }
        }
        return super.call(path, request, options);
    }

    protected prepareCommand<U>(command: ITransportCommand<U>, options: O): void {
        super.prepareCommand(command, options);
        if (!this.token.isValid) {
            return;
        }
        let request = command.request as ITransportHttpRequest;
        request.headers = { Authorization: `Bearer ${this.token.access.value}` };
    }

    // --------------------------------------------------------------------------
    //
    //  Public Properties
    //
    // --------------------------------------------------------------------------

    public get token(): IKeycloakTokenManager {
        return this._token;
    }
    public set token(value: IKeycloakTokenManager) {
        if (value === this._token) {
            return;
        }
        this._token = value;
        if (!_.isNil(value)) {
            this.commitTokenProperties();
        }
    }
}
