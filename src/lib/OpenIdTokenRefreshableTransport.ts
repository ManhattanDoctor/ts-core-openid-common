
import { TransportHttp, ITransportHttpRequest, ITransportCommandOptions, ITransportCommand, ITransportHttpSettings } from '@ts-core/common';
import { IOpenIdTokenRefreshableManager } from './IOpenIdTokenRefreshableManager';
import { OpenIdTokenUndefinedError } from '../error';
import { IOpenIdTokenRefreshable } from './IOpenIdTokenRefreshable';
import * as _ from 'lodash';

export abstract class OpenIdTokenRefreshableTransport<S extends ITransportHttpSettings = ITransportHttpSettings, O extends ITransportCommandOptions = ITransportCommandOptions> extends TransportHttp<S, O> {
    // --------------------------------------------------------------------------
    //
    //  Properties
    //
    // --------------------------------------------------------------------------

    protected _token: IOpenIdTokenRefreshableManager;

    // --------------------------------------------------------------------------
    //
    //  Protected Methods
    //
    // --------------------------------------------------------------------------

    protected async checkRefreshable<U = any>(path: string, request?: ITransportHttpRequest<U>, options?: O): Promise<void> {
        if (_.isNil(this.token) || !this.token.isValid) {
            throw new OpenIdTokenUndefinedError();
        }
        if (this.token.isExpired) {
            this.token.value = await this.getRefreshable();
        }
    }

    protected prepareCommand<U>(command: ITransportCommand<U>, options: O): void {
        super.prepareCommand(command, options);
        if (_.isNil(this.token) || !this.token.isValid) {
            return;
        }
        let request = command.request as ITransportHttpRequest;
        request.headers = { Authorization: `Bearer ${this.token.access.value}` };
    }

    protected commitTokenProperties(): void { }

    protected abstract getRefreshable(): Promise<IOpenIdTokenRefreshable>;

    protected abstract isSkipCheckRefreshable<U = any>(path: string, request?: ITransportHttpRequest<U>, options?: ITransportCommandOptions): boolean;

    // --------------------------------------------------------------------------
    //
    //  Public Methods
    //
    // --------------------------------------------------------------------------

    public async refresh(isForce?: boolean): Promise<boolean> {
        if (_.isNil(this.token) || !this.token.isValid) {
            return false;
        }
        if (this.token.isExpired || isForce) {
            this.token.value = await this.getRefreshable();
        }
        return true;
    }

    public async call<V = any, U = any>(path: string, request?: ITransportHttpRequest<U>, options?: O): Promise<V> {
        if (!this.isSkipCheckRefreshable(path, request, options)) {
            await this.checkRefreshable(path, request, options);
        }
        return super.call(path, request, options);
    }

    // --------------------------------------------------------------------------
    //
    //  Public Properties
    //
    // --------------------------------------------------------------------------

    public get token(): IOpenIdTokenRefreshableManager {
        return this._token;
    }
    public set token(value: IOpenIdTokenRefreshableManager) {
        if (value === this._token) {
            return;
        }
        this._token = value;
        if (!_.isNil(value)) {
            this.commitTokenProperties();
        }
    }
}
