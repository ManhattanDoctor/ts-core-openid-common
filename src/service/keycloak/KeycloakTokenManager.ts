import { IDestroyable } from '@ts-core/common';
import { IOpenIdToken } from '../../lib';
import { KeycloakToken } from './KeycloakToken';
import { KeycloakAccessToken } from './KeycloakAccessToken';
import * as _ from 'lodash';

export class KeycloakTokenManager implements IKeycloakTokenManager, IDestroyable {
    //--------------------------------------------------------------------------
    //
    // 	Properties
    //
    //--------------------------------------------------------------------------

    protected _value: IOpenIdToken;
    protected _access: KeycloakAccessToken;
    protected _refresh: KeycloakToken;

    //--------------------------------------------------------------------------
    //
    // 	Constructor
    //
    //--------------------------------------------------------------------------

    constructor(value?: IOpenIdToken) {
        this.value = value;
    }

    //--------------------------------------------------------------------------
    //
    // 	Protected Methods
    //
    //--------------------------------------------------------------------------

    protected commitValueProperties(): void {
        this._access = this.isValid ? new KeycloakAccessToken(this.value.access_token) : null;
        this._refresh = this.isValid ? new KeycloakToken(this.value.refresh_token) : null;
    }

    //--------------------------------------------------------------------------
    //
    // 	Public Methods
    //
    //--------------------------------------------------------------------------

    public destroy(): void {
        this.value = null;
    }

    //--------------------------------------------------------------------------
    //
    // 	Public Methods
    //
    //--------------------------------------------------------------------------

    public get access(): KeycloakAccessToken {
        return this._access;
    }

    public get refresh(): KeycloakToken {
        return this._refresh;
    }

    public get isExpired(): boolean {
        return !this.isValid || this.access.isExpired;
    }

    public get isValid(): boolean {
        return !_.isNil(this.value);
    }

    public get value(): IOpenIdToken {
        return this._value;
    }
    public set value(value: IOpenIdToken) {
        if (value === this._value) {
            return;
        }
        this._value = value;
        this.commitValueProperties();
    }
}


export interface IKeycloakTokenManager {
    readonly access: KeycloakAccessToken;
    readonly refresh: KeycloakToken;

    readonly isValid: boolean;
    readonly isExpired: boolean;

    value: IOpenIdToken;
}

