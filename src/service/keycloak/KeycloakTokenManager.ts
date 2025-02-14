import { IDestroyable, Loadable, ObservableData } from '@ts-core/common';
import { IOpenIdRefreshable } from '../../lib';
import { KeycloakToken } from './KeycloakToken';
import { KeycloakAccessToken } from './KeycloakAccessToken';
import { filter, map, Observable } from 'rxjs';
import * as _ from 'lodash';

export class KeycloakTokenManager<T extends IOpenIdRefreshable = IOpenIdRefreshable> extends Loadable<KeycloakTokenManagerEvent, T> implements IKeycloakTokenManager {
    //--------------------------------------------------------------------------
    //
    // 	Properties
    //
    //--------------------------------------------------------------------------

    protected _value: T;
    protected _access: KeycloakAccessToken;
    protected _refresh: KeycloakToken;

    //--------------------------------------------------------------------------
    //
    // 	Constructor
    //
    //--------------------------------------------------------------------------

    constructor(value?: T) {
        super();
        this.value = value;
    }

    //--------------------------------------------------------------------------
    //
    // 	Protected Methods
    //
    //--------------------------------------------------------------------------

    protected commitValueProperties(): void {
        this._access = this.isValid ? new KeycloakAccessToken(this.value.accessToken) : null;
        this._refresh = this.isValid ? new KeycloakToken(this.value.refreshToken) : null;
        if (!_.isNil(this.observer)) {
            this.observer.next(new ObservableData(KeycloakTokenManagerEvent.CHANGED, this.value));
        }
    }

    //--------------------------------------------------------------------------
    //
    // 	Public Methods
    //
    //--------------------------------------------------------------------------

    public destroy(): void {
        if (this.isDestroyed) {
            return;
        }
        super.destroy();
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

    public get value(): T {
        return this._value;
    }

    public set value(value: T) {
        if (value === this._value) {
            return;
        }
        this._value = value;
        this.commitValueProperties();
    }

    public get isExpired(): boolean {
        return !this.isValid || this.access.isExpired;
    }

    public get isValid(): boolean {
        return !_.isNil(this.value);
    }

    public get changed(): Observable<IOpenIdRefreshable> {
        return this.events.pipe(
            filter(item => item.type === KeycloakTokenManagerEvent.CHANGED),
            map(() => null)
        );
    }
}

export enum KeycloakTokenManagerEvent {
    CHANGED = 'CHANGED'
}


export interface IKeycloakTokenManager extends IDestroyable {
    readonly access: KeycloakAccessToken;
    readonly refresh: KeycloakToken;

    readonly isValid: boolean;
    readonly isExpired: boolean;

    value: IOpenIdRefreshable;
}

