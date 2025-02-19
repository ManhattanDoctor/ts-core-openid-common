import { IDestroyable, Loadable, ObservableData } from '@ts-core/common';
import { filter, map, Observable } from 'rxjs';
import { IOpenIdToken } from './IOpenIdToken';
import { IOpenIdTokenRefreshable } from './IOpenIdTokenRefreshable';
import * as _ from 'lodash';

export abstract class OpenIdTokenRefreshableManager<A extends IOpenIdToken, R extends IOpenIdToken, T extends IOpenIdTokenRefreshable> extends Loadable<OpenIdTokenRefreshableManagerEvent, T> implements IOpenIdTokenRefreshableManager<A, R, T> {
    //--------------------------------------------------------------------------
    //
    // 	Properties
    //
    //--------------------------------------------------------------------------

    protected _value: T;
    protected _access: A;
    protected _refresh: R;

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
        this._access = this.isValid ? this.createAccess() : null;
        this._refresh = this.isValid ? this.createRefresh() : null;
        if (!_.isNil(this.observer)) {
            this.observer.next(new ObservableData(OpenIdTokenRefreshableManagerEvent.CHANGED, this.value));
        }
    }

    protected abstract createAccess(): A;

    protected abstract createRefresh(): R;

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

    public get access(): A {
        return this._access;
    }

    public get refresh(): R {
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

    public get changed(): Observable<IOpenIdTokenRefreshable> {
        return this.events.pipe(
            filter(item => item.type === OpenIdTokenRefreshableManagerEvent.CHANGED),
            map(() => this.value)
        );
    }
}

export enum OpenIdTokenRefreshableManagerEvent {
    CHANGED = 'CHANGED'
}

export interface IOpenIdTokenRefreshableManager<A extends IOpenIdToken = IOpenIdToken, R extends IOpenIdToken = IOpenIdToken, T extends IOpenIdTokenRefreshable = IOpenIdTokenRefreshable> extends IDestroyable {
    readonly access: A;
    readonly refresh: R;
    readonly isValid: boolean;
    readonly isExpired: boolean;

    value: T;
}