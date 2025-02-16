import { DateUtil, TransformUtil } from '@ts-core/common';
import { OpenIdTokenInvalidError, OpenIdTokenUndefinedError } from '../error';
import * as _ from 'lodash';

export class OpenIdToken<H extends IOpenIdTokenHeader = IOpenIdTokenHeader, C extends IOpenIdTokenContent = IOpenIdTokenContent> implements IOpenIdToken {
    // --------------------------------------------------------------------------
    //
    //  Properties
    //
    // --------------------------------------------------------------------------

    protected _value: string;

    protected _header: H;
    protected _signed: string;
    protected _content: C;
    protected _signature: Buffer;

    // --------------------------------------------------------------------------
    //
    //  Constructor
    //
    // --------------------------------------------------------------------------

    constructor(value: string) {
        if (_.isNil(value)) {
            throw new OpenIdTokenUndefinedError();
        }
        this._value = value;
        this.commitTokenProperties();
    }

    // --------------------------------------------------------------------------
    //
    //  Protected Methods
    //
    // --------------------------------------------------------------------------

    protected commitTokenProperties(): void {
        try {
            let array = this.value.split('.');
            this._signed = `${array[0]}.${array[1]}`;
            this._header = TransformUtil.toJSON(Buffer.from(array[0], 'base64').toString());
            this._content = TransformUtil.toJSON(Buffer.from(array[1], 'base64').toString());
            this._signature = Buffer.from(array[2], 'base64');
        } catch (error) {
            throw new OpenIdTokenInvalidError(error.message);
        }
    }

    // --------------------------------------------------------------------------
    //
    //  Public Properties
    //
    // --------------------------------------------------------------------------

    public get value(): string {
        return this._value;
    }

    public get header(): H {
        return this._header;
    }

    public get signed(): string {
        return this._signed;
    }

    public get content(): C {
        return this._content;
    }

    public get signature(): Buffer {
        return this._signature;
    }

    public get isExpired(): boolean {
        return this.content.exp * DateUtil.MILLISECONDS_SECOND < Date.now();
    }
}

export interface IOpenIdToken {
    value: string;
    readonly isExpired: boolean;
}

export interface IOpenIdTokenHeader { }

export interface IOpenIdTokenContent {
    exp: number;
}