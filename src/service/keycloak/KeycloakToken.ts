import { DateUtil, TransformUtil } from '@ts-core/common';
import { OpenIdTokenInvalidError, OpenIdTokenUndefinedError } from '../../error';
import * as _ from 'lodash';

export class KeycloakToken {
    // --------------------------------------------------------------------------
    //
    //  Properties
    //
    // --------------------------------------------------------------------------

    protected _value: string;

    protected _header: IOpenIdTokenHeader;
    protected _signed: string;
    protected _content: IOpenIdTokenContent;
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
            this._signed = array[0] + '.' + array[1];
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

    public get header(): IOpenIdTokenHeader {
        return this._header;
    }

    public get signed(): string {
        return this._signed;
    }

    public get content(): IOpenIdTokenContent {
        return this._content;
    }

    public get signature(): Buffer {
        return this._signature;
    }

    public get isExpired(): boolean {
        return this.content.exp * DateUtil.MILLISECONDS_SECOND < Date.now();
    }

    public get value(): string {
        return this._value;
    }
}

export interface IOpenIdTokenHeader {
    alg: string;
    typ: string;
    kid: string;

    [key: string]: any;
}

export type IOpenIdTokenContent = Record<string, any>;