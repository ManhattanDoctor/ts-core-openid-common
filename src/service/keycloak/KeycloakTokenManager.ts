import { IOpenIdTokenRefreshable, OpenIdTokenRefreshableManager } from '../../lib';
import { KeycloakToken } from './KeycloakToken';
import { KeycloakAccessToken } from './KeycloakAccessToken';
import * as _ from 'lodash';

export class KeycloakTokenManager<A extends KeycloakAccessToken = KeycloakAccessToken, R extends KeycloakToken = KeycloakToken, T extends IOpenIdTokenRefreshable = IOpenIdTokenRefreshable> extends OpenIdTokenRefreshableManager<A, R, T> {
    //--------------------------------------------------------------------------
    //
    // 	Protected Methods
    //
    //--------------------------------------------------------------------------

    protected createAccess(): A {
        return !_.isNil(this.value.access) ? new KeycloakAccessToken(this.value.access) as A : null;
    }

    protected createRefresh(): R {
        return !_.isNil(this.value.refresh) ? new KeycloakToken(this.value.refresh) as R : null;
    }
}