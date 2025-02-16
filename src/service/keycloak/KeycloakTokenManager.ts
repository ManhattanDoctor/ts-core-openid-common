import { IOpenIdTokenRefreshable, OpenIdTokenRefreshableManager } from '../../lib';
import { KeycloakToken } from './KeycloakToken';
import { KeycloakAccessToken } from './KeycloakAccessToken';
import * as _ from 'lodash';

export class KeycloakTokenManager extends OpenIdTokenRefreshableManager<KeycloakAccessToken, KeycloakToken, IOpenIdTokenRefreshable> {
    //--------------------------------------------------------------------------
    //
    // 	Protected Methods
    //
    //--------------------------------------------------------------------------

    protected createAccess(): KeycloakAccessToken {
        return new KeycloakAccessToken(this.value.access);
    }

    protected createRefresh(): KeycloakToken {
        return new KeycloakToken(this.value.refresh);
    }
}