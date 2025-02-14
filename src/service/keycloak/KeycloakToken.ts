import { IOpenIdTokenContent, IOpenIdTokenHeader, OpenIdToken } from '../../lib';
import * as _ from 'lodash';

export class KeycloakToken<H extends IKeycloakTokenHeader = IKeycloakTokenHeader, C extends IKeycloakContent = IKeycloakContent> extends OpenIdToken<H, C> { }

export interface IKeycloakTokenHeader extends IOpenIdTokenHeader {
    alg: string;
}

export interface IKeycloakContent extends IOpenIdTokenContent {
    iat: number;
    typ: string;
    iss: string;
    aud: string;
    azp: string;
    notBefore: number;
    realm_access: object;
    resource_access: object;
}