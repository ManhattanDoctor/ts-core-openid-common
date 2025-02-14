import { IOpenIdTokenContent, IOpenIdTokenHeader, OpenIdToken } from '../../lib';
import * as _ from 'lodash';

export class KeycloakToken<H extends IKeycloakTokenHeader = IKeycloakTokenHeader, C extends IKeycloakTokenContent = IKeycloakTokenContent> extends OpenIdToken<H, C> { }

export interface IKeycloakTokenHeader extends IOpenIdTokenHeader {
    alg: string;
}

export interface IKeycloakTokenContent extends IOpenIdTokenContent {
    iat: number;
    sub: string;
    typ: string;
    iss: string;
    aud: string;
    azp: string;
    notBefore: number;
    realm_access: object;
    resource_access: object;
}