import { IOpenIdTokenContent, IOpenIdTokenHeader, OpenIdToken } from '../../lib';
import * as _ from 'lodash';

export class KeycloakToken extends OpenIdToken<IKeycloakTokenHeader, IKeycloakContent> { }

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
}