import { createVerify } from 'crypto';
import { OpenIdOptionsPublicKeyUndefinedError, OpenIdTokenExpiredError, OpenIdTokenSignatureInvalidError, OpenIdTokenSignatureAlgorithmUnknownError, OpenIdTokenNotSignedError, OpenIdTokenResourceForbiddenError, OpenIdTokenResourceScopeForbiddenError, OpenIdTokenRoleForbiddenError, OpenIdTokenRoleInvalidTypeError, OpenIdTokenStaleError, OpenIdTokenUndefinedError, OpenIdTokenWrongAudienceError, OpenIdTokenWrongClientIdError, OpenIdTokenWrongIssError, OpenIdTokenWrongTypeError } from '../../error';
import { KeycloakResources } from './KeycloakClient';
import { IOpenIdOfflineValidationOptions, IOpenIdRoleValidationOptions, OpenIdResourceValidationOptions } from '../IOpenIdOptions';
import { IOpenIdUser } from '../../lib';
import { KeycloakAccessToken } from './KeycloakAccessToken';
import { KeycloakToken } from './KeycloakToken';
import * as _ from 'lodash';

export class KeycloakUtil {
    // --------------------------------------------------------------------------
    //
    //  Public Methods
    //
    // --------------------------------------------------------------------------

    public static buildResourcePermission(options: OpenIdResourceValidationOptions): Array<string> {
        let items = !_.isArray(options) ? [options] : options;
        let permissions = new Array();
        for (let item of items) {
            if (_.isNil(item) || _.isEmpty(item.name) || _.isEmpty(item.scope)) {
                continue;
            }
            let scopes = !_.isArray(item.scope) ? [item.scope] : item.scope;
            permissions.push(`${item.name}#${scopes.join(',')}`);
        }
        return permissions;
    }

    public static parseRole(role: string): IKeycloakRole {
        let array = role.split(':');
        return array.length > 1 ? { type: array[0], role: array[1] } : { type: KeycloakRole.CLIENT, role: array[0] };
    }

    public static getUserInfo<T extends IOpenIdUser>(token: string): T {
        return new KeycloakAccessToken(token).getUserInfo<T>();
    }

    // --------------------------------------------------------------------------
    //
    //  Validate Token
    //
    // --------------------------------------------------------------------------

    public static async validateToken(token: string, options: IOpenIdOfflineValidationOptions): Promise<void> {
        let item = new KeycloakToken(token);
        if (_.isNil(item.signed)) {
            throw new OpenIdTokenNotSignedError();
        }
        if (item.isExpired) {
            throw new OpenIdTokenExpiredError();
        }
        if (!_.isNil(options.iss) && options.iss !== item.content.iss) {
            throw new OpenIdTokenWrongIssError();
        }
        if (!_.isNil(options.type) && options.type !== item.content.typ) {
            throw new OpenIdTokenWrongTypeError();
        }
        if (!_.isNil(options.notBefore) && options.notBefore > item.content.iat) {
            throw new OpenIdTokenStaleError();
        }

        let audience = _.isArray(item.content.aud) ? item.content.aud : [item.content.aud];
        if (options.type === 'ID') {
            if (!audience.includes(options.clientId)) {
                throw new OpenIdTokenWrongAudienceError();
            }
            if (item.content.azp && item.content.azp !== options.clientId) {
                throw new OpenIdTokenWrongClientIdError();
            }
        } else if (options.isVerifyAudience) {
            if (!audience.includes(options.clientId)) {
                throw new OpenIdTokenWrongAudienceError();
            }
        }
        await KeycloakUtil.validateTokenSignature(item, options);
    }

    public static async validateTokenSignature(token: KeycloakToken, options: IOpenIdOfflineValidationOptions): Promise<void> {
        if (_.isNil(options.publicKey)) {
            throw new OpenIdOptionsPublicKeyUndefinedError();
        }

        let algorithm = null;
        let { alg } = token.header;
        switch (alg) {
            case 'RS256':
                algorithm = 'RSA-SHA256';
                break;
            default:
                throw new OpenIdTokenSignatureAlgorithmUnknownError(alg);
        }
        let verify = createVerify(algorithm).update(token.signed);
        if (!verify.verify(options.publicKey, token.signature.toString('base64'), 'base64')) {
            throw new OpenIdTokenSignatureInvalidError();
        }
    }

    // --------------------------------------------------------------------------
    //
    //  Role Methods
    //
    // --------------------------------------------------------------------------

    public static validateRole(token: string, options: IOpenIdRoleValidationOptions): void {
        let item = new KeycloakAccessToken(token);
        let roles = !_.isArray(options.role) ? [options.role] : options.role;
        for (let role of roles) {
            let isHasRole = KeycloakUtil.hasRole(item, role);
            if (!options.isAny) {
                if (!isHasRole) {
                    throw new OpenIdTokenRoleForbiddenError(role);
                }
            }
            else {
                if (isHasRole) {
                    return;
                }
            }
        }
    }

    public static hasRole(token: string | KeycloakAccessToken, role: string): boolean {
        if (_.isString(token)) {
            token = new KeycloakAccessToken(token);
        }
        let item = KeycloakUtil.parseRole(role);
        switch (item.type) {
            case KeycloakRole.REALM:
                return token.hasRealmRole(item.role);
            case KeycloakRole.CLIENT:
                return token.hasClientRole(item.role);
            default:
                throw new OpenIdTokenRoleInvalidTypeError(item.type);
        }
    }

    public static validateResourceScope(options: OpenIdResourceValidationOptions, resources: KeycloakResources): void {
        let items = !_.isArray(options) ? [options] : options;
        for (let item of items) {
            let { name, scope, isAny } = item;
            let resource = _.find(resources, { rsname: name });
            if (_.isNil(resource)) {
                throw new OpenIdTokenResourceForbiddenError(resource);
            }
            let scopes = !_.isArray(scope) ? [scope] : scope;
            for (let scope of scopes) {
                let isHasScope = resource.scopes.includes(scope);
                if (!isAny) {
                    if (!isHasScope) {
                        throw new OpenIdTokenResourceScopeForbiddenError(item);
                    }
                }
                else {
                    if (isHasScope) {
                        continue;
                    }
                }
            }
        }
    }
}

interface IKeycloakRole {
    type: string;
    role: string;
}
enum KeycloakRole {
    REALM = 'realm',
    CLIENT = 'client',
}
