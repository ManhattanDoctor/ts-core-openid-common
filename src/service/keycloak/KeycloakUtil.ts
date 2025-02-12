import { createVerify } from 'crypto';
import { OpenIdTokenExpiredError, OpenIdTokenInvalidSignatureError, OpenIdTokenNotSignedError, OpenIdTokenResourceForbiddenError, OpenIdTokenResourceScopeForbiddenError, OpenIdTokenRoleForbiddenError, OpenIdTokenRoleInvalidTypeError, OpenIdTokenStaleError, OpenIdTokenUndefinedError, OpenIdTokenWrongAudienceError, OpenIdTokenWrongClientIdError, OpenIdTokenWrongIssError, OpenIdTokenWrongTypeError } from '../../error';
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

    public static buildResourcePermission(options: OpenIdResourceValidationOptions): string {
        if (_.isNil(options)) {
            return null;
        }
        let items = !_.isArray(options) ? [options] : options;
        let permissions = new Array();
        for (let item of items) {
            if (_.isEmpty(item.name) || _.isEmpty(item.scope)) {
                continue;
            }
            let scopes = !_.isArray(item.scope) ? [item.scope] : item.scope;
            permissions.push(`${item.name}#${scopes.join(',')}`);
        }
        return permissions.join(',');
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
        if (!_.isNil(options.publicKey)) {
            let verify = createVerify('RSA-SHA256').update(item.signed);
            if (!verify.verify(options.publicKey, item.signature.toString('base64'), 'base64')) {
                throw new OpenIdTokenInvalidSignatureError();
            }
        }
    }

    // --------------------------------------------------------------------------
    //
    //  Role Methods
    //
    // --------------------------------------------------------------------------

    public static async validateRole(token: string, options: IOpenIdRoleValidationOptions): Promise<void> {
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

    public static async validateResourceScope(resources: KeycloakResources, options: OpenIdResourceValidationOptions): Promise<void> {
        let items = !_.isArray(options) ? [options] : options;
        for (let item of items) {
            let resource = _.find(resources, { rsname: item.name });
            if (_.isNil(resource)) {
                throw new OpenIdTokenResourceForbiddenError(resource);
            }
            let scopes = !_.isArray(item.scope) ? [item.scope] : item.scope;
            for (let scope of scopes) {
                let isHasScope = resource.scopes.includes(scope);
                if (!item.isAny) {
                    if (!isHasScope) {
                        throw new OpenIdTokenResourceScopeForbiddenError({ name: item.name, scope: scope });
                    }
                }
                else {
                    if (isHasScope) {
                        return;
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
