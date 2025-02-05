import { createVerify } from 'crypto';
import { OpenIdTokenExpiredError, OpenIdTokenInvalidSignatureError, OpenIdTokenNotSignedError, OpenIdTokenResourceForbiddenError, OpenIdTokenResourceScopeForbiddenError, OpenIdTokenRoleForbiddenError, OpenIdTokenRoleInvalidTypeError, OpenIdTokenStaleError, OpenIdTokenUndefinedError, OpenIdTokenWrongAudienceError, OpenIdTokenWrongClientIdError, OpenIdTokenWrongIssError, OpenIdTokenWrongTypeError } from '../../error';
import { KeycloakResources } from './KeycloakClient';
import { IOpenIdOfflineValidationOptions, IOpenIdResourceScopePermissionOptions, IOpenIdResourceValidationOptions, IOpenIdRoleValidationOptions } from '../IOpenIdOptions';
import { KeycloakToken } from './KeycloakToken';
import { IOpenIdUser } from '../../lib';
import * as _ from 'lodash';

export class KeycloakUtil {
    // --------------------------------------------------------------------------
    //
    //  Public Methods
    //
    // --------------------------------------------------------------------------

    public static buildResourcePermission(options: IOpenIdResourceScopePermissionOptions): string {
        if (_.isNil(options) || _.isEmpty(options.name)) {
            return null;
        }
        if (_.isEmpty(options.scope)) {
            return options.name;
        }
        let scopes = options.scope;
        if (!_.isArray(scopes)) {
            scopes = [scopes];
        }
        return `${options.name}#${scopes.join(',')}`;
    }

    public static parseRole(role: string): IKeycloakRole {
        let array = role.split(':');
        return array.length > 1 ? { type: array[0], role: array[1] } : { type: KeycloakRole.CLIENT, role: array[0] };
    }

    public static async getUserInfo<T extends IOpenIdUser>(token: string): Promise<T> {
        return new KeycloakToken(token).getUserInfo<T>();
    }

    // --------------------------------------------------------------------------
    //
    //  Validate Token
    //
    // --------------------------------------------------------------------------

    public static async validateToken(token: string, options: IOpenIdOfflineValidationOptions): Promise<void> {
        let item = new KeycloakToken(token);
        if (_.isNil(item)) {
            throw new OpenIdTokenUndefinedError();
        }
        if (_.isNil(item.signed)) {
            throw new OpenIdTokenNotSignedError();
        }
        if (item.isExpired()) {
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
        let item = new KeycloakToken(token);
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

    public static hasRole(token: string | KeycloakToken, role: string): boolean {
        if (_.isString(token)) {
            token = new KeycloakToken(token);
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

    public static async validateResourceScope(resources: KeycloakResources, options: IOpenIdResourceValidationOptions): Promise<void> {
        let resource = _.find(resources, { rsname: options.name });
        if (_.isNil(resource)) {
            throw new OpenIdTokenResourceForbiddenError(resource);
        }
        let scopes = !_.isArray(options.scope) ? [options.scope] : options.scope;
        for (let scope of scopes) {
            let isHasScope = resource.scopes.includes(scope);
            if (!options.isAny) {
                if (!isHasScope) {
                    throw new OpenIdTokenResourceScopeForbiddenError(scope);
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

interface IKeycloakRole {
    type: string;
    role: string;
}
enum KeycloakRole {
    REALM = 'realm',
    CLIENT = 'client',
}
