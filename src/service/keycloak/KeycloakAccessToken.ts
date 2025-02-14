import { ObjectUtil } from '@ts-core/common';
import { IOpenIdUser } from '../../lib';
import { IKeycloakContent, IKeycloakTokenHeader, KeycloakToken } from './KeycloakToken';
import * as _ from 'lodash';

export class KeycloakAccessToken<H extends IKeycloakTokenHeader = IKeycloakTokenHeader, C extends IKeycloakContent = IKeycloakContent> extends KeycloakToken<H, C> {

    // --------------------------------------------------------------------------
    //
    //  Protected Methods
    //
    // --------------------------------------------------------------------------

    protected hasRole(path: string, name: string): boolean {
        let roles = _.get(this.content, path);
        return _.isArray(roles) ? roles.includes(name) : false;
    }

    // --------------------------------------------------------------------------
    //
    //  Public Methods
    //
    // --------------------------------------------------------------------------

    public getUserInfo<T extends IOpenIdUser>(): T {
        return ObjectUtil.copyProperties(this.content, {});
    }

    public hasClientRole(name: string): boolean {
        return this.hasRole(`resource_access.${this.content.azp}.roles`, name);
    }

    public hasRealmRole(name: string): boolean {
        return this.hasRole('realm_access.roles', name);
    }
}      
