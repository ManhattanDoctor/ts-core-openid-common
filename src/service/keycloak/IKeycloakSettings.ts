import { IOpenIdClientCredentials } from "../../lib";

export interface IKeycloakSettings extends IOpenIdClientCredentials {
    url: string;
    realm: string;
    realmPublicKey?: string;
}

export interface IKeycloakAdministratorSettings extends IKeycloakSettings {
    scope: string;
    login: string;
    password: string;
}