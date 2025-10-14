
export interface IKeycloakSettings {
    url: string;
    realm: string;
    clientId: string;
    clientSecret: string;
    realmPublicKey: string;
}

export interface IKeycloakAdministratorSettings extends IKeycloakSettings {
    scope: string;
    login: string;
    password: string;
}