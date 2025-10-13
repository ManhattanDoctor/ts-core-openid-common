export interface IKeycloakSettings {
    url: string;
    realm: string;
    clientId: string;
    realmPublicKey: string;

    clientSecret?: string;
}

export interface IKeycloakAdministratorSettings {
    url: string;
    realm: string;
    clientId: string;
    clientSecret: string;

    login: string;
    password: string;
}