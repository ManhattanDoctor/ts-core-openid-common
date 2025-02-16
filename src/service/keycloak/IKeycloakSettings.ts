export interface IKeycloakSettings {
    url: string;
    realm: string;
    clientId: string;
    clientSecret: string;
    realmPublicKey: string;
}

export interface IKeycloakAdministratorSettings {
    url: string;
    realm: string;
    login: string;
    password: string;
    clientId: string;
    clientSecret: string;
}