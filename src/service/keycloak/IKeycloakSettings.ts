export interface IKeycloakSettings {
    url: string;
    
    realm: string;
    realmPublicKey: string;

    clientId: string;
    clientSecret: string;
}

export interface IKeycloakAdministratorSettings {
    url: string;
    realm: string;
    userName: string;
    userPassword: string;
}