export type OpenIdResources = Map<string, IOpenIdResource>;

export interface IOpenIdResource {
    id: string;
    name: string;
    scopes: Array<string>;
}