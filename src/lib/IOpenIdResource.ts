export type OpenIdResources = Map<string, IOpenIdResource>;

export interface IOpenIdResource<T = Record<string, any>> {
    id: string;
    name: string;
    scopes: Array<string>;

    type?: string;
    attributes?: T;

    [key: string]: any;
}