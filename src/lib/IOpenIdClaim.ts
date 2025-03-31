export type IOpenIdClaim = Record<string, Array<string>> | string;

export interface IOpenIdTokenClaim {
    token: string;
    format: string;
}