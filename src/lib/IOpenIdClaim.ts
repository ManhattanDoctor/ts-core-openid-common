export interface IOpenIdClaim {
    token: Record<string, Array<string>> | string;
    format?: string;
}
export interface IOpenIdTokenClaim {
    token: string;
    format: string;
}