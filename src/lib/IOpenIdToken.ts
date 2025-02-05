export interface IOpenIdToken {
    id_token: string;
    scope: string;
    token_type: string;
    expires_in: number;
    access_token: string;
    session_state: string;
    not_before_policy: number;

    refresh_token: string;
    refresh_expires_in: number;

    [key: string]: any;
}