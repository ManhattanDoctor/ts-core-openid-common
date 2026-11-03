import axios from 'axios';
import * as jwkToPemModule from 'jwk-to-pem';
import { OpenIdJwksUnavailableError, OpenIdTokenSignatureAlgorithmUnknownError, OpenIdTokenSignatureInvalidError } from '../../error';
import { IKeycloakSettings } from './IKeycloakSettings';
import { KeycloakToken } from './KeycloakToken';

interface IKeycloakJwk {
    kid: string;
    kty: string;
    alg?: string;
    use?: string;
    key_ops?: Array<string>;
    n: string;
    e: string;
}

/** Public keys only. No user tokens or sessions are retained. */
export class KeycloakJwks {
    private static CACHE_TTL = 5 * 60_000;
    private static REFRESH_COOLDOWN = 30_000;
    private keys = new Map<string, string>();
    private expiresAt = 0;
    private nextFetchAt = 0;
    private pending: Promise<void>;
    public readonly url: string;

    constructor(settings: IKeycloakSettings) {
        this.url = KeycloakJwks.getUrl(settings);
    }

    public static getUrl(settings: IKeycloakSettings): string {
        return `${settings.url.replace(/\/+$/, '')}/realms/${encodeURIComponent(settings.realm)}/protocol/openid-connect/certs`;
    }

    public async getPublicKey(value: string): Promise<string> {
        const token = new KeycloakToken(value);
        if (token.header.alg !== 'RS256') {
            throw new OpenIdTokenSignatureAlgorithmUnknownError(token.header.alg);
        }
        const kid = (token.header as { kid?: unknown }).kid;
        if (typeof kid !== 'string' || !kid.length || kid.length > 256) {
            throw new OpenIdTokenSignatureInvalidError();
        }
        if (Date.now() < this.expiresAt && this.keys.has(kid)) {
            return this.keys.get(kid);
        }
        await this.refresh();
        if (Date.now() >= this.expiresAt) {
            throw new OpenIdJwksUnavailableError();
        }
        const key = this.keys.get(kid);
        if (!key) {
            throw new OpenIdTokenSignatureInvalidError();
        }
        return key;
    }

    private async refresh(): Promise<void> {
        if (this.pending) return this.pending;
        // Unknown kid values must not cause an unbounded stream of requests.
        if (Date.now() < this.nextFetchAt) {
            if (Date.now() >= this.expiresAt) throw new OpenIdJwksUnavailableError();
            return;
        }
        this.nextFetchAt = Date.now() + KeycloakJwks.REFRESH_COOLDOWN;
        this.pending = this.fetchKeys();
        try {
            await this.pending;
        } finally {
            this.pending = undefined;
        }
    }

    private async fetchKeys(): Promise<void> {
        try {
            const response = await axios.get(this.url, { timeout: 10_000, maxRedirects: 0, maxContentLength: 1024 * 1024 });
            const entries: Array<IKeycloakJwk> = response.data?.keys;
            if (!Array.isArray(entries) || entries.length > 100) throw new Error('Invalid JWKS');
            const keys = new Map<string, string>();
            for (const item of entries) {
                if (!item || item.kty !== 'RSA' || (item.alg && item.alg !== 'RS256') ||
                    (item.use && item.use !== 'sig') || (item.key_ops && (!Array.isArray(item.key_ops) || !item.key_ops.includes('verify')))) continue;
                if (typeof item.kid !== 'string' || !item.kid.length || item.kid.length > 256 ||
                    typeof item.n !== 'string' || typeof item.e !== 'string' || keys.has(item.kid)) throw new Error('Invalid signing key');
                const convert = (jwkToPemModule as any).default || jwkToPemModule;
                keys.set(item.kid, convert({ kty: 'RSA', n: item.n, e: item.e }));
            }
            if (!keys.size) throw new Error('No signing keys');
            this.keys = keys;
            this.expiresAt = Date.now() + KeycloakJwks.CACHE_TTL;
        } catch {
            throw new OpenIdJwksUnavailableError();
        }
    }
}
