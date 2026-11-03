const assert = require('node:assert/strict');
const { test } = require('node:test');
const { generateKeyPairSync, sign } = require('node:crypto');
const { KeycloakUtil } = require('../dist/test-build/service/keycloak/KeycloakUtil');
const { OpenIdTokenNotActiveError, OpenIdTokenInvalidError, OpenIdTokenStaleError,
    OpenIdTokenExpiredError, OpenIdTokenSignatureInvalidError } = require('../dist/test-build/error');

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const now = 2_000_000_000;
const claims = { sub: 'test-user', iss: 'https://issuer.example/realms/test', aud: 'api', typ: 'Bearer', iat: now - 30, exp: now + 600 };
const options = { publicKey: publicKey.export({ type: 'spki', format: 'pem' }), iss: claims.iss, clientId: 'api', isVerifyAudience: true, type: 'Bearer' };
function token(payload, key = privateKey) {
    const content = [{ alg: 'RS256', typ: 'JWT' }, payload].map(value => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
    return `${content}.${sign('RSA-SHA256', Buffer.from(content), key).toString('base64url')}`;
}
for (const [name, additions] of [
    ['without nbf', {}], ['with past nbf', { nbf: now - 1 }],
    ['at the exact nbf boundary', { nbf: now }], ['with past fractional nbf', { nbf: now - 0.5 }],
]) {
    test(`accepts a valid signed token ${name}`, async (t) => {
        t.mock.method(Date, 'now', () => now * 1000);
        await KeycloakUtil.validateToken(token({ ...claims, ...additions }), options);
    });
}
for (const nbf of [now + 1, now + 0.5]) {
    test(`rejects a signed token before nbf=${nbf}`, async (t) => {
        t.mock.method(Date, 'now', () => now * 1000);
        await assert.rejects(KeycloakUtil.validateToken(token({ ...claims, nbf }), options), OpenIdTokenNotActiveError);
    });
}
for (const nbf of [String(now), null, false, {}, [now]]) {
    test(`rejects malformed nbf ${JSON.stringify(nbf)}`, async (t) => {
        t.mock.method(Date, 'now', () => now * 1000);
        await assert.rejects(KeycloakUtil.validateToken(token({ ...claims, nbf }), options), OpenIdTokenInvalidError);
    });
}
test('keeps the existing iat-based notBefore policy independent of nbf', async (t) => {
    t.mock.method(Date, 'now', () => now * 1000);
    await assert.rejects(KeycloakUtil.validateToken(token({ ...claims, nbf: now - 10 }), { ...options, notBefore: now - 20 }), OpenIdTokenStaleError);
});
test('still rejects expired tokens with valid nbf', async (t) => {
    t.mock.method(Date, 'now', () => now * 1000);
    await assert.rejects(KeycloakUtil.validateToken(token({ ...claims, nbf: now - 100, exp: now - 1 }), options), OpenIdTokenExpiredError);
});
test('still verifies the signature after nbf passes', async (t) => {
    t.mock.method(Date, 'now', () => now * 1000);
    const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
    await assert.rejects(KeycloakUtil.validateToken(token({ ...claims, nbf: now }, other.privateKey), options), OpenIdTokenSignatureInvalidError);
});
