const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createServer } = require('node:http');
const { generateKeyPairSync, sign } = require('node:crypto');
const { KeycloakService } = require('../dist/test-build/service/keycloak/KeycloakService');
const { OpenIdJwksUnavailableError, OpenIdTokenSignatureInvalidError, OpenIdTokenWrongAudienceError, OpenIdTokenNotActiveError } = require('../dist/test-build/error');
const a = generateKeyPairSync('rsa', { modulusLength: 2048 });
const b = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = (pair, kid) => ({ ...pair.publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' });
function token(pair, kid, issuer, payload = {}, header = {}) {
    const now = Math.floor(Date.now() / 1000);
    const body = [{ alg: 'RS256', kid, typ: 'JWT', ...header }, { sub: 'user', iss: issuer, aud: 'api', typ: 'Bearer', iat: now, exp: now + 3600, ...payload }].map(v => Buffer.from(JSON.stringify(v)).toString('base64url')).join('.');
    return body + '.' + sign('RSA-SHA256', Buffer.from(body), pair.privateKey).toString('base64url');
}
async function fixture(t) {
    let clock = Date.now();
    t.mock.method(Date, 'now', () => clock);
    const state = { keys: [jwk(a, 'a')], status: 200, calls: [], body: undefined };
    const server = createServer((req, res) => {
        state.calls.push({ path: req.url, authorization: req.headers.authorization });
        res.writeHead(state.status, { 'Content-Type': 'application/json', ...(state.status === 302 ? { Location: '/redirect' } : {}) });
        res.end(state.body ?? JSON.stringify({ keys: state.keys }));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const url = `http://127.0.0.1:${server.address().port}`;
    const settings = { url, realm: 'test', clientId: 'api' };
    const issuer = url + '/realms/test';
    const options = { iss: issuer, type: 'Bearer', isVerifyAudience: true };
    return { state, settings, issuer, options, service: new KeycloakService(settings), advance: n => { clock += n; } };
}
test('shares a single fetch across concurrent validations and caches public keys only', async t => {
    const f = await fixture(t);
    const value = token(a, 'a', f.issuer);
    await Promise.all(Array.from({ length: 20 }, () => f.service.validateToken(value, f.options)));
    await f.service.validateToken(value, f.options);
    assert.deepEqual(f.state.calls, [{ path: '/realms/test/protocol/openid-connect/certs', authorization: undefined }]);
});
test('supports new and old signing keys during rotation', async t => {
    const f = await fixture(t);
    await f.service.validateToken(token(a, 'a', f.issuer), f.options);
    f.state.keys.push(jwk(b, 'b'));
    f.advance(31_000);
    await f.service.validateToken(token(b, 'b', f.issuer), f.options);
    await f.service.validateToken(token(a, 'a', f.issuer), f.options);
    assert.equal(f.state.calls.length, 2);
});
test('bounds unknown-kid refreshes instead of fetching for each invalid token', async t => {
    const f = await fixture(t);
    await f.service.validateToken(token(a, 'a', f.issuer), f.options);
    for (let i = 0; i < 10; i++) await assert.rejects(f.service.validateToken(token(a, `unknown-${i}`, f.issuer), f.options), OpenIdTokenSignatureInvalidError);
    assert.equal(f.state.calls.length, 1);
    f.advance(31_000);
    await assert.rejects(f.service.validateToken(token(a, 'unknown', f.issuer), f.options), OpenIdTokenSignatureInvalidError);
    assert.equal(f.state.calls.length, 2);
});
test('refreshes expired cache and stops accepting a removed key', async t => {
    const f = await fixture(t);
    await f.service.validateToken(token(a, 'a', f.issuer), f.options);
    f.state.keys = [jwk(b, 'b')];
    f.advance(301_000);
    await assert.rejects(f.service.validateToken(token(a, 'a', f.issuer), f.options), OpenIdTokenSignatureInvalidError);
    await f.service.validateToken(token(b, 'b', f.issuer), f.options);
});
test('fails closed on a JWKS outage after cache expiry, with request backoff', async t => {
    const f = await fixture(t);
    await f.service.validateToken(token(a, 'a', f.issuer), f.options);
    f.state.status = 503;
    await f.service.validateToken(token(a, 'a', f.issuer), f.options);
    f.advance(301_000);
    for (let i = 0; i < 2; i++) await assert.rejects(f.service.validateToken(token(a, 'a', f.issuer), f.options), OpenIdJwksUnavailableError);
    assert.equal(f.state.calls.length, 2);
});
test('keeps explicit public keys compatible without making JWKS requests', async t => {
    const f = await fixture(t);
    f.state.status = 503;
    const pem = a.publicKey.export({ type: 'spki', format: 'pem' });
    await f.service.validateToken(token(a, undefined, f.issuer), { ...f.options, publicKey: pem });
    await new KeycloakService({ ...f.settings, realmPublicKey: pem }).validateToken(token(a, undefined, f.issuer), f.options);
    assert.equal(f.state.calls.length, 0);
});
test('does not trust token URLs, arbitrary audiences, future nbf or incorrect signatures', async t => {
    const f = await fixture(t);
    await f.service.validateToken(token(a, 'a', f.issuer, {}, { jku: 'http://127.0.0.1:1/attacker' }), f.options);
    await assert.rejects(f.service.validateToken(token(a, 'a', f.issuer, { aud: 'other' }), f.options), OpenIdTokenWrongAudienceError);
    await assert.rejects(f.service.validateToken(token(a, 'a', f.issuer, { nbf: Date.now() / 1000 + 60 }), f.options), OpenIdTokenNotActiveError);
    await assert.rejects(f.service.validateToken(token(b, 'a', f.issuer), f.options), OpenIdTokenSignatureInvalidError);
});
for (const [name, change] of [
    ['duplicate kid', f => { f.state.keys.push(jwk(b, 'a')); }],
    ['encryption-only keys', f => { f.state.keys[0].use = 'enc'; }],
    ['malformed JSON', f => { f.state.body = '{broken'; }],
    ['redirects', f => { f.state.status = 302; }],
]) test(`rejects ${name}`, async t => {
    const f = await fixture(t); change(f);
    await assert.rejects(f.service.validateToken(token(a, 'a', f.issuer), f.options), OpenIdJwksUnavailableError);
});
test('rejects missing kid without fetching keys', async t => {
    const f = await fixture(t);
    await assert.rejects(f.service.validateToken(token(a, undefined, f.issuer), f.options), OpenIdTokenSignatureInvalidError);
    assert.equal(f.state.calls.length, 0);
});
