const assert = require('node:assert/strict');
const { test } = require('node:test');
const { OpenIdToken } = require('../dist/test-build/lib/IOpenIdToken');

test('decodes URL-safe JWT with a Buffer that supports only standard base64', t => {
    const header = { alg: 'RS256', typ: 'JWT' };
    const content = { sub: 'user', name: 'Имя 😀', exp: 4_000_000_000 };
    const signature = Buffer.from([251, 255, 254]);
    const parts = [Buffer.from(JSON.stringify(header)), Buffer.from(JSON.stringify(content)), signature];
    const value = parts.map(item => item.toString('base64url')).join('.');
    const from = Buffer.from;
    t.mock.method(Buffer, 'from', (value, encoding) => {
        assert.notEqual(encoding, 'base64url');
        if (encoding === 'base64') assert.doesNotMatch(value, /[-_]/);
        return from(value, encoding);
    });
    const token = new OpenIdToken(value);
    assert.deepEqual(token.header, header);
    assert.deepEqual(token.content, content);
    assert.deepEqual(token.signature, signature);
    assert.equal(token.signed, value.substring(0, value.lastIndexOf('.')));
    assert.equal(token.value, value);
});
