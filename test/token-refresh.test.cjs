const assert = require('node:assert/strict');
const { test } = require('node:test');
const { OpenIdTokenRefreshableTransport } = require('../dist/test-build/lib/OpenIdTokenRefreshableTransport');
const { OpenIdTokenUndefinedError } = require('../dist/test-build/error');

function deferred() {
    let resolve, reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
}
function manager(access = 'old') {
    return {
        value: { access, refresh: 'refresh-' + access },
        get isValid() { return this.value !== null; },
        get isExpired() { return this.value?.access === 'old'; },
        get access() { return { value: this.value?.access }; },
    };
}
function fixture() {
    const transport = Object.create(OpenIdTokenRefreshableTransport.prototype);
    transport.token = manager();
    const pending = [];
    transport.getRefreshable = () => {
        const item = deferred();
        pending.push(item);
        return item.promise;
    };
    return { transport, pending };
}
const updated = { access: 'new', refresh: 'rotated' };

test('refresh, forced refresh and getToken share one request and rotated tokens', async () => {
    const { transport, pending } = fixture();
    const requests = [transport.refresh(), transport.refresh(true), transport.getToken(), transport.checkRefreshable('/api')];
    await Promise.resolve();
    assert.equal(pending.length, 1);
    pending[0].resolve(updated);
    assert.deepEqual(await Promise.all(requests), [true, true, updated, undefined]);
    assert.equal(transport.authorization, 'Bearer new');
});

test('all waiters receive failure and next attempt can retry', async () => {
    const { transport, pending } = fixture();
    const error = new Error('refresh failed');
    const requests = [transport.refresh(), transport.getToken()];
    const settled = Promise.allSettled(requests);
    await Promise.resolve();
    pending[0].reject(error);
    for (const result of await settled) assert.equal(result.reason, error);
    const retry = transport.refresh();
    await Promise.resolve();
    assert.equal(pending.length, 2);
    pending[1].resolve(updated);
    assert.equal(await retry, true);
});

for (const change of ['logout', 'value', 'manager']) {
    test(`late refresh cannot overwrite ${change}`, async () => {
        const { transport, pending } = fixture();
        const oldManager = transport.token;
        const refreshing = transport.refresh();
        const rejected = assert.rejects(refreshing, OpenIdTokenUndefinedError);
        await Promise.resolve();
        if (change === 'logout') transport.token.value = null;
        if (change === 'value') transport.token.value = { access: 'other', refresh: 'other-refresh' };
        if (change === 'manager') transport.token = manager('other');
        const expected = transport.token.value;
        pending[0].resolve(updated);
        await rejected;
        assert.equal(transport.token.value, expected);
        if (change === 'manager') assert.equal(oldManager.value.access, 'old');
    });
}

test('new session waits for old refresh failure and can retry afterwards', async () => {
    const { transport, pending } = fixture();
    const old = transport.refresh();
    const rejected = assert.rejects(old, OpenIdTokenUndefinedError);
    transport.token = manager();
    const current = transport.refresh();
    const currentRejected = assert.rejects(current, OpenIdTokenUndefinedError);
    assert.equal(pending.length, 1);
    pending[0].resolve(updated);
    await Promise.all([rejected, currentRejected]);
    const retry = transport.refresh();
    assert.equal(pending.length, 2);
    pending[1].resolve(updated);
    assert.equal(await retry, true);
});

test('valid tokens skip refresh, but wait for an existing forced refresh', async () => {
    const { transport, pending } = fixture();
    transport.token = manager('valid');
    assert.equal(await transport.refresh(), true);
    assert.equal(pending.length, 0);
    const forced = transport.refresh(true);
    const read = transport.getToken();
    await Promise.resolve();
    assert.equal(pending.length, 1);
    pending[0].resolve(updated);
    await forced;
    assert.equal(await read, updated);
});

test('missing session does not start refresh', async () => {
    const { transport, pending } = fixture();
    transport.token.value = null;
    assert.equal(await transport.refresh(), false);
    await assert.rejects(transport.getToken(), OpenIdTokenUndefinedError);
    assert.equal(pending.length, 0);
});

test('synchronous refresh failure releases the pending operation', async () => {
    const { transport } = fixture();
    transport.getRefreshable = () => { throw new Error('synchronous'); };
    await assert.rejects(transport.refresh(), /synchronous/);
    transport.getRefreshable = async () => updated;
    assert.equal(await transport.refresh(), true);
});
