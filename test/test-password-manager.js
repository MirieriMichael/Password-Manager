const PasswordManager = require('../password-manager');
const assert = require('assert');

describe('PasswordManager', function () {
    it('should initialize a new password manager', async function () {
        const pm = await PasswordManager.init('myMasterPassword');
        assert.ok(pm);
    });

    it('should set and retrieve a password', async function () {
        const pm = await PasswordManager.init('myMasterPassword');
        await pm.set('example.com', 'myPassword123');
        const password = await pm.get('example.com');
        assert.strictEqual(password, 'myPassword123');
    });

    it('should remove a password', async function () {
        const pm = await PasswordManager.init('myMasterPassword');
        await pm.set('example.com', 'myPassword123');
        const removed = await pm.remove('example.com');
        assert.strictEqual(removed, true);
        const password = await pm.get('example.com');
        assert.strictEqual(password, null);
    });

    it('should dump and load the password manager state', async function () {
        const pm1 = await PasswordManager.init('myMasterPassword');
        await pm1.set('example.com', 'myPassword123');
        const [dumpedData, hash] = await pm1.dump();

        const pm2 = await PasswordManager.load('myMasterPassword', dumpedData, hash);
        const password = await pm2.get('example.com');
        assert.strictEqual(password, 'myPassword123');
    });

    it('should throw an error for an incorrect password during load', async function () {
        const pm = await PasswordManager.init('myMasterPassword');
        await pm.set('example.com', 'myPassword123');
        const [dumpedData] = await pm.dump();

        await assert.rejects(async () => {
            await PasswordManager.load('wrongPassword', dumpedData);
        }, /Invalid password/);
    });

    it('should throw an error if data integrity check fails', async function () {
        const pm = await PasswordManager.init('myMasterPassword');
        await pm.set('example.com', 'myPassword123');
        const [dumpedData, hash] = await pm.dump();

        const tamperedData = JSON.stringify({
            passwordHash: pm.passwordHash,
            kvs: { 'example.com': 'tamperedPassword' }
        });

        await assert.rejects(async () => {
            await PasswordManager.load('myMasterPassword', tamperedData, hash);
        }, /Data integrity check failed/);
    });
});
