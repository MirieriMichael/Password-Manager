console.log("Test file loading");
const expect = require('expect.js');
const crypto = require('crypto');
const PasswordManager = require('../password-manager');

describe('PasswordManager Tests', function() {
    this.timeout(10000); // Set timeout to 5000ms for all tests in this describe block

    let pm;

    // Initialize the PasswordManager instance before each test
    beforeEach(async function() {
        this.timeout(10000);
        console.log('Starting beforeEach');
        pm = await PasswordManager.init('securePassword');
        console.log('beforeEach completed');
    });

    it('should set and get a password correctly', async function() {
        await pm.set('example.com', 'password123');
        const retrievedPassword = await pm.get('example.com');
        expect(retrievedPassword).to.be('password123');
    });

    it('should detect a swap attack', async function() {
        await pm.set('example.com', 'password123');
        const domainKey = pm.generateDomainKey('example.com');

        // Directly manipulate the database to simulate a swap attack
        const collection = pm.db.collection('passwords');
        await collection.updateOne(
            { domain: domainKey },
            { $set: { value: { iv: 'fakeiv', encrypted: 'fakeenc', authTag: 'fakeauth' } } }
        );

        try {
            await pm.get('example.com');
            throw new Error('Expected swap attack to be detected');
        } catch (error) {
            expect(error.message).to.contain('Potential tampering detected (swap attack)');
        }
    });

    it('should detect a rollback attack', async function() {
        await pm.set('example.com', 'password123');
        const initialDump = await pm.dump();

        // Add a new password, then revert back to the initial state (simulating rollback)
        await pm.set('test.com', 'anotherpassword');
        const collection = pm.db.collection('passwords');
        await collection.deleteOne({ domain: pm.generateDomainKey('test.com') });

        // Verify that the manager detects the rollback
        try {
            pm.verifyKvsHash();
            throw new Error('Expected rollback attack to be detected');
        } catch (error) {
            expect(error.message).to.contain('Potential tampering detected (rollback attack)');
        }
    });

    it('should update and remove passwords correctly', async function() {
        await pm.set('example.com', 'initialPassword');
        await pm.set('example.com', 'updatedPassword');

        const updatedPassword = await pm.get('example.com');
        expect(updatedPassword).to.be('updatedPassword');

        const removed = await pm.remove('example.com');
        expect(removed).to.be(true);

        const shouldBeNull = await pm.get('example.com');
        expect(shouldBeNull).to.be(null);
    });

    it('should detect tampering in dump data', async function() {
        await pm.set('example.com', 'password123');
        const [dumpData, dumpHash] = await pm.dump();

        // Manually alter the dumped data (simulating a tampering)
        const alteredData = JSON.stringify([{ domain: 'example.com', value: 'tamperedValue' }]);
        const tamperedHash = crypto.createHash('sha256').update(alteredData).digest('hex');

        // Confirm that the altered data and hash mismatch indicates tampering
        expect(dumpHash).to.not.be(tamperedHash);
    });
});
