const crypto = require('crypto');
const { connectDB } = require('./db');

class PasswordManager {
    constructor() {
        this.db = null;
        this.key = null;
        this.kvs = {};
    }

    static async init(password) {
        const pm = new PasswordManager();
        pm.db = await connectDB();
        pm.key = await pm.deriveKey(password);
        return pm;
    }

    async deriveKey(password) {
        // PBKDF2 key derivation as before
        const salt = crypto.randomBytes(16);
        return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
    }

    async set(name, value) {
        const domainKey = this.generateDomainKey(name);
        const encryptedValue = await this.encrypt(value);
        await this.db.collection('passwords').updateOne(
            { domain: domainKey },
            { $set: { value: encryptedValue } },
            { upsert: true }
        );
    }

    async get(name) {
        const domainKey = this.generateDomainKey(name);
        const record = await this.db.collection('passwords').findOne({ domain: domainKey });
        return record ? this.decrypt(record.value) : null;
    }

    async remove(name) {
        const domainKey = this.generateDomainKey(name);
        const result = await this.db.collection('passwords').deleteOne({ domain: domainKey });
        return result.deletedCount > 0;
    }

    generateDomainKey(name) {
        // Generate HMAC key for domain
        return crypto.createHmac('sha256', this.key).update(name).digest('base64');
    }

    async encrypt(value) {
        // Use AES-GCM for encryption as per requirements
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
        let encrypted = cipher.update(value, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag().toString('hex');
        return { iv: iv.toString('hex'), encrypted, authTag };
    }

    async decrypt(record) {
        const { iv, encrypted, authTag } = record;
        const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, Buffer.from(iv, 'hex'));
        decipher.setAuthTag(Buffer.from(authTag, 'hex'));
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }

    async dump() {
        // Fetch all records from the database and generate JSON representation
        const records = await this.db.collection('passwords').find().toArray();
        const hash = crypto.createHash('sha256').update(JSON.stringify(records)).digest('hex');
        return [JSON.stringify(records), hash];
    }
}

module.exports = PasswordManager;
