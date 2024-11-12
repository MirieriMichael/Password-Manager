const crypto = require('crypto');
const { connectDB } = require('./db');

class PasswordManager {
    constructor() {
        this.db = null;
        this.key = null;
        this.kvs = {};
        this.kvsHash = null; // Store the hash of the kvs for rollback protection
    }

    static async init(password) {
        console.log('Initializing PasswordManager...');
        const pm = new PasswordManager();
        pm.db = await connectDB();
        
        pm.key = await pm.deriveKey(password);
        console.log('Database connected');
        
        // Load and verify data on initialization to detect rollback attacks
        await pm.loadKvs();
        pm.verifyKvsHash();
        console.log('Key derived');
        
        return pm;
    }

    async deriveKey(password) {
        // PBKDF2 key derivation
        const salt = crypto.randomBytes(16);
        return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
    }

    generateDomainKey(name) {
        // Generate HMAC key for domain to protect against swap attacks
        return crypto.createHmac('sha256', this.key).update(name).digest('base64');
    }

    async set(name, value) {
        const domainKey = this.generateDomainKey(name);
        const encryptedValue = await this.encrypt(value);
        
        // Generate HMAC for integrity (swap attack protection)
        const entrySignature = this.generateHmacSignature(domainKey, encryptedValue);

        // Save to database with signature
        await this.db.collection('passwords').updateOne(
            { domain: domainKey },
            { $set: { value: encryptedValue, signature: entrySignature } },
            { upsert: true }
        );
        
        // Update the KVS and its hash
        this.kvs[domainKey] = encryptedValue;
        this.updateKvsHash();
    }

    async get(name) {
        const domainKey = this.generateDomainKey(name);
        const record = await this.db.collection('passwords').findOne({ domain: domainKey });
        
        if (!record) return null;
        
        // Verify the entry's HMAC to detect swap attacks
        const entrySignature = this.generateHmacSignature(domainKey, record.value);
        if (entrySignature !== record.signature) {
            throw new Error('Potential tampering detected (swap attack)');
        }

        return this.decrypt(record.value);
    }

    async remove(name) {
        const domainKey = this.generateDomainKey(name);
        const result = await this.db.collection('passwords').deleteOne({ domain: domainKey });
        
        if (result.deletedCount > 0) {
            delete this.kvs[domainKey];
            this.updateKvsHash();
        }
        
        return result.deletedCount > 0;
    }

    generateHmacSignature(domainKey, value) {
        // Create an HMAC signature for the entry
        return crypto.createHmac('sha256', this.key).update(domainKey + JSON.stringify(value)).digest('hex');
    }

    async encrypt(value) {
        // Use AES-GCM for encryption
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

    updateKvsHash() {
        // Update the SHA-256 hash of the current KVS to protect against rollback attacks
        this.kvsHash = crypto.createHash('sha256').update(JSON.stringify(this.kvs)).digest('hex');
    }

    verifyKvsHash() {
        // Verify the current KVS hash against the stored hash to detect rollback attacks
        const currentHash = crypto.createHash('sha256').update(JSON.stringify(this.kvs)).digest('hex');
        if (this.kvsHash && this.kvsHash !== currentHash) {
            throw new Error('Potential tampering detected (rollback attack)');
        }
    }

    async loadKvs() {
        // Load all records from the database into kvs
        const records = await this.db.collection('passwords').find().toArray();
        records.forEach(record => {
            this.kvs[record.domain] = record.value;
        });
        
        // Set the initial hash of the kvs
        this.updateKvsHash();
    }

    async dump() {
        // Generate JSON representation with a SHA-256 hash of the entire kvs content
        const records = await this.db.collection('passwords').find().toArray();
        const hash = crypto.createHash('sha256').update(JSON.stringify(records)).digest('hex');
        return [JSON.stringify(records), hash];
    }
}

module.exports = PasswordManager;
