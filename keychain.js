const crypto = require('crypto');

class Keychain {
  constructor(password, kvs = {}) {
    this.passwordHash = crypto.createHash('sha256').update(password).digest('hex');
    this.kvs = kvs;
  }

  static async init(password) {
    return new Keychain(password);
  }

  static async load(password, representation, trustedDataCheck) {
    const parsedData = JSON.parse(representation);
    const inputPasswordHash = crypto.createHash('sha256').update(password).digest('hex');
    
    if (inputPasswordHash !== parsedData.passwordHash) {
      throw new Error('Invalid password');
    }

    if (trustedDataCheck !== undefined) {
      const hash = crypto.createHash('sha256').update(representation).digest('hex');
      if (hash !== trustedDataCheck) {
        throw new Error('Data integrity check failed');
      }
    }

    return new Keychain(password, parsedData.kvs);
  }

  async dump() {
    const serializedData = JSON.stringify({
      passwordHash: this.passwordHash,
      kvs: this.kvs
    });

    const hash = crypto.createHash('sha256').update(serializedData).digest('hex');
    return [serializedData, hash];
  }

  async set(name, value) {
    this.kvs[name] = value;
  }

  async get(name) {
    return this.kvs.hasOwnProperty(name) ? this.kvs[name] : null;
  }

  async remove(name) {
    if (this.kvs.hasOwnProperty(name)) {
      delete this.kvs[name];
      return true;
    }
    return false;
  }
}
