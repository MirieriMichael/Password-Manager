// db.js
const { MongoClient } = require('mongodb');
const uri = process.env.MONGO_URI || 'mongodb://localhost:27017';
const client = new MongoClient(uri);
let db;

async function connectDB() {
    if (!db) {
        await client.connect();
        db = client.db('password_manager');
        console.log('Database connected');
    }
    return db;
}

module.exports = { connectDB };
