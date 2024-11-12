require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const PasswordManager = require('./password-manager');

const app = express();
app.use(express.json());
const cors = require('cors');
app.use(cors());


const mongoUri = process.env.MONGO_URI;  // Database URI
const port = process.env.PORT || 3000;   // Port number

let passwordManager;

// Middleware to check if the PasswordManager is initialized
function checkPasswordManager(req, res, next) {
    if (!passwordManager) {
        return res.status(400).json({ error: 'Password Manager not initialized. Please initialize it first.' });
    }
    next();
}

// Connect to MongoDB
mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch((error) => console.log('MongoDB connection error: ', error));

// Initialize password manager
// Initialize password manager
app.post('/api/init', async (req, res) => {
    console.log('Received request to /api/init:', req.body);  // Debugging line
    try {
        const { password } = req.body;
        passwordManager = await PasswordManager.init(password);
        res.status(200).json({ message: 'Password Manager Initialized' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


// Load existing password manager with integrity check
app.post('/api/load', async (req, res) => {
    try {
        const { password, representation, trustedDataCheck } = req.body;
        passwordManager = await PasswordManager.load(password, representation, trustedDataCheck);
        res.status(200).json({ message: 'Password Manager Loaded' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Set a password (requires initialization)
app.post('/api/set', checkPasswordManager, async (req, res) => {
    try {
        const { name, value } = req.body;
        await passwordManager.set(name, value);
        res.status(200).json({ message: 'Password set' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get a password (requires initialization)
app.get('/api/get', checkPasswordManager, async (req, res) => {
    try {
        const { name } = req.query;
        const password = await passwordManager.get(name);
        res.status(200).json({ password });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Remove a password (requires initialization)
app.delete('/api/remove', checkPasswordManager, async (req, res) => {
    try {
        const { name } = req.body;
        const result = await passwordManager.remove(name);
        res.status(200).json({ message: result ? 'Password removed' : 'Password not found' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Dump keychain data (requires initialization)
app.get('/api/dump', checkPasswordManager, async (req, res) => {
    try {
        const [representation, hash] = await passwordManager.dump();
        res.status(200).json({ representation, hash });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Default route to handle invalid paths
app.get('/', (req, res) => {
    res.send('Welcome to the Password Manager API');
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
