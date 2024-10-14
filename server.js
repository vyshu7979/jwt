const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
app.use(express.json());

// Static array to simulate a user database
const users = [
    { id: 1, username: 'user1', password: bcrypt.hashSync('password1', 10), role: 'user' },
    { id: 2, username: 'admin', password: bcrypt.hashSync('adminpass', 10), role: 'admin' }
];

// Middleware for token verification
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401); // Unauthorized

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Forbidden
        req.user = user;
        next();
    });
};

// Login route
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).send('Invalid credentials');
    }

    const accessToken = jwt.sign({ id: user.id, role: user.role }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
    res.json({ accessToken });
});

// Get user profile route
app.get('/api/user/profile', authenticateToken, (req, res) => {
    const user = users.find(u => u.id === req.user.id);
    res.json({ id: user.id, username: user.username, role: user.role });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running at ${PORT}`);
  });