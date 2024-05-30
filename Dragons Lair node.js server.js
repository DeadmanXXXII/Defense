const express = require('express');
const path = require('path');
const app = express();

app.use(express.static(path.join(__dirname, 'public')));

// Middleware to log IP address of incoming requests
app.use((req, res, next) => {
    const attackerIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    req.attackerIP = attackerIP;
    next();
});

// Endpoint to trigger breach detection
app.get('/breach', (req, res) => {
    const attackerIP = req.attackerIP;
    console.log(`Breach detected from IP: ${attackerIP}`);
    // Call breach detection functions here
    res.send('Breach detected!');
});

// Start server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});