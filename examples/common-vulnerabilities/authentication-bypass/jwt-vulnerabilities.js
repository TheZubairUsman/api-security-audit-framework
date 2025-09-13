#!/usr/bin/env node
/**
 * JWT Security Vulnerabilities and Secure Implementation Examples
 * 
 * This file demonstrates common JWT vulnerabilities and their secure counterparts.
 * Use the vulnerable examples for security testing and the secure examples in production.
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// ============================================================================
// CONFIGURATION AND KEYS
// ============================================================================

// Weak secret for vulnerable examples
const WEAK_SECRET = 'secret';

// Strong secret for secure examples
const STRONG_SECRET = crypto.randomBytes(64).toString('hex');

// RSA key pair for RS256 examples (simplified for demo)
const RSA_PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEjWT2BTq5W
xf5ghjsW8kHs4qTpxOOqJKqgQGhQPqhNZqGvJkJsXJHgWKKKhGvJkJsXJHgWKKK
...truncated for brevity...
-----END RSA PRIVATE KEY-----`;

const RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEjWT2BTq5Wxf5ghjsW8kHs4qTpxOOqJKqgQGhQPqhNZqGv
...truncated for brevity...
QIDAQAB
-----END PUBLIC KEY-----`;

// ============================================================================
// VULNERABLE EXAMPLE 1: 'none' Algorithm Bypass
// ============================================================================

app.post('/api/vulnerable/login-none', (req, res) => {
    /**
     * VULNERABLE: Accepts 'none' algorithm tokens
     * 
     * Attack: Create token with {"alg": "none", "typ": "JWT"} header
     * and no signature: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
     */
    const { username, password } = req.body;
    
    if (username === 'admin' && password === 'password') {
        // VULNERABLE: Using 'none' algorithm
        const token = jwt.sign({ user: username, role: 'admin' }, '', { algorithm: 'none' });
        return res.json({ token, message: 'Login successful' });
    }
    
    res.status(401).json({ error: 'Invalid credentials' });
});

app.get('/api/vulnerable/admin-none', (req, res) => {
    /**
     * VULNERABLE: Doesn't properly validate 'none' algorithm
     */
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        // VULNERABLE: Accepts any algorithm including 'none'
        const decoded = jwt.verify(token, WEAK_SECRET, { algorithms: ['HS256', 'none'] });
        
        if (decoded.role === 'admin') {
            return res.json({ message: 'Admin access granted', user: decoded.user });
        }
        
        res.status(403).json({ error: 'Insufficient privileges' });
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

// ============================================================================
// VULNERABLE EXAMPLE 2: Algorithm Confusion (RS256 to HS256)
// ============================================================================

app.post('/api/vulnerable/login-rs256', (req, res) => {
    /**
     * Creates RS256 token that can be exploited with algorithm confusion
     */
    const { username, password } = req.body;
    
    if (username === 'user' && password === 'password') {
        const token = jwt.sign(
            { user: username, role: 'user' }, 
            RSA_PRIVATE_KEY, 
            { algorithm: 'RS256', expiresIn: '1h' }
        );
        return res.json({ token, message: 'Login successful' });
    }
    
    res.status(401).json({ error: 'Invalid credentials' });
});

app.get('/api/vulnerable/admin-confusion', (req, res) => {
    /**
     * VULNERABLE: Algorithm confusion attack possible
     * 
     * Attack: Change algorithm from RS256 to HS256 and sign with public key
     */
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        // VULNERABLE: Allows multiple algorithms without proper validation
        const decoded = jwt.verify(token, RSA_PUBLIC_KEY, { algorithms: ['RS256', 'HS256'] });
        
        return res.json({ message: 'Access granted', user: decoded.user, role: decoded.role });
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

// ============================================================================
// VULNERABLE EXAMPLE 3: Weak Secret
// ============================================================================

app.post('/api/vulnerable/login-weak', (req, res) => {
    /**
     * VULNERABLE: Uses weak, predictable secret
     */
    const { username, password } = req.body;
    
    if (username === 'user' && password === 'password') {
        // VULNERABLE: Weak secret can be brute-forced
        const token = jwt.sign(
            { user: username, role: 'user', iat: Math.floor(Date.now() / 1000) }, 
            WEAK_SECRET,
            { algorithm: 'HS256' }
        );
        return res.json({ token, message: 'Login successful' });
    }
    
    res.status(401).json({ error: 'Invalid credentials' });
});

// ============================================================================
// VULNERABLE EXAMPLE 4: Missing Signature Verification
// ============================================================================

app.get('/api/vulnerable/no-verify', (req, res) => {
    /**
     * VULNERABLE: Decodes JWT without signature verification
     */
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        // VULNERABLE: Decodes without verification
        const decoded = jwt.decode(token);
        
        if (decoded && decoded.user) {
            return res.json({ message: 'Access granted', user: decoded.user });
        }
        
        res.status(401).json({ error: 'Invalid token' });
    } catch (error) {
        res.status(401).json({ error: 'Token decode failed' });
    }
});

// ============================================================================
// SECURE EXAMPLE 1: Proper Algorithm Validation
// ============================================================================

app.post('/api/secure/login', (req, res) => {
    /**
     * SECURE: Uses strong secret and proper algorithm
     */
    const { username, password } = req.body;
    
    // In production, validate against database with hashed passwords
    if (username === 'user' && password === 'securepassword123') {
        const token = jwt.sign(
            { 
                user: username, 
                role: 'user',
                iat: Math.floor(Date.now() / 1000),
                exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour
            }, 
            STRONG_SECRET,
            { algorithm: 'HS256' }
        );
        return res.json({ token, message: 'Login successful' });
    }
    
    res.status(401).json({ error: 'Invalid credentials' });
});

app.get('/api/secure/protected', (req, res) => {
    /**
     * SECURE: Proper JWT validation with specific algorithm
     */
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        // SECURE: Specify exact algorithm and verify signature
        const decoded = jwt.verify(token, STRONG_SECRET, { algorithms: ['HS256'] });
        
        // Additional validation
        if (!decoded.user || !decoded.role) {
            return res.status(401).json({ error: 'Invalid token structure' });
        }
        
        return res.json({ 
            message: 'Access granted', 
            user: decoded.user,
            role: decoded.role 
        });
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'Invalid token' });
        }
        res.status(401).json({ error: 'Token verification failed' });
    }
});

// ============================================================================
// SECURE EXAMPLE 2: RS256 with Proper Key Management
// ============================================================================

app.post('/api/secure/login-rs256', (req, res) => {
    /**
     * SECURE: RS256 with proper key management
     */
    const { username, password } = req.body;
    
    if (username === 'admin' && password === 'secureadminpass123') {
        const token = jwt.sign(
            { 
                user: username, 
                role: 'admin',
                iat: Math.floor(Date.now() / 1000),
                exp: Math.floor(Date.now() / 1000) + (60 * 30) // 30 minutes
            }, 
            RSA_PRIVATE_KEY,
            { algorithm: 'RS256' }
        );
        return res.json({ token, message: 'Admin login successful' });
    }
    
    res.status(401).json({ error: 'Invalid credentials' });
});

app.get('/api/secure/admin', (req, res) => {
    /**
     * SECURE: Proper RS256 validation
     */
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        // SECURE: Only allow RS256 algorithm
        const decoded = jwt.verify(token, RSA_PUBLIC_KEY, { algorithms: ['RS256'] });
        
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        return res.json({ 
            message: 'Admin access granted', 
            user: decoded.user 
        });
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        res.status(401).json({ error: 'Invalid token' });
    }
});

// ============================================================================
// SECURE EXAMPLE 3: Token Blacklisting
// ============================================================================

const blacklistedTokens = new Set();

app.post('/api/secure/logout', (req, res) => {
    /**
     * SECURE: Token blacklisting for logout
     */
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, STRONG_SECRET, { algorithms: ['HS256'] });
        
        // Add token to blacklist
        blacklistedTokens.add(token);
        
        res.json({ message: 'Logout successful' });
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

app.get('/api/secure/protected-with-blacklist', (req, res) => {
    /**
     * SECURE: Check token blacklist
     */
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    // Check blacklist first
    if (blacklistedTokens.has(token)) {
        return res.status(401).json({ error: 'Token has been revoked' });
    }
    
    try {
        const decoded = jwt.verify(token, STRONG_SECRET, { algorithms: ['HS256'] });
        
        return res.json({ 
            message: 'Access granted', 
            user: decoded.user 
        });
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

// ============================================================================
// UTILITY ENDPOINTS
// ============================================================================

app.get('/api/test/decode-token', (req, res) => {
    /**
     * Utility endpoint to decode JWT tokens for testing
     */
    const token = req.query.token;
    
    if (!token) {
        return res.status(400).json({ error: 'Token parameter required' });
    }
    
    try {
        const decoded = jwt.decode(token, { complete: true });
        res.json({
            header: decoded.header,
            payload: decoded.payload,
            signature: decoded.signature
        });
    } catch (error) {
        res.status(400).json({ error: 'Invalid token format' });
    }
});

app.get('/api/test/generate-attack-tokens', (req, res) => {
    /**
     * Generate example attack tokens for testing
     */
    const attackTokens = {
        none_algorithm: jwt.sign({ user: 'admin', role: 'admin' }, '', { algorithm: 'none' }),
        weak_secret: jwt.sign({ user: 'admin', role: 'admin' }, 'secret', { algorithm: 'HS256' }),
        algorithm_confusion: jwt.sign({ user: 'admin', role: 'admin' }, RSA_PUBLIC_KEY, { algorithm: 'HS256' })
    };
    
    res.json({
        message: 'Attack tokens for testing (DO NOT USE IN PRODUCTION)',
        tokens: attackTokens
    });
});

// ============================================================================
// SERVER STARTUP
// ============================================================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`JWT Security Demo Server running on port ${PORT}`);
    console.log('\nVulnerable Endpoints (for testing):');
    console.log('- POST /api/vulnerable/login-none');
    console.log('- GET /api/vulnerable/admin-none');
    console.log('- POST /api/vulnerable/login-rs256');
    console.log('- GET /api/vulnerable/admin-confusion');
    console.log('- POST /api/vulnerable/login-weak');
    console.log('- GET /api/vulnerable/no-verify');
    console.log('\nSecure Endpoints (production patterns):');
    console.log('- POST /api/secure/login');
    console.log('- GET /api/secure/protected');
    console.log('- POST /api/secure/login-rs256');
    console.log('- GET /api/secure/admin');
    console.log('- POST /api/secure/logout');
    console.log('- GET /api/secure/protected-with-blacklist');
    console.log('\nUtility Endpoints:');
    console.log('- GET /api/test/decode-token?token=<jwt>');
    console.log('- GET /api/test/generate-attack-tokens');
    console.log('\nWARNING: This application contains intentional JWT vulnerabilities!');
    console.log('Use only for security testing and educational purposes.');
});
