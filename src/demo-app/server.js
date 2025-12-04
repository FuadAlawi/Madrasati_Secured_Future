/**
 * Madrasati Demo Application
 * Simple web application for security testing with OWASP ZAP
 */

const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory user database (for demo purposes)
const users = [
    {
        id: 1,
        username: 'student001',
        password: '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzQxQxQxQx', // 'Student@123'
        role: 'student',
        name: 'Ahmed AlSaudi'
    },
    {
        id: 2,
        username: 'teacher001',
        password: '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzQxQxQxQx', // 'Teacher@123'
        role: 'teacher',
        name: 'Fatima AlMutairi'
    }
];

const grades = [
    { student_id: 1, course: 'Mathematics', grade: 85, teacher_id: 2 },
    { student_id: 1, course: 'Arabic', grade: 92, teacher_id: 2 },
    { student_id: 1, course: 'Science', grade: 78, teacher_id: 2 }
];

// ============= Security Middleware =============

// Helmet for security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true
    }
}));

// Additional security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'madrasati-demo-secret-change-in-production',
    name: 'madrasati_sid',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Set to true in production with HTTPS
        httpOnly: true,
        maxAge: 1800000, // 30 minutes
        sameSite: 'strict'
    }
}));

// Rate limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    message: 'Too many login attempts, please try again after 15 minutes'
});

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 60 // 60 requests per minute
});

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static files
app.use('/static', express.static(path.join(__dirname, 'public')));

// ============= Authentication Middleware =============

function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
}

function requireRole(role) {
    return (req, res, next) => {
        if (req.session.userRole !== role) {
            return res.status(403).send('Forbidden: Insufficient permissions');
        }
        next();
    };
}

// ============= Routes =============

// Home page (public)
app.get('/', (req, res) => {
    res.render('index', {
        user: req.session.userId ? {
            id: req.session.userId,
            name: req.session.userName,
            role: req.session.userRole
        } : null
    });
});

// Login page
app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.render('login', { error: null });
});

// Login POST (with rate limiting)
app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;

    // Input validation
    if (!username || !password) {
        return res.render('login', { error: 'Username and password required' });
    }

    // Find user (in production, query database securely)
    const user = users.find(u => u.username === username);

    if (!user) {
        // Generic error message to prevent username enumeration
        return res.render('login', { error: 'Invalid username or password' });
    }

    // Verify password (in production, use bcrypt.compare)
    // For demo, using simple comparison
    const bcrypt = require('bcrypt');
    const isValid = await bcrypt.compare(password, user.password);

    if (!isValid) {
        return res.render('login', { error: 'Invalid username or password' });
    }

    // Create session
    req.session.userId = user.id;
    req.session.userName = user.name;
    req.session.userRole = user.role;
    req.session.username = user.username;

    res.redirect('/dashboard');
});

// Dashboard (protected)
app.get('/dashboard', requireAuth, (req, res) => {
    const user = users.find(u => u.id === req.session.userId);

    res.render('dashboard', {
        user: {
            id: user.id,
            name: user.name,
            role: user.role,
            username: user.username
        }
    });
});

// View grades (student only)
app.get('/grades', requireAuth, (req, res) => {
    if (req.session.userRole !== 'student') {
        return res.status(403).send('Only students can view this page');
    }

    const studentGrades = grades.filter(g => g.student_id === req.session.userId);

    res.render('grades', {
        user: {
            id: req.session.userId,
            name: req.session.userName,
            role: req.session.userRole
        },
        grades: studentGrades
    });
});

// Manage grades (teacher only)
app.get('/manage-grades', requireAuth, requireRole('teacher'), (req, res) => {
    res.render('manage-grades', {
        user: {
            id: req.session.userId,
            name: req.session.userName,
            role: req.session.userRole
        },
        grades: grades
    });
});

// API endpoint to get grades (with authorization)
app.get('/api/grades/:studentId', apiLimiter, requireAuth, (req, res) => {
    const requestedStudentId = parseInt(req.params.studentId);

    // Authorization check
    if (req.session.userRole === 'student' && requestedStudentId !== req.session.userId) {
        return res.status(403).json({
            error: 'Forbidden',
            message: 'You can only view your own grades'
        });
    }

    const studentGrades = grades.filter(g => g.student_id === requestedStudentId);

    res.json({
        success: true,
        student_id: requestedStudentId,
        grades: studentGrades
    });
});

// Logout
app.post('/logout', requireAuth, (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Session destruction error:', err);
        }
        res.clearCookie('madrasati_sid');
        res.redirect('/');
    });
});

// Profile (demonstration of input validation)
app.get('/profile', requireAuth, (req, res) => {
    const user = users.find(u => u.id === req.session.userId);
    res.render('profile', { user, error: null, success: null });
});

app.post('/profile', requireAuth, (req, res) => {
    const { name, email } = req.body;

    // Input validation
    if (!name || name.length < 2 || name.length > 100) {
        return res.render('profile', {
            user: users.find(u => u.id === req.session.userId),
            error: 'Name must be between 2 and 100 characters',
            success: null
        });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (email && !emailRegex.test(email)) {
        return res.render('profile', {
            user: users.find(u => u.id === req.session.userId),
            error: 'Invalid email format',
            success: null
        });
    }

    // Update user (in production, update database)
    const user = users.find(u => u.id === req.session.userId);
    user.name = name;
    req.session.userName = name;

    res.render('profile', {
        user,
        error: null,
        success: 'Profile updated successfully'
    });
});

// Error handling
app.use((err, req, res, next) => {
    console.error('Error:', err);

    res.status(500).render('error', {
        message: process.env.NODE_ENV === 'production'
            ? 'An unexpected error occurred'
            : err.message
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).render('error', { message: 'Page not found' });
});

// ============= Start Server =============

app.listen(PORT, () => {
    console.log(`🚀 Madrasati Demo Application running on http://localhost:${PORT}`);
    console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`\n   Demo Credentials:`);
    console.log(`   Student: student001 / Student@123`);
    console.log(`   Teacher: teacher001 / Teacher@123`);
});

module.exports = app;
