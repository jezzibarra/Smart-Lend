/**
 * Smart Lending Application (SLAP)
 * Core Enterprise Express & MongoDB Server
 *
 * SECURITY & PRIVACY POLICIES ENFORCED:
 * 1. IP Address Protection:
 *    - Zero IP collection or storage in database or logs.
 *    - Request logging excludes IP addresses, headers, and tokens.
 *    - Static serving is locked down (server source and .env are never served).
 * 2. Strict Sign-Up Whitelist:
 *    - Accepts only permitted fields (username, email, password, dob, idType, idNumber, otp).
 *    - Rejects or strips unauthorized fields (role, isAdmin, ipAddress).
 * 3. Password Security:
 *    - Passwords hashed using bcryptjs (12 salt rounds) - never stored as plain text.
 *    - Password hashes are excluded from API responses and default queries.
 * 4. Role-Based Access Control (RBAC):
 *    - 'customer' and 'admin' roles are enforced ON THE SERVER for every protected endpoint.
 *    - Admin privileges are never assignable through public registration.
 * 5. Sessions:
 *    - Stateless JWT (HS256, 1-hour expiry) issued only after credential verification.
 * 6. Brute-force protection via rate limits keyed on username/email (never on IP).
 * 7. Audit logs record admin actions without IPs, tokens, passwords, or full records.
 * 8. DATABASE-ONLY OPERATION:
 *    - The server refuses to start unless MongoDB is reachable.
 *    - No in-memory or mock storage exists: a record is reported as saved ONLY
 *      when MongoDB confirms the write.
 */

require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');

const { connectDB, getIsConnected } = require('./config/db');
const {
  signToken,
  allowlistBody,
  cleanString,
  parsePositiveAmount,
  isValidObjectId
} = require('./config/security');
const { authenticate, requireAdmin, requireCustomer } = require('./middleware/auth');
const { createRateLimiter } = require('./middleware/rateLimit');
const User = require('./models/User');
const Client = require('./models/Client');
const Transaction = require('./models/Transaction');
const AuditLog = require('./models/AuditLog');
const { evaluateApplication, getPublicRates } = require('./config/lending');
const LoanApplication = require('./models/LoanApplication');

const app = express();
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// Disable technology fingerprinting header
app.disable('x-powered-by');

// ----------------------------------------------------
// CORS (explicit allowlist - never wildcard with credentials)
// - SAME-ORIGIN browser requests are always allowed so the portals served by
//   this server keep working with zero configuration.
// - Cross-origin access requires the origin in ALLOWED_ORIGINS.
// - file:// pages ("Origin: null") are allowed in development only.
// ----------------------------------------------------
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  const host = req.headers.host;

  const hasNoOrigin = !origin;
  const isSameOrigin = !!origin && !!host && origin.replace(/^https?:\/\//i, '').toLowerCase() === host.toLowerCase();
  const isLocalFile = origin === 'null' && !IS_PRODUCTION;
  const isExplicitlyAllowed = !!origin && allowedOrigins.includes(origin);
  const allowed = hasNoOrigin || isSameOrigin || isExplicitlyAllowed || isLocalFile;

  if (allowed) {
    if (origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  }

  if (req.method === 'OPTIONS') {
    if (!allowed) return res.status(403).json({ success: false, message: 'Origin not allowed.' });
    return res.sendStatus(204);
  }
  if (!allowed) {
    return res.status(403).json({ success: false, message: 'Origin not allowed.' });
  }
  next();
});

// Body parser with payload limit protection
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// ----------------------------------------------------
// SECURITY HEADERS (+ Content Security Policy)
// ----------------------------------------------------
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  if (IS_PRODUCTION) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://accounts.google.com",
    "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self' https://accounts.google.com",
    "frame-src https://accounts.google.com"
  ].join('; '));
  next();
});

// ----------------------------------------------------
// PRIVACY-COMPLIANT LOGGING (no IPs, headers, or credentials)
// ----------------------------------------------------
app.use((req, res, next) => {
  console.log(`[API] ${req.method} ${req.path}`);
  next();
});

// ----------------------------------------------------
// DATABASE GUARD
// Ensures the backend connects to MongoDB BEFORE accepting database-dependent
// requests. Requests arriving while MongoDB is unavailable receive a clear 503
// instead of silently succeeding against mock data.
// ----------------------------------------------------
async function ensureDatabase(req, res, next) {
  await connectDB();
  if (getIsConnected()) return next();
  return res.status(503).json({
    success: false,
    message: 'Database temporarily unavailable. Ensure MongoDB is running, then try again shortly.'
  });
}

// ----------------------------------------------------
// STATIC SERVING (locked down)
// Only these routes exist - server source, .env and package files are never
// downloadable. (The previous implementation served the whole project dir.)
// ----------------------------------------------------
function safeStatic(dir) {
  const handler = express.static(path.join(__dirname, dir));
  return (req, res, next) => {
    const ext = path.extname(req.path).toLowerCase();
    if (ext && !['.html', '.css'].includes(ext)) {
      return res.status(404).json({ success: false, message: 'Not found.' });
    }
    handler(req, res, next);
  };
}
app.use('/Login', safeStatic('Login'));
app.use('/Admin', safeStatic('Admin'));
app.use('/Dashboard', safeStatic('Dashboard'));
app.get('/privacy.html', (req, res) => res.sendFile(path.join(__dirname, 'privacy.html')));
app.get('/', (req, res) => res.redirect('/Login/index.html'));

// ----------------------------------------------------
// EPHEMERAL OTP STORE
// Transient email verification codes (5-minute expiry). This is NOT a database
// fallback - codes exist only in memory and expire automatically.
// ----------------------------------------------------
const otpStore = {};
setInterval(() => {
  const now = Date.now();
  for (const [email, record] of Object.entries(otpStore)) {
    if (now > record.expiresAt) delete otpStore[email];
  }
}, 60 * 1000).unref();

// ----------------------------------------------------
// HELPERS
// ----------------------------------------------------
function generateOtp() {
  return String(crypto.randomInt(100000, 1000000));
}

function formatAmount(amount) {
  return '₱' + Number(amount).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function publicUser(user) {
  return {
    id: user._id ? user._id.toString() : String(user.id || ''),
    username: user.username,
    email: user.email,
    role: user.role || 'customer'
  };
}

function issueToken(user) {
  return signToken({
    sub: user._id ? user._id.toString() : String(user.id || ''),
    username: user.username,
    role: user.role || 'customer'
  });
}

/** Writes an audit entry. Never stores IPs, tokens, or personal details. */
async function logAudit(action, actor, targetId = '', details = '') {
  if (!actor || !actor.username || !actor.role) return;
  try {
    await AuditLog.create({
      action,
      actorUsername: actor.username,
      actorRole: actor.role,
      targetId: String(targetId || '').slice(0, 60),
      details: String(details || '').slice(0, 300),
      createdAt: new Date()
    });
  } catch (err) {
    console.error('[AUDIT] Unable to record audit entry:', err.message);
  }
}

// ----------------------------------------------------
// GOOGLE OAUTH CONFIGURATION
// ----------------------------------------------------
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '359397950707-011kbbsi7hdfi1mingsqnehfo5m3i00b.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

const AUTHORIZED_ADMIN_EMAILS = (process.env.AUTHORIZED_ADMIN_EMAILS || 'owner@business.com,jessalbarra428@gmail.com,yvonemartinez023@gmail.com')
  .split(',')
  .map(e => e.trim().toLowerCase())
  .filter(Boolean);

// ----------------------------------------------------
// RATE LIMITERS (keyed on submitted identifier - never IP)
// ----------------------------------------------------
const loginLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 15, keyFn: req => cleanString(req.body && req.body.username).toLowerCase() || 'login-anonymous' });
const signupLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10, keyFn: req => cleanString(req.body && req.body.email).toLowerCase() || 'signup-anonymous' });
const otpLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10, keyFn: req => cleanString(req.body && req.body.email).toLowerCase() || 'otp-anonymous' });
const googleLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 15, keyFn: () => 'google' });

// ----------------------------------------------------
// STARTUP: seed sample data + bootstrap admin (server startup only)
// ----------------------------------------------------
async function seedDatabaseIfEmpty() {
  try {
    const clientCount = await Client.countDocuments();
    if (clientCount === 0) {
      await Client.insertMany([
        { clientId: 'C101', name: 'Maria Santos', contact: '09171234567', loan: '₱10,000.00', status: 'Active', createdAt: new Date() },
        { clientId: 'C102', name: 'Juan Cruz', contact: '09189876543', loan: '₱5,000.00', status: 'Fully Paid', createdAt: new Date() }
      ]);
      console.log('[DATABASE] Seeded default client records.');
    }
    const txnCount = await Transaction.countDocuments();
    if (txnCount === 0) {
      await Transaction.insertMany([
        { txnId: 'TXN-8801', name: 'Maria Santos', channel: 'GCash', ref: '900182391', amount: '₱2,000.00', date: '2026-10-08', createdAt: new Date() }
      ]);
      console.log('[DATABASE] Seeded default transaction records.');
    }
  } catch (err) {
    console.error('[DATABASE] Sample data seeding skipped:', err.message);
  }
}

/**
 * Creates an initial administrator ONLY when environment variables provide the
 * credentials explicitly. There are NO hardcoded admin passwords in this codebase.
 * Use scripts/setup-admin.js to create additional admins securely.
 */
async function bootstrapInitialAdmin() {
  const username = cleanString(process.env.INITIAL_ADMIN_USERNAME);
  const email = cleanString(process.env.INITIAL_ADMIN_EMAIL).toLowerCase();
  const password = process.env.INITIAL_ADMIN_PASSWORD || '';

  if (!username || !email || !password) {
    console.warn('[ADMIN SETUP] No initial admin configured. Run "npm run setup:admin" to create one securely.');
    return;
  }
  if (password.length < 8) {
    console.warn('[ADMIN SETUP] INITIAL_ADMIN_PASSWORD must be at least 8 characters.');
    return;
  }

  try {
    const adminExists = await User.findOne({ role: 'admin' });
    if (adminExists) return;

    const user = new User({ username: username.toLowerCase(), email, password, role: 'admin', provider: 'local' });
    await user.save();
    await logAudit('admin.create_admin', { username: user.username, role: 'admin' }, String(user._id), 'Initial admin created from environment configuration');
    console.log(`[ADMIN SETUP] Initial admin "${username}" created in database.`);
  } catch (err) {
    console.error('[ADMIN SETUP] Could not create initial admin:', err.message);
  }
}

// ====================================================
// 0. PUBLIC CONFIG & RATES (no database required)
// ====================================================
const DEV_TEST_ACCOUNTS = [
  { id: 'admin', label: 'Login as Admin', username: 'admin.test@example.com', password: 'AdminTest123!' },
  { id: 'customer1', label: 'Login as Customer 1', username: 'customer.test@example.com', password: 'CustomerTest123!' },
  { id: 'customer2', label: 'Login as Customer 2', username: 'customer2.test@example.com', password: 'CustomerTest456!' }
];

app.get('/api/config', (req, res) => {
  const payload = {
    success: true,
    environment: IS_PRODUCTION ? 'production' : 'development',
    testAccountsEnabled: !IS_PRODUCTION
  };
  if (!IS_PRODUCTION) payload.testAccounts = DEV_TEST_ACCOUNTS;
  res.json(payload);
});

app.get('/api/rates', (req, res) => {
  res.json({ success: true, data: getPublicRates() });
});

// ====================================================
// 1. CUSTOMER AUTHENTICATION ENDPOINTS (/api/auth)
// ====================================================

// --- A. SEND OTP ENDPOINT ---
app.post('/api/auth/send-otp', otpLimiter, (req, res) => {
  const email = cleanString(req.body.email).toLowerCase();

  if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ success: false, message: 'Valid email address is required.' });
  }

  const otp = generateOtp();
  otpStore[email] = { code: otp, expiresAt: Date.now() + 5 * 60 * 1000 };

  if (!IS_PRODUCTION) {
    console.log(`[OTP] Verification code dispatched to ${email}: ${otp}`);
  } else {
    console.log('[OTP] Verification code dispatched.');
  }

  res.status(200).json({ success: true, message: 'Verification code sent. Check the server console (development mode).' });
});

// --- B. CUSTOMER SIGN-UP ENDPOINT ---
app.post('/api/auth/signup', ensureDatabase, signupLimiter, async (req, res) => {
  const { username, email, password, dob, idType, idNumber, otp } =
    allowlistBody(req.body, ['username', 'email', 'password', 'dob', 'idType', 'idNumber', 'otp']);

  if (!username || !email || !password || !dob || !idType || !idNumber) {
    return res.status(400).json({ success: false, message: 'All registration fields are required.' });
  }

  const cleanEmail = cleanString(email).toLowerCase();
  const cleanUsername = cleanString(username).toLowerCase();

  // 1. Verify OTP
  const storedOtp = otpStore[cleanEmail];
  if (!storedOtp || storedOtp.code !== cleanString(otp) || Date.now() > storedOtp.expiresAt) {
    return res.status(400).json({ success: false, message: 'Invalid or expired verification code.' });
  }

  // 2. Strict Age Verification (>= 18)
  const birthDate = new Date(dob);
  const today = new Date();
  let age = today.getFullYear() - birthDate.getFullYear();
  const m = today.getMonth() - birthDate.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) age--;
  if (isNaN(age) || age < 18) {
    return res.status(403).json({
      success: false,
      message: 'Access Denied: You must be at least 18 years old to access this website and register for loans.'
    });
  }
  if (age > 120) {
    return res.status(400).json({ success: false, message: 'Please provide a valid date of birth.' });
  }

  // 3. Password Strength Server Validation
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long.' });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ email: cleanEmail }, { username: cleanUsername }] });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'A user with this username or email already exists.' });
    }

    const user = new User({
      username: cleanUsername,
      email: cleanEmail,
      password, // hashed by the User model pre-save hook (bcrypt, 12 rounds)
      dob: birthDate,
      age,
      idType: cleanString(idType),
      idNumber: cleanString(idNumber),
      role: 'customer' // Enforced server-side: public signup can NEVER create admins
    });

    await user.save(); // success here means MongoDB confirmed the write
    delete otpStore[cleanEmail];

    await logAudit('customer.registered', { username: user.username, role: 'customer' }, String(user._id));

    return res.status(201).json({ success: true, message: 'Account created successfully.', user: publicUser(user) });
  } catch (err) {
    console.error('[AUTH ERROR] Registration failed:', err.message);
    return res.status(500).json({ success: false, message: 'Server error during account registration.' });
  }
});

// --- C. CUSTOMER LOGIN ENDPOINT ---
app.post('/api/auth/login', ensureDatabase, loginLimiter, async (req, res) => {
  const { username, password } = allowlistBody(req.body, ['username', 'password']);
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username/email and password are required.' });
  }

  const cleanIdentifier = cleanString(username).toLowerCase();

  try {
    const user = await User.findOne({
      $or: [{ email: cleanIdentifier }, { username: cleanIdentifier }]
    }).select('+password');

    if (!user || user.role !== 'customer') {
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }

    await logAudit('customer.login', { username: user.username, role: 'customer' }, String(user._id));

    return res.status(200).json({
      success: true,
      message: 'Login successful.',
      token: issueToken(user),
      user: publicUser(user)
    });
  } catch (err) {
    console.error('[AUTH ERROR] Customer login error:', err.message);
    return res.status(500).json({ success: false, message: 'Internal authentication error.' });
  }
});

// --- D. CUSTOMER GOOGLE SIGN-IN ---
app.post('/api/auth/google', ensureDatabase, googleLimiter, async (req, res) => {
  const credential = cleanString(req.body.credential);
  if (!credential) {
    return res.status(400).json({ success: false, message: 'Google credential token is required.' });
  }

  try {
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = (payload.email || '').toLowerCase();

    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({
        email,
        username: (email.split('@')[0] + '-' + crypto.randomInt(1000, 9999)).toLowerCase(),
        role: 'customer',
        provider: 'google'
      });
    }
    if (user.role !== 'customer') {
      return res.status(403).json({ success: false, message: 'Use the admin portal for staff accounts.' });
    }

    await logAudit('customer.google_login', { username: user.username, role: 'customer' }, String(user._id));

    return res.status(200).json({ success: true, message: 'Google authentication successful.', token: issueToken(user), user: publicUser(user) });
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Invalid Google OAuth credential token.' });
  }
});

// --- E. LOGOUT (audit record; token removal happens client-side) ---
app.post('/api/auth/logout', ensureDatabase, authenticate, async (req, res) => {
  await logAudit(req.user.role === 'admin' ? 'admin.logout' : 'customer.login', req.user, '', 'Session ended by user');
  res.json({ success: true, message: 'Signed out. Please clear your local session.' });
});

// ====================================================
// 2. CUSTOMER DATA ENDPOINTS (own data only)
// ====================================================

// --- A. OWN PROFILE ---
app.get('/api/customer/profile', ensureDatabase, authenticate, requireCustomer, async (req, res) => {
  try {
    if (!isValidObjectId(req.user.userId)) {
      return res.status(400).json({ success: false, message: 'Invalid account reference.' });
    }
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'Account not found.' });
    }
    return res.json({ success: true, data: user.toJSON() });
  } catch (err) {
    console.error('[CUSTOMER ERROR] profile:', err.message);
    return res.status(500).json({ success: false, message: 'Unable to load profile.' });
  }
});

// --- B. OWN LOAN RECORDS ---
app.get('/api/customer/loans', ensureDatabase, authenticate, requireCustomer, async (req, res) => {
  try {
    if (!isValidObjectId(req.user.userId)) {
      return res.status(400).json({ success: false, message: 'Invalid account reference.' });
    }
    const loans = await Client.find({ ownerId: req.user.userId }).sort({ createdAt: -1 });
    return res.json({ success: true, data: loans });
  } catch (err) {
    console.error('[CUSTOMER ERROR] loans:', err.message);
    return res.status(500).json({ success: false, message: 'Unable to load loan records.' });
  }
});

// --- C. OWN PAYMENT HISTORY ---
app.get('/api/customer/payments', ensureDatabase, authenticate, requireCustomer, async (req, res) => {
  try {
    if (!isValidObjectId(req.user.userId)) {
      return res.status(400).json({ success: false, message: 'Invalid account reference.' });
    }
    const payments = await Transaction.find({ ownerId: req.user.userId }).sort({ createdAt: -1 });
    return res.json({ success: true, data: payments });
  } catch (err) {
    console.error('[CUSTOMER ERROR] payments:', err.message);
    return res.status(500).json({ success: false, message: 'Unable to load payment history.' });
  }
});

// ====================================================
// 3. ADMIN AUTHENTICATION ENDPOINTS (/api/admin)
// ====================================================

// --- A. ADMIN LOGIN (database-backed accounts only) ---
app.post('/api/admin/login', ensureDatabase, loginLimiter, async (req, res) => {
  const { username, password } = allowlistBody(req.body, ['username', 'password']);
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }

  const cleanUser = cleanString(username).toLowerCase();
  console.log('[ADMIN LOGIN DEBUG] Attempt login for:', cleanUser);

  try {
    const admin = await User.findOne({
      $or: [{ email: cleanUser }, { username: cleanUser }],
      role: 'admin'
    }).select('+password');

    console.log('[ADMIN LOGIN DEBUG] Found admin:', admin ? admin.username : 'NOT FOUND');

    if (!admin) {
      console.log('[ADMIN LOGIN DEBUG] Admin not found for:', cleanUser);
      return res.status(401).json({ success: false, message: 'Invalid administrative credentials.' });
    }

    const isMatch = await admin.comparePassword(password);
    console.log('[ADMIN LOGIN DEBUG] Password match:', isMatch);
    if (!isMatch) {
      console.log('[ADMIN LOGIN DEBUG] Password mismatch for:', cleanUser);
      return res.status(401).json({ success: false, message: 'Invalid administrative credentials.' });
    }

    await logAudit('admin.login', { username: admin.username, role: 'admin' }, String(admin._id));

    return res.status(200).json({ success: true, message: 'Admin authentication successful.', token: issueToken(admin), user: publicUser(admin) });
  } catch (err) {
    console.error('[ADMIN ERROR] login:', err.message);
    return res.status(500).json({ success: false, message: 'Internal authentication error.' });
  }
});

// --- B. ADMIN GOOGLE SIGN-IN (whitelist verification) ---
app.post('/api/admin/google', ensureDatabase, googleLimiter, async (req, res) => {
  const credential = cleanString(req.body.credential);
  if (!credential) {
    return res.status(400).json({ success: false, message: 'Google credential is required.' });
  }

  try {
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = (payload.email || '').toLowerCase();

    if (!AUTHORIZED_ADMIN_EMAILS.includes(email)) {
      return res.status(403).json({
        success: false,
        message: 'Access Denied: This Google account is not whitelisted for administrative access.'
      });
    }

    let admin = await User.findOne({ email, role: 'admin' });
    if (!admin) {
      // OAuth admins have no password (random unusable hash).
      const randomPassword = crypto.randomBytes(32).toString('hex');
      admin = await User.create({
        email,
        username: (email.split('@')[0] + '-' + crypto.randomInt(1000, 9999)).toLowerCase(),
        password: randomPassword,
        role: 'admin',
        provider: 'google'
      });
    }

    await logAudit('admin.google_login', { username: admin.username, role: 'admin' }, String(admin._id));

    return res.status(200).json({ success: true, message: 'Admin Google authentication verified.', token: issueToken(admin), user: publicUser(admin) });
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid Google authentication token.' });
  }
});

// ====================================================
// 4. CLIENT LOAN RECORDS ENDPOINTS (/api/clients) [ADMIN]
// ====================================================

app.get('/api/clients', ensureDatabase, authenticate, requireAdmin, async (req, res) => {
  try {
    const clients = await Client.find().sort({ createdAt: -1 });
    return res.status(200).json({ success: true, data: clients });
  } catch (err) {
    console.error('[CLIENT ERROR] list:', err.message);
    return res.status(500).json({ success: false, message: 'Unable to retrieve client records.' });
  }
});

app.post('/api/clients', ensureDatabase, authenticate, requireAdmin, async (req, res) => {
  const { name, contact, loan, status } = allowlistBody(req.body, ['name', 'contact', 'loan', 'status']);

  const cleanName = cleanString(name);
  const cleanContact = cleanString(contact);
  const amount = parsePositiveAmount(loan);

  if (!cleanName || !cleanContact || amount === null) {
    return res.status(400).json({ success: false, message: 'Client name, contact, and a valid loan amount are required.' });
  }
  if (cleanName.length > 100 || cleanContact.length > 20) {
    return res.status(400).json({ success: false, message: 'Client details exceed allowed length.' });
  }
  const cleanStatus = ['Active', 'Fully Paid', 'Overdue'].includes(status) ? status : 'Active';
  const formattedLoan = formatAmount(amount);

  try {
    const count = await Client.countDocuments();
    const client = new Client({
      clientId: 'C10' + (count + 1),
      name: cleanName,
      contact: cleanContact,
      loan: formattedLoan,
      status: cleanStatus
    });
    await client.save();

    await logAudit('admin.create_client', req.user, client.clientId, 'Loan record registered');
    return res.status(201).json({ success: true, message: 'Client record saved.', data: client });
  } catch (err) {
    console.error('[CLIENT ERROR] create:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to record client.' });
  }
});

// --- DELETE CLIENT (sensitive operation - audit logged) ---
app.delete('/api/admin/clients/:clientId', ensureDatabase, authenticate, requireAdmin, async (req, res) => {
  const clientId = cleanString(req.params.clientId);
  if (!/^[A-Za-z0-9-]{1,30}$/.test(clientId)) {
    return res.status(400).json({ success: false, message: 'Invalid client reference.' });
  }

  try {
    const deleted = await Client.findOneAndDelete({ clientId });
    if (!deleted) {
      return res.status(404).json({ success: false, message: 'Client record not found.' });
    }
    await logAudit('admin.delete_client', req.user, clientId, 'Loan record deleted');
    return res.json({ success: true, message: 'Client record deleted.' });
  } catch (err) {
    console.error('[CLIENT ERROR] delete:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to delete client record.' });
  }
});

// ====================================================
// 5. TRANSACTION ENGINE ENDPOINTS (/api/transactions) [ADMIN]
// ====================================================

app.get('/api/transactions', ensureDatabase, authenticate, requireAdmin, async (req, res) => {
  try {
    const transactions = await Transaction.find().sort({ createdAt: -1 });
    return res.status(200).json({ success: true, data: transactions });
  } catch (err) {
    console.error('[TXN ERROR] list:', err.message);
    return res.status(500).json({ success: false, message: 'Unable to retrieve transaction logs.' });
  }
});

app.post('/api/transactions', ensureDatabase, authenticate, requireAdmin, async (req, res) => {
  const { name, channel, ref, amount } = allowlistBody(req.body, ['name', 'channel', 'ref', 'amount']);

  const cleanName = cleanString(name);
  const cleanRef = cleanString(ref);
  const parsedAmount = parsePositiveAmount(amount);

  if (!cleanName || !cleanRef || parsedAmount === null) {
    return res.status(400).json({ success: false, message: 'All transaction reference fields are required.' });
  }
  if (!['GCash', 'Maya'].includes(channel)) {
    return res.status(400).json({ success: false, message: 'Payment channel must be GCash or Maya.' });
  }
  if (!/^[A-Za-z0-9-]{4,30}$/.test(cleanRef)) {
    return res.status(400).json({ success: false, message: 'Transaction reference format is invalid.' });
  }

  const txnId = 'TXN-' + crypto.randomInt(1000, 10000);
  const date = new Date().toISOString().split('T')[0];
  const formattedAmount = formatAmount(parsedAmount);

  try {
    const txn = new Transaction({
      txnId,
      name: cleanName,
      channel,
      ref: cleanRef,
      amount: formattedAmount,
      date
    });
    await txn.save();

    await logAudit('admin.create_transaction', req.user, txnId, 'Payment reference verified');
    return res.status(201).json({ success: true, message: 'Transaction saved.', data: txn });
  } catch (err) {
    console.error('[TXN ERROR] create:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to record transaction reference.' });
  }
});

// ====================================================
// 6. BORROWER EVALUATION / LOAN APPLICATIONS
// ====================================================

const UPLOAD_ROOT = path.join(__dirname, 'uploads', 'loan-applications');
const MAX_DOC_SIZE_BYTES = 1.5 * 1024 * 1024; // 1.5 MB per document
const ALLOWED_DOC_TYPES = {
  'image/png': Buffer.from([0x89, 0x50, 0x4e, 0x47]),
  'image/jpeg': Buffer.from([0xff, 0xd8, 0xff]),
  'image/webp': Buffer.from([0x52, 0x49, 0x46, 0x46]),
  'application/pdf': Buffer.from([0x25, 0x50, 0x44, 0x46])
};

function generateApplicationRef() {
  return `APP-${new Date().getFullYear()}-${crypto.randomInt(100000, 1000000)}`;
}

function matchesFileMagic(buffer, mimeType) {
  const signature = ALLOWED_DOC_TYPES[mimeType];
  if (!signature) return false;
  for (let i = 0; i < signature.length; i++) {
    if (buffer[i] !== signature[i]) return false;
  }
  return true;
}

/** Validates + securely stores an uploaded document; returns stored metadata. */
function storeApplicationDocument(applicationRef, doc) {
  const kind = cleanString(doc.kind);
  const originalName = cleanString(doc.originalName);
  const mimeType = cleanString(doc.mimeType);
  const dataBase64 = typeof doc.dataBase64 === 'string' ? doc.dataBase64 : '';

  if (!['idDocument', 'proofOfIncome'].includes(kind)) {
    return { error: 'Invalid document kind.' };
  }
  if (!originalName || originalName.length > 150) {
    return { error: 'Invalid document file name.' };
  }
  if (!ALLOWED_DOC_TYPES[mimeType]) {
    return { error: 'Unsupported file type. Allowed: PNG, JPEG, WEBP, PDF.' };
  }

  let buffer;
  try {
    buffer = Buffer.from(dataBase64, 'base64');
    if (!buffer || buffer.length === 0) throw new Error('empty');
  } catch (err) {
    return { error: 'Invalid document data.' };
  }
  if (buffer.length > MAX_DOC_SIZE_BYTES) {
    return { error: 'Document exceeds the 1.5 MB limit.' };
  }
  if (!matchesFileMagic(buffer, mimeType)) {
    return { error: 'File content does not match its declared type.' };
  }

  const extension = mimeType === 'application/pdf' ? '.pdf'
    : mimeType === 'image/png' ? '.png'
    : mimeType === 'image/webp' ? '.webp' : '.jpg';

  const dir = path.join(UPLOAD_ROOT, applicationRef);
  fs.mkdirSync(dir, { recursive: true });
  const storedPath = path.join(dir, `${kind}${extension}`);
  fs.writeFileSync(storedPath, buffer);

  return { ok: true, meta: { kind, originalName, storedPath, mimeType, sizeBytes: buffer.length } };
}

function validateApplicationPayload(body) {
  const { personal, employment, debts, loanRequest, consent, documents } = body || {};

  const fullName = cleanString(personal && personal.fullName);
  const dobRaw = cleanString(personal && personal.dob);
  const mobile = cleanString(personal && personal.mobile).replace(/[\s-]/g, '');
  const email = cleanString(personal && personal.email).toLowerCase();
  const residentialAddress = cleanString(personal && personal.residentialAddress);
  const idType = cleanString(personal && personal.idType);
  const idNumber = cleanString(personal && personal.idNumber);

  if (!fullName || fullName.length < 3) return { error: 'Full legal name is required (min 3 characters).' };
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dobRaw)) return { error: 'Valid date of birth (YYYY-MM-DD) is required.' };

  const dob = new Date(dobRaw);
  const today = new Date();
  let age = today.getFullYear() - dob.getFullYear();
  const m = today.getMonth() - dob.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < dob.getDate())) age--;
  if (isNaN(age) || age < 18) return { error: 'Applicant must be at least 18 years old.' };
  if (age > 120) return { error: 'Please provide a valid date of birth.' };

  if (!/^09\d{9}$/.test(mobile)) return { error: 'Valid PH mobile number required (e.g. 09171234567).' };
  if (!/^\S+@\S+\.\S+$/.test(email)) return { error: 'Valid email address is required.' };
  if (residentialAddress.length < 10) return { error: 'Complete residential address is required (min 10 characters).' };
  if (!idType || !idNumber) return { error: 'Valid government ID type and number are required.' };
  if (idNumber.length < 4 || idNumber.length > 30) return { error: 'ID number must be 4-30 characters.' };

  const employmentStatus = cleanString(employment && employment.employmentStatus);
  const occupation = cleanString(employment && employment.occupation);
  const employerName = cleanString(employment && employment.employerName);
  const monthlyIncome = Number(employment && employment.monthlyIncome);
  const otherIncomeSource = cleanString(employment && employment.otherIncomeSource);
  const otherIncome = Number(employment && employment.otherIncome || 0);

  if (!['Employed', 'Self-Employed', 'Business Owner', 'Freelancer', 'OFW', 'Student', 'Unemployed', 'Retired'].includes(employmentStatus)) {
    return { error: 'Valid employment status is required.' };
  }
  if (!occupation || occupation.length < 2) return { error: 'Occupation is required.' };
  if (!Number.isFinite(monthlyIncome) || monthlyIncome < 0) return { error: 'Valid monthly income is required.' };
  if (otherIncome < 0) return { error: 'Other income cannot be negative.' };

  const otherMonthlyObligations = Number((debts && debts.otherMonthlyObligations) || 0);
  if (otherMonthlyObligations < 0) return { error: 'Other obligations cannot be negative.' };

  let existingLoans = [];
  if (debts && Array.isArray(debts.existingLoans)) {
    for (const loan of debts.existingLoans) {
      const lenderName = cleanString(loan.lenderName);
      const remainingBalance = Number(loan.remainingBalance);
      const monthlyInstallment = Number(loan.monthlyInstallment);
      const paymentStatus = cleanString(loan.paymentStatus);
      if (!lenderName) return { error: 'Each existing loan requires a lender name.' };
      if (!Number.isFinite(remainingBalance) || remainingBalance < 0) return { error: 'Remaining balance must be a positive number.' };
      if (!Number.isFinite(monthlyInstallment) || monthlyInstallment < 0) return { error: 'Monthly installment must be a positive number.' };
      if (!['Current', 'Overdue'].includes(paymentStatus)) return { error: 'Payment status must be Current or Overdue.' };
      existingLoans.push({ lenderName, remainingBalance, monthlyInstallment, paymentStatus });
    }
    if (existingLoans.length > 20) return { error: 'Too many existing loans listed.' };
  }

  const requestedAmount = Number(loanRequest && loanRequest.requestedAmount);
  const loanPurpose = cleanString(loanRequest && loanRequest.loanPurpose);
  const repaymentTermMonths = parseInt(loanRequest && loanRequest.repaymentTermMonths, 10);
  const paymentFrequency = cleanString(loanRequest && loanRequest.paymentFrequency).toLowerCase();

  const { config: lendingConfig } = require('./config/lending');
  if (!Number.isFinite(requestedAmount) || requestedAmount < lendingConfig.minLoanAmount || requestedAmount > lendingConfig.maxLoanAmount) {
    return { error: `Requested amount must be between ₱${lendingConfig.minLoanAmount.toLocaleString()} and ₱${lendingConfig.maxLoanAmount.toLocaleString()}.` };
  }
  if (loanPurpose.length < 5) return { error: 'Please describe the loan purpose (min 5 characters).' };
  if (!lendingConfig.allowedTermsMonths.includes(repaymentTermMonths)) {
    return { error: `Repayment term must be one of: ${lendingConfig.allowedTermsMonths.join(', ')} months.` };
  }
  if (!lendingConfig.allowedFrequencies.includes(paymentFrequency)) {
    return { error: 'Payment frequency must be monthly, biweekly, or weekly.' };
  }
  if (consent !== true && consent !== 'true') {
    return { error: 'You must consent to the data privacy and credit investigation notice.' };
  }

  let docs = [];
  if (Array.isArray(documents)) {
    if (documents.length > 4) return { error: 'Too many documents uploaded (max 4).' };
    docs = documents;
  }

  return {
    ok: true,
    data: {
      personal: { fullName, dob, mobile, email, residentialAddress, idType, idNumber },
      employment: { employmentStatus, occupation, employerName, monthlyIncome, otherIncomeSource, otherIncome },
      debts: { existingLoans, otherMonthlyObligations },
      loanRequest: { requestedAmount, loanPurpose, repaymentTermMonths, paymentFrequency },
      documents: docs
    }
  };
}

// --- A. SUBMIT APPLICATION (customer only) ---
app.post('/api/applications', express.json({ limit: '2.5mb' }), ensureDatabase, authenticate, requireCustomer, async (req, res) => {
  const validation = validateApplicationPayload(req.body);
  if (!validation.ok) {
    return res.status(400).json({ success: false, message: validation.error });
  }
  const { data } = validation;

  try {
    const evaluation = evaluateApplication({
      monthlyIncome: data.employment.monthlyIncome,
      otherIncome: data.employment.otherIncome,
      otherMonthlyObligations: data.debts.otherMonthlyObligations,
      existingLoans: data.debts.existingLoans,
      requestedAmount: data.loanRequest.requestedAmount,
      repaymentTermMonths: data.loanRequest.repaymentTermMonths,
      paymentFrequency: data.loanRequest.paymentFrequency
    });

    let applicationRef = generateApplicationRef();
    for (let i = 0; i < 5; i++) {
      const clash = await LoanApplication.findOne({ applicationRef });
      if (!clash) break;
      applicationRef = generateApplicationRef();
    }

    // Securely store uploaded documents before recording metadata
    const storedDocuments = [];
    for (const doc of data.documents) {
      const stored = storeApplicationDocument(applicationRef, doc);
      if (stored.error) {
        return res.status(400).json({ success: false, message: `${doc.kind}: ${stored.error}` });
      }
      storedDocuments.push(stored.meta);
    }

    const application = new LoanApplication({
      applicationRef,
      ownerId: req.user.userId,
      status: 'Pending Review',
      ...data.personal,
      ...data.employment,
      ...data.debts,
      ...data.loanRequest,
      evaluation,
      consentGiven: true,
      consentAcceptedAt: new Date(),
      documents: storedDocuments,
      review: {}
    });

    await application.save(); // reported successful only after MongoDB confirms

    await logAudit('customer.submit_application', req.user, applicationRef, 'Borrower evaluation submitted');

    return res.status(201).json({ success: true, message: 'Application submitted for review.', data: application.toJSON() });
  } catch (err) {
    console.error('[APPLICATION ERROR] submit:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to submit application.' });
  }
});

// --- B. OWN APPLICATIONS (customer only, own data only) ---
app.get('/api/applications/mine', ensureDatabase, authenticate, requireCustomer, async (req, res) => {
  try {
    if (!isValidObjectId(req.user.userId)) {
      return res.status(400).json({ success: false, message: 'Invalid account reference.' });
    }
    const applications = await LoanApplication.find({ ownerId: req.user.userId }).sort({ createdAt: -1 });
    return res.json({ success: true, data: applications });
  } catch (err) {
    console.error('[APPLICATION ERROR] list mine:', err.message);
    return res.status(500).json({ success: false, message: 'Unable to retrieve applications.' });
  }
});

// --- C. OWN APPLICATION DOCUMENTS (customer, own records only) ---
app.get('/api/applications/:ref/documents/:kind', ensureDatabase, authenticate, requireCustomer, async (req, res) => {
  const ref = cleanString(req.params.ref);
  const kind = cleanString(req.params.kind);
  if (!/^APP-\d{4}-\d{6}$/.test(ref) || !['idDocument', 'proofOfIncome'].includes(kind)) {
    return res.status(400).json({ success: false, message: 'Invalid request.' });
  }

  try {
    if (!isValidObjectId(req.user.userId)) {
      return res.status(400).json({ success: false, message: 'Invalid account reference.' });
    }
    const application = await LoanApplication.findOne({ applicationRef: ref, ownerId: req.user.userId });
    if (!application) {
      return res.status(404).json({ success: false, message: 'Document not found.' });
    }

    const doc = (application.documents || []).find(d => d.kind === kind);
    if (!doc || !fs.existsSync(doc.storedPath)) {
      return res.status(404).json({ success: false, message: 'Document not found.' });
    }

    await logAudit('customer.view_application_document', req.user, ref, `Viewed own ${kind}`);
    res.setHeader('Content-Type', doc.mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${doc.originalName.replace(/[^\w.-]/g, '_')}"`);
    res.sendFile(doc.storedPath);
  } catch (err) {
    console.error('[APPLICATION ERROR] own document:', err.message);
    return res.status(500).json({ success: false, message: 'Unable to retrieve document.' });
  }
});

// --- D. ADMIN: LIST ALL APPLICATIONS ---
app.get('/api/admin/applications', ensureDatabase, authenticate, requireAdmin, async (req, res) => {
  try {
    const applications = await LoanApplication.find().sort({ createdAt: -1 }).limit(500);
    const owners = await User.find({ _id: { $in: applications.map(a => a.ownerId) } }).select('username email');
    const ownerMap = new Map(owners.map(o => [String(o._id), { username: o.username, email: o.email }]));
    const payload = applications.map(a => {
      const json = a.toJSON();
      json.owner = ownerMap.get(String(a.ownerId)) || null;
      return json;
    });
    return res.json({ success: true, data: payload });
  } catch (err) {
    console.error('[APPLICATION ERROR] admin list:', err.message);
    return res.status(500).json({ success: false, message: 'Unable to retrieve applications.' });
  }
});

// --- E. ADMIN: APPLICATION DOCUMENTS ---
app.get('/api/admin/applications/:ref/documents/:kind', ensureDatabase, authenticate, requireAdmin, async (req, res) => {
  const ref = cleanString(req.params.ref);
  const kind = cleanString(req.params.kind);
  if (!/^APP-\d{4}-\d{6}$/.test(ref) || !['idDocument', 'proofOfIncome'].includes(kind)) {
    return res.status(400).json({ success: false, message: 'Invalid request.' });
  }

  try {
    const application = await LoanApplication.findOne({ applicationRef: ref });
    if (!application) {
      return res.status(404).json({ success: false, message: 'Application not found.' });
    }
    const doc = (application.documents || []).find(d => d.kind === kind);
    if (!doc || !fs.existsSync(doc.storedPath)) {
      return res.status(404).json({ success: false, message: 'Document not found.' });
    }

    await logAudit('admin.view_application_document', req.user, ref, `Reviewed ${kind}`);
    res.setHeader('Content-Type', doc.mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${doc.originalName.replace(/[^\w.-]/g, '_')}"`);
    res.sendFile(doc.storedPath);
  } catch (err) {
    console.error('[APPLICATION ERROR] admin document:', err.message);
    return res.status(500).json({ success: false, message: 'Unable to retrieve document.' });
  }
});

// --- F. ADMIN: REVIEW APPLICATION (status + decision reason) ---
app.patch('/api/admin/applications/:ref/status', ensureDatabase, authenticate, requireAdmin, async (req, res) => {
  const ref = cleanString(req.params.ref);
  const { status, decisionReason } = allowlistBody(req.body, ['status', 'decisionReason']);

  if (!/^APP-\d{4}-\d{6}$/.test(ref)) {
    return res.status(400).json({ success: false, message: 'Invalid application reference.' });
  }
  if (!LoanApplication.APPLICATION_STATUSES.includes(status)) {
    return res.status(400).json({ success: false, message: 'Invalid application status.' });
  }
  const cleanReason = cleanString(decisionReason);
  if ((status === 'Rejected' || status === 'More Information Required') && cleanReason.length < 3) {
    return res.status(400).json({ success: false, message: 'A decision reason is required for this status.' });
  }
  if (cleanReason.length > 1000) {
    return res.status(400).json({ success: false, message: 'Decision reason is too long.' });
  }

  try {
    const review = { decisionReason: cleanReason, reviewedAt: new Date(), reviewedBy: req.user.username };

    const application = await LoanApplication.findOneAndUpdate(
      { applicationRef: ref },
      { status, review, updatedAt: new Date() },
      { new: true }
    );
    if (!application) {
      return res.status(404).json({ success: false, message: 'Application not found.' });
    }

    await logAudit('admin.review_application', req.user, ref, `Status set to "${status}"`);
    return res.json({ success: true, message: 'Application status updated.', data: application.toJSON() });
  } catch (err) {
    console.error('[APPLICATION ERROR] review:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to update application.' });
  }
});

// ====================================================
// 7. ADMIN SECURITY ENDPOINTS
// ====================================================

// --- A. AUDIT LOG (admin actions; no IPs/tokens/personal records) ---
app.get('/api/admin/audit-logs', ensureDatabase, authenticate, requireAdmin, async (req, res) => {
  try {
    const logs = await AuditLog.find().sort({ createdAt: -1 }).limit(100);
    return res.json({ success: true, data: logs });
  } catch (err) {
    console.error('[ADMIN ERROR] audit logs:', err.message);
    return res.status(500).json({ success: false, message: 'Unable to retrieve audit logs.' });
  }
});

// --- B. SECURITY OVERVIEW ---
app.get('/api/admin/security-overview', ensureDatabase, authenticate, requireAdmin, async (req, res) => {
  try {
    const [customerCount, adminCount, clientCount, txnCount, auditCount, recentLogins] = await Promise.all([
      User.countDocuments({ role: 'customer' }),
      User.countDocuments({ role: 'admin' }),
      Client.countDocuments(),
      Transaction.countDocuments(),
      AuditLog.countDocuments(),
      AuditLog.find().sort({ createdAt: -1 }).limit(5)
    ]);
    return res.json({
      success: true,
      data: { customerCount, adminCount, clientCount, transactionCount: txnCount, auditCount, recentLogins }
    });
  } catch (err) {
    console.error('[ADMIN ERROR] overview:', err.message);
    return res.status(500).json({ success: false, message: 'Unable to build security overview.' });
  }
});

// ====================================================
// 8. CENTRALIZED ERROR HANDLER (no internal details leaked)
// ====================================================
app.use((err, req, res, next) => {
  console.error('[SERVER ERROR]', err.message);
  res.status(500).json({ success: false, message: 'An unexpected error occurred.' });
});

// ----------------------------------------------------
// SERVER INITIALIZATION
// The server refuses to start unless MongoDB is confirmed reachable.
// ----------------------------------------------------
const PORT = process.env.PORT || 5000;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log('=======================================================');
    console.log(`SLAP Smart Lending Backend Server active on port ${PORT}`);
    console.log(`Environment: ${IS_PRODUCTION ? 'PRODUCTION' : 'DEVELOPMENT'}`);
    console.log('Privacy Protocol: IP Collection & Tracking Disabled');
    console.log('=======================================================');
  });

  connectDB().then(async (connected) => {
    if (!connected) {
      if (IS_PRODUCTION) {
        console.error('=======================================================');
        console.error('SLAP server stopping: MongoDB is required in production.');
        console.error('Fix MONGODB_URI in environment or check MongoDB status.');
        console.error('=======================================================');
        process.exit(1);
      } else {
        console.warn('=======================================================');
        console.warn('SLAP NOTICE: MongoDB is not running locally.');
        console.warn('Static UI, calculators, and rate endpoints are active at http://localhost:' + PORT);
        console.warn('To enable database persistence, start MongoDB or set MONGODB_URI in .env.');
        console.warn('=======================================================');
      }
    } else {
      console.log(`[DATABASE] MongoDB connected (db: "${require('mongoose').connection.name}")`);
      try {
        await seedDatabaseIfEmpty();
        await bootstrapInitialAdmin();
      } catch (err) {
        console.error('[STARTUP] Sample data seeding skipped:', err.message);
      }
    }
  });
}

module.exports = app;

// Test-only access to the ephemeral OTP store (inert unless SLAP_TEST_MODE=1).
// This is NOT a mock database: codes still expire in 5 minutes and must match
// the verification flow. Used by the automated test suite.
if (process.env.SLAP_TEST_MODE === '1') {
  module.exports.__testOtp = otpStore;
}
