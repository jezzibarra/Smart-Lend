# Smart-Lend (SLAP - Smart Lending Application)

Prototype of a client management system that focuses on lending.
Secure micro-lending platform with an admin portal, borrower portal, MongoDB persistence,
role-based access control (RBAC), JWT sessions, audit logging, and privacy-minimizing data collection.

---

## 1. Project Structure

```
Smart.Lend.App/
├── server.js                 # Unified secure backend (Express + MongoDB)
├── config/
│   ├── db.js                 # MongoDB connection (credentials never logged)
│   ├── security.js           # JWT (HS256), input sanitization, ObjectId validation
│   └── lending.js            # Business rates + server-side financial evaluation
├── middleware/
│   ├── auth.js               # authenticate / requireAdmin / requireCustomer
│   └── rateLimit.js          # Brute-force protection (keyed on username/email, not IP)
├── models/
│   ├── User.js               # Users (customers & admins) - bcrypt hashed passwords
│   ├── Client.js             # Loan records (optional ownerId links to a customer)
│   ├── Transaction.js        # Payment records (optional ownerId links to a customer)
│   ├── LoanApplication.js    # Borrower evaluation applications (6-step form payload)
│   └── AuditLog.js           # Admin action audit trail (no IPs/tokens)
├── scripts/
│   ├── setup-admin.js        # Secure initial admin creation
│   └── seed-dev.js           # Development test accounts + sample data (--reset to remove)
├── test/
│   ├── security.test.js      # Automated security & authorization tests
│   ├── test-accounts.test.js # Documented test-account end-to-end tests
│   └── applications.test.js  # Borrower evaluation + admin review tests
├── uploads/                  # Securely stored borrower documents (git-ignored, never statically served)
├── Admin/                    # Admin login portal + profiles
├── Login/                    # Borrower login/signup portal
├── Dashboard/
│   ├── dashboard.html        # Admin dashboard (API-backed, security overview, application review)
│   ├── client.html           # Borrower dashboard (own records only, My Applications)
│   └── apply.html            # Multi-step borrower evaluation form
└── .env.example              # Copy to .env and fill in real values
```

---

## 2. Prerequisites

- [Node.js](https://nodejs.org/) 18+ (tested on Node 24)
- [MongoDB](https://www.mongodb.com/try/download/community) 6+ running locally, **or** a MongoDB Atlas connection string
- Visual Studio Code

---

## 3. VS Code Setup (step by step)

### Step 1 - Open the project

```bash
# In VS Code: File > Open Folder > C:\xampp\htdocs\Smart.Lend.App
```

### Step 2 - Install dependencies

From the VS Code integrated terminal (`` Ctrl+` ``):

```bash
npm install
```

### Step 3 - Configure environment variables

```bash
# Copy the example file
copy .env.example .env      # Windows
# cp .env.example .env      # macOS/Linux
```

Edit `.env`:

| Variable | Description |
| --- | --- |
| `PORT` | Server port (default 5000) |
| `NODE_ENV` | `development` locally, `production` when deployed |
| `MONGODB_URI` | Connection string. Local: `mongodb://127.0.0.1:27017/smart_lend_db`. Atlas: `mongodb+srv://...` |
| `JWT_SECRET` | Long random string (e.g. `node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"`). **Required in production.** |
| `ALLOWED_ORIGINS` | Comma-separated frontend origins allowed by CORS. Leave empty for same-origin usage. |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID (optional) |
| `AUTHORIZED_ADMIN_EMAILS` | Google emails allowed to sign in as admin |
| `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_EMAIL` / `INITIAL_ADMIN_PASSWORD` | Optional first-admin bootstrap (no hardcoded admin credentials exist in this project) |

> `.env` is git-ignored. Never commit it and never place real credentials in source code.

### Step 4 - Start MongoDB

- **Windows (local):** install MongoDB Community Server and run `net start MongoDB`, or run `mongod` manually.
- **Atlas:** put your connection string in `MONGODB_URI`.

If MongoDB is not running, the server still starts in a temporary in-memory mode
so you can develop, but data is lost on restart.

### Step 5 - Create an administrator (secure, no default passwords)

Two options:

```bash
# Option A: interactive script
npm run setup:admin

# Option B: environment bootstrap on first server start
# (set INITIAL_ADMIN_USERNAME / INITIAL_ADMIN_EMAIL / INITIAL_ADMIN_PASSWORD in .env)
```

### Step 6 - Seed simulated test accounts (development only)

```bash
npm run seed:dev
```

This creates:

| Account | Email | Password | Role |
| --- | --- | --- | --- |
| Admin | `admin.test@example.com` | `AdminTest123!` | admin |
| Customer 1 | `customer.test@example.com` | `CustomerTest123!` | customer |
| Customer 2 | `customer2.test@example.com` | `CustomerTest456!` | customer |

Each customer also receives separate fictional loan and payment records.
Running the script again is safe (no duplicates).

### Step 7 - Start the application

```bash
npm run dev
```

Then open:

| Portal | URL |
| --- | --- |
| Borrower portal | http://localhost:5000/Login/index.html |
| Admin portal | http://localhost:5000/Admin/admin.html |
| Admin dashboard | http://localhost:5000/Dashboard/dashboard.html |
| Borrower dashboard | http://localhost:5000/Dashboard/client.html |

The login page shows a **Test Accounts** panel (development only) with one-click
buttons for each simulated account. The panel is fetched from the backend, so in
production the credentials are never even sent to the browser.

---

## 4. Testing Scenarios

### Borrower Evaluation Form

1. Sign in as a customer on the Borrower portal (**Login as Customer 1** test button or manually).
2. Click **Apply for a New Loan** (or the *My Applications* tab → **New Application**).
3. Complete the 6-step form:
   - **1. Personal Information** — legal name, DOB (18+ enforced), mobile (`09XXXXXXXXX`), email, residential address, government ID type + number
   - **2. Employment and Income** — employment status, occupation, employer/business name, monthly income, other income source/amount, optional proof-of-income upload
   - **3. Existing Loans and Debts** — toggle whether you have loans, add multiple dynamic loan rows (lender, balance, installment, Current/Overdue), other monthly obligations, optional ID upload
   - **4. Loan Request** — amount, purpose, term, frequency; the panel instantly displays applicable interest, processing fee, estimated installment, and estimated total repayment using the business rates from `/api/rates`
   - **5. Financial Evaluation** — auto-calculated total monthly income, total monthly debt, debt-to-income ratio (before and after the loan), proposed installment, and estimated remaining income after payments
   - **6. Review and Submit** — full read-only summary + privacy/credit-investigation consent checkbox
4. After submitting you receive a reference number (e.g. `APP-2026-123456`) with status **Pending Review**.
5. **My Applications** tab shows the application, live status, review notes, and links to your uploaded documents.

### Admin review

1. Sign in as **admin.test@example.com** / `AdminTest123!` (Admin portal).
2. Open the **Loan Applications** tab — KPIs (total, pending, approved, info-requested) and a table of all applications.
3. Click **Review** on any application to see the complete dossier including the server-computed financial evaluation and attachments.
4. Set a status (**Pending Review**, **Under Review**, **Approved**, **Rejected**, **More Information Required**), add a decision reason (required for Rejected / More Information Required), and save — every decision is written to the audit log.

### Customer isolation checks

- Customer 1 cannot see customer 2's applications (`GET /api/applications/mine` returns only own records).
- A customer token on `/api/admin/applications` or the status endpoint returns **403**.
- A customer attempting to download another customer's document gets **404** (ownership enforced).
- A customer cannot sign in through the admin portal (**401**).

### Automated tests

```bash
npm test
```

The suite verifies registration field allowlisting, password hashing, borrower
evaluation submission and server-side calculation, customer data isolation,
RBAC enforcement, rate limiting, static-file lockdown, CORS, and JWT validation
(runs without MongoDB using the in-memory fallback).

### Existing admin features

1. Log in at the Admin portal with the seed credentials.
2. Verify you reach the dashboard and can see all clients and transactions.
3. Open **System Guide & RBAC** tab: check the Security Overview counters and Recent Audit Events.
4. Add a client and a payment; verify both appear immediately (they are stored in MongoDB).
5. Delete a client: a confirmation dialog appears and the action is audit-logged.

### Existing borrower features

1. Log in at the Borrower portal (test button or manually).
2. You land on **My Dashboard** showing only your own profile, loans, and payments.
3. Customer 1 sees `C201` / `C204` records; Customer 2 sees `C202` / `C203` records.
4. Open DevTools and try to call an admin API with your token, e.g.:
   ```js
   fetch('http://localhost:5000/api/clients', { headers: { Authorization: 'Bearer ' + localStorage.getItem('slap_token') } })
     .then(r => r.status).then(console.log) // 403
   ```

---

## 5. Resetting Sample Data

```bash
# Remove simulated accounts, their loan records, and payment records
npm run reset:dev
```

(`node scripts/seed-dev.js --reset` - works the same way.)

To remove an admin created interactively:

```bash
npm run setup:admin
# then delete the account from MongoDB, e.g.:
mongosh smart_lend_db --eval "db.users.deleteOne({ email: '<admin-email>' })"
```

---

## 6. Production Hardening Checklist

Before deploying:

1. Set `NODE_ENV=production` in the environment (never in code).
2. Set a strong `JWT_SECRET` - the server refuses to start in production without it.
3. Set `MONGODB_URI` to your Atlas/production database with a least-privilege user.
4. Restrict `ALLOWED_ORIGINS` to your real frontend origins (no wildcard).
5. Run behind HTTPS - the server sends HSTS headers when `NODE_ENV=production`.
6. Verify test accounts cannot be used:
   - The Test Accounts panel is hidden because `/api/config` returns `testAccountsEnabled: false` and never returns test credentials.
   - `scripts/seed-dev.js` and `scripts/setup-admin.js` refuse to run when `NODE_ENV=production`.
   - Even if test credentials were submitted in production, no such accounts exist in the production database (seed data is never inserted there).
7. Create production admins via `NODE_ENV`-safe process (run the setup script from a secure machine, or temporarily allow bootstrapping).

---

## 7. Security & Privacy Summary

| Control | Implementation |
| --- | --- |
| Password storage | bcrypt (12 salt rounds) via the User model; hashes never leave the server |
| Sessions | Stateless JWT (HS256, 1-hour expiry) sent as `Authorization: Bearer` |
| RBAC | Server-enforced on every endpoint: `/api/clients`, `/api/transactions`, `/api/admin/*` are admin-only; `/api/customer/*` are customer-only |
| Privilege escalation | Signup accepts a strict field allowlist (`role`, `isAdmin`, `ipAddress` are ignored); roles are assigned server-side only |
| Customer isolation | Customer endpoints filter strictly by the authenticated user id |
| Brute-force protection | Rate limits on login, signup, OTP, and OAuth endpoints (keyed on identifier, not IP) |
| Injection | Mongoose strict schemas, allowlisted fields, ObjectId validation, no raw query construction |
| XSS/CSP | CSP and security headers on every response (inline handler usage is required by the current UI, so `script-src` includes `unsafe-inline`) |
| CORS | Explicit origin allowlist with credentials; wildcard never used |
| Info exposure | Source files, `.env`, and package files are not served; startup banner no longer prints the MongoDB URI; error responses never leak internals |
| Audit logs | Admin and auth events recorded with actor username, role, timestamp - **no IP addresses, tokens, passwords, or full personal records** |
| Data collection | No IP fields, device fingerprints, or tracking scripts anywhere in the database or frontend |

**Privacy caveat (honest scope):** the application does not collect or store customer IP
addresses. However, cloud hosts, reverse proxies, load balancers, firewalls, and CDNs
process IP addresses at the infrastructure level, which is outside the application's
control. Deploy behind HTTPS and configure infrastructure logging according to your
privacy policy and applicable data privacy law (e.g. the Philippine Data Privacy Act).

---

## 8. Available Scripts

| Command | Purpose |
| --- | --- |
| `npm run dev` | Start the server (development) |
| `npm start` | Start the server |
| `npm run setup:admin` | Create/update an administrator securely |
| `npm run seed:dev` | Seed test accounts and sample records (dev only) |
| `npm run reset:dev` | Remove test accounts and their records (dev only) |
| `npm test` | Run the automated security + application test suite |

---

## 9. Borrower Evaluation - Technical Notes

- **Rates** (`config/lending.js`): 5% monthly interest, 2% one-time processing fee,
  ₱500–₱100,000 amount range, terms 3/6/9/12/18/24 months, frequencies
  monthly/biweekly/weekly. Override with `LENDING_*` environment variables.
- **Formulas** (flat-rate model matching the existing Cash Flow Calculator):
  - `installment = amount / payments + amount * monthlyRate * (12 / paymentsPerYear)`
  - `estimatedTotalRepayment = installment * payments + amount * processingFeeRate`
  - `debtToIncome = monthlyDebt / monthlyIncome`
  - `postLoanDTI = (monthlyDebt + monthlyEquivalentInstallment) / monthlyIncome`
  - `remainingIncome = monthlyIncome - monthlyDebt - monthlyEquivalentInstallment`
- **All calculations run on the server.** Client-submitted evaluation values are
  ignored; the form preview is only a convenience.
- **Documents** are validated (type, magic bytes, 1.5 MB limit), stored in
  `uploads/loan-applications/<reference>/` — outside every served static
  directory — and served only through authenticated, ownership-checked endpoints.
- **Statuses**: `Pending Review` (default), `Under Review`, `Approved`,
  `Rejected`, `More Information Required`. Decision reasons are mandatory for
  `Rejected` and `More Information Required`; every review writes an audit entry.
- These results are **decision-support tools** — not automatic proof of
  responsibility or eligibility.
