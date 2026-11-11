# TEST CREDENTIALS

**File:** TEST_CREDENTIALS.md
**Project:** Smart Lending Application (SLAP)
**Purpose:** Dedicated customer test account for verifying customer-side features
**Created:** 2026-11-09
**Environment:** Development only — never use in production

---

## Dedicated Customer Test Account

| Field | Value |
|-------|-------|
| Name | Maria Santos |
| Email | `maria.santos@smartlend.test` |
| Password | `SmartLendTest123!` |
| Username | `maria.santos.test` |
| Role | `customer` |
| Mobile | `09171234567` |
| ID Type | PhilSys National ID |
| ID Number | `TEST-1234-5678-9012` |
| Address | 123 Rizal Street, Barangay 1, Quezon City, Metro Manila |
| Employment | Employed — Sari-sari Store Owner (Self-Employed) |
| Monthly Income | ₱30,000 |

---

## Sample Records (pre-seeded)

| Record Type | Reference | Status |
|-------------|-----------|--------|
| Loan Application | `TEST-APP-0001` | Pending Review |
| Client Loan | `TEST-CL-0001` | Active |
| Payment | `TEST-TXN-0001` | Confirmed (GCash) |

---

## How to Create/Refresh This Account

```bash
# Create the account (skips if already exists)
node scripts/seed-customer-test-account.js

# Remove and recreate the account
node scripts/seed-customer-test-account.js --reset
node scripts/seed-customer-test-account.js
```

The seeder script (`scripts/seed-customer-test-account.js`):
- Is repeatable: running it again will skip existing records (no duplicates)
- Hashes passwords via bcrypt (12 rounds) through the User model pre-save hook
- Assigns the `customer` role (not admin)
- Creates sample loan application, client loan, and payment records
- Refuses to run when `NODE_ENV=production`

---

## What This Account Can Access

- Customer dashboard (`Dashboard/client.html`)
- Customer profile (read/update)
- My loan records (`/api/customer/loans`)
- Payment history (`/api/customer/payments`)
- My applications (`/api/applications/mine`)
- Submit new loan applications (`/api/applications`)
- Download own application documents

---

## What This Account CANNOT Access (Verified)

- Admin dashboard (`Dashboard/dashboard.html`) — returns 403
- Admin client management (`/api/clients`) — returns 403
- Admin transaction management — returns 403
- Admin audit logs (`/api/admin/audit-logs`) — returns 403
- Admin security overview (`/api/admin/security-overview`) — returns 403
- Admin login endpoint (`/api/admin/login`) — returns 401
- Application review/approval APIs (`/api/admin/applications/*/status`) — returns 403

Role-based access control is enforced server-side on every protected endpoint.

---

## Security Notes

- Password is hashed with bcrypt (12 rounds) — never stored as plain text
- This account was created using the same authentication system as production
- No production credentials are hardcoded in this file
- This account is for development/testing only
- The account email domain (`@smartlend.test`) is clearly a test domain
