# REPAIR CHECKLIST

**Project:** Smart Lending Application (SLAP)
**Status legend:** Pending | In Progress | Completed | Blocked

---

## 1. Database and Backend
- [x] Completed — Remove hardcoded Google client ID / admin email defaults in `server.js`.
- [ ] Pending — Add unique index on `User.mobile` (`models/User.js`).
- [ ] Pending — Replace document-count ID generation with UUID/counter (`server.js` Client/Transaction creation).
- [ ] Pending — Add pagination to `/api/clients`, `/api/transactions`, audit logs, applications.
- [ ] Pending — Wire unused models (`Loan`, `Payment`, `RepaymentSchedule`, `Notification`) into endpoints or remove.
- [ ] Pending — Invoke repayment schedule generators in loan lifecycle.
- [ ] Pending — Fix duplicate declarations in `config/lending.js`.
- [ ] Pending — Document `--test-force-exit` / add `after` hooks for tests.

## 2. Authentication and Account Security
- [ ] Pending — Customer profile update must use allowlisted body fields only (`server.js`).
- [ ] Pending — Implement password reset flow.
- [ ] Pending — Persist account lockout beyond ephemeral rate limiter (or document limitation).
- [ ] Pending — Ensure `SLAP_TEST_MODE` cannot be enabled in production.
- [ ] Pending — Remove debug login scripts from root (`debug-login.js`, `test-login*.js`) after verification.

## 3. Admin Dashboard
- [ ] Pending — Verify document download route matches `Dashboard/client.html`.
- [ ] Pending — Add pagination/search to admin lists.
- [ ] Pending — Verify admin-only page/API access for customer accounts.

## 4. Customer Dashboard
- [ ] Pending — Verify "My Applications" status tracking and document download.
- [ ] Pending — Ensure customer cannot access admin pages/APIs (already enforced; verify).

## 5. Loan and Payment Management
- [ ] Pending — Implement loan lifecycle from approved application.
- [ ] Pending — Implement payment recording against loans.
- [ ] Pending — Generate and store repayment schedules.
- [ ] Pending — Add notification creation on status changes.

## 6. Customer Application and Ticket System
- [ ] Pending — Confirm server ignores client-submitted evaluation values (already does).
- [ ] Pending — Add ticket status lookup by reference (exists; verify).
- [ ] Pending — Add pagination to application lists.

## 7. Frontend and UI/UX
- [ ] Pending — Move inline handlers to external JS to allow stricter CSP (optional).
- [ ] Pending — Add ARIA landmarks and skip links.
- [ ] Pending — Improve keyboard accessibility of mobile sidebar.

## 8. Validation and Error Handling
- [ ] Pending — Standardize error responses.
- [ ] Pending — Add input validation for profile update fields.
- [ ] Pending — Ensure no stack traces leak in production.

## 9. Testing and Optimization
- [x] Completed — Fix `test/security.test.js`: double `BASE` prefix + duplicate test removal (line 101, line 283-290).
- [x] Completed — Fix `test/applications.test.js`: ownerId assertion + notEqual assertion.
- [x] Completed — Run full test suite with `--test-force-exit` (all 46 tests pass: 26 security + 7 test-accounts + 13 applications).
- [x] Completed — Create customer test account and `TEST_CREDENTIALS.md`.
- [x] Completed — Verify unauthorized access prevention (test-accounts.test.js confirms customers blocked from admin APIs).
- [ ] Pending — Verify mobile/desktop layouts.

---

### Task Execution Order (by priority)
1. CRITICAL: hardcoded secrets/defaults.
2. HIGH: test bug fix, unused models decision, customer test account.
3. MEDIUM: profile allowlist, ID generation, pagination, etc.
4. LOW: cleanup, accessibility, docs.
