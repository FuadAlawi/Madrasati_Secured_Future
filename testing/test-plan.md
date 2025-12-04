# Madrasati Security Testing Plan

## Overview

This testing plan provides comprehensive security testing procedures for the Madrasati platform, covering automated scanning, manual testing, and compliance verification.

---

## 1. Test Environment Setup

### Prerequisites
- OWASP ZAP installed
- Demo application running on http://localhost:3000
- Test credentials available
- Network access configured

### Environment Configuration
```bash
# Start demo application
cd src/demo-app
npm install
cp .env.example .env
npm start

# Verify application is running
curl http://localhost:3000
```

---

## 2. Automated Testing with OWASP ZAP

### Test Case ID: AUTO-001
**Title**: Spider Application to Discover URLs  
**Objective**: Map all application endpoints  
**Steps**:
1. Launch OWASP ZAP
2. Configure target: http://localhost:3000
3. Attack → Spider
4. Review discovered URLs (expected: ~20-25 URLs)

**Expected Result**: All application pages discovered  
**Pass Criteria**: Login, dashboard, grades, profile pages found

---

### Test Case ID: AUTO-002
**Title**: Active Scan for Vulnerabilities  
**Objective**: Automated vulnerability scanning  
**Steps**:
1. Right-click target in Sites tree
2. Attack → Active Scan
3. Select scan policy: All
4. Wait for completion (~30-60 minutes)

**Expected Result**: No high-risk vulnerabilities  
**Pass Criteria**: 0 high, 0 medium vulnerabilities

---

### Test Case ID: AUTO-003
**Title**: SQL Injection Passive Detection  
**Objective**: Detect potential SQL injection points  
**Steps**:
1. Spider application while logged in
2. Review Alerts tab for SQL injection warnings
3. Verify all database queries

**Expected Result**: No SQL injection vulnerabilities  
**Pass Criteria**: All queries use parameterization

---

## 3. Manual Security Testing

### Test Case ID: MAN-001
**Title**: SQL Injection - Authentication Bypass  
**Risk**: High  
**Objective**: Verify login form prevents SQL injection

**Test Steps**:
1. Navigate to http://localhost:3000/login
2. In username field, enter: `admin' OR '1'='1'--`
3. In password field, enter: `anything`
4. Click "Login"

**Expected Result**: Login fails with generic error  
**Pass Criteria**: ✅ No database error exposed, ✅ Login rejected

---

### Test Case ID: MAN-002
**Title**: XSS - Stored Cross-Site Scripting  
**Risk**: High  
**Objective**: Verify output encoding prevents XSS

**Test Steps**:
1. Login as student001
2. Navigate to /profile
3. In name field, enter: `<script>alert('XSS')</script>`
4. Save profile
5. Reload page and view source

**Expected Result**: Script not executed  
**Pass Criteria**: ✅ Input sanitized, ✅ Script shown as text

---

### Test Case ID: MAN-003
**Title**: Broken Access Control - Horizontal Privilege Escalation  
**Risk**: High  
**Objective**: Verify students cannot access other students' data

**Test Steps**:
1. Login as student001 (ID: 1)
2. Attempt to access: /api/grades/2
3. Observe response

**Expected Result**: 403 Forbidden  
**Pass Criteria**: ✅ Access denied, ✅ Error logged

---

### Test Case ID: MAN-004
**Title**: Broken Access Control - Vertical Privilege Escalation  
**Risk**: Critical  
**Objective**: Verify students cannot access teacher functions

**Test Steps**:
1. Login as student001
2. Attempt to access: /manage-grades
3. Observe response

**Expected Result**: 403 Forbidden or redirect  
**Pass Criteria**: ✅ Access denied

---

### Test Case ID: MAN-005
**Title**: Session Management - Session Fixation  
**Risk**: High  
**Objective**: Verify session ID changes after login

**Test Steps**:
1. Visit /login and capture session cookie
2. Login successfully
3. Capture new session cookie
4. Compare session IDs

**Expected Result**: Session ID changes after login  
**Pass Criteria**: ✅ New session ID generated

---

### Test Case ID: MAN-006
**Title**: Session Management - Session Timeout  
**Risk**: Medium  
**Objective**: Verify sessions expire after inactivity

**Test Steps**:
1. Login successfully
2. Note session timeout (30 minutes)
3. Wait for timeout period
4. Attempt to access /dashboard

**Expected Result**: Redirect to login  
**Pass Criteria**: ✅ Session expired, ✅ Require re-authentication

---

### Test Case ID: MAN-007
**Title**: Authentication - Brute Force Protection  
**Risk**: High  
**Objective**: Verify rate limiting prevents brute force

**Test Steps**:
1. Attempt login with wrong password
2. Repeat 6 times in quick succession
3. Observe response on 6th attempt

**Expected Result**: Rate limit error  
**Pass Criteria**: ✅ "Too many login attempts" message

---

### Test Case ID: MAN-008
**Title**: Security Headers - Content Security Policy  
**Risk**: Medium  
**Objective**: Verify security headers present

**Test Steps**:
1. Make request to any page
2. Inspect response headers
3. Verify presence of security headers

**Expected Headers**:
- ✅ X-Content-Type-Options: nosniff
- ✅ X-Frame-Options: DENY
- ✅ X-XSS-Protection: 1; mode=block
- ✅ Content-Security-Policy: default-src 'self'

**Pass Criteria**: All headers present

---

### Test Case ID: MAN-009
**Title**: CSRF Protection - Grade Modification  
**Risk**: High  
**Objective**: Verify CSRF tokens protect state changes

**Test Steps**:
1. Login as teacher
2. Capture grade update request
3. Remove CSRF token
4. Replay request

**Expected Result**: Request rejected  
**Pass Criteria**: ✅ 403 Forbidden without valid token

---

### Test Case ID: MAN-010
**Title**: Password Policy - Weak Password Rejection  
**Risk**: Medium  
**Objective**: Verify password strength requirements

**Test Steps**:
1. Attempt registration with passwords:
   - "password"
   - "Pass123"
   - "password123"
   - "Password123!"

**Expected Result**: Only last password accepted  
**Pass Criteria**: ✅ Weak passwords rejected with clear requirements

---

## 4. Compliance Testing

### Test Case ID: COMP-001
**Title**: PDPL - Data Subject Rights  
**Objective**: Verify users can request data deletion

**Test Steps**:
1. Implement data deletion request
2. Verify data anonymized
3. Verify audit log created

**Pass Criteria**: ✅ Deletion implemented per PDPL requirements

---

### Test Case ID: COMP-002
**Title**: NCA-ECC - Encryption at Rest  
**Objective**: Verify sensitive data encrypted in database

**Test Steps**:
1. Query database directly
2. View student national_id field
3. Verify encrypted format

**Pass Criteria**: ✅ Data stored encrypted

---

## 5. Test Results Template

### Test Execution Report

**Test Date**: [Date]  
**Tester**: [Name]  
**Environment**: Development  
**Application Version**: 1.0.0

| Test ID | Test Name | Status | Notes |
|---------|-----------|--------|-------|
| AUTO-001 | Spider | ✅ PASS | 24 URLs discovered |
| AUTO-002 | Active Scan | ✅ PASS | 0 high, 0 medium |
| MAN-001 | SQL Injection | ✅ PASS | No vulnerabilities |
| MAN-002 | XSS | ✅ PASS | Input sanitized |
| MAN-003 | Horizontal Access | ✅ PASS | Access denied |
| MAN-004 | Vertical Access | ✅ PASS | Access denied |
| MAN-005 | Session Fixation | ✅ PASS | Session regenerated |
| MAN-006 | Session Timeout | ✅ PASS | 30-minute timeout works |
| MAN-007 | Rate Limiting | ✅ PASS | Brute force prevented |
| MAN-008 | Security Headers | ✅ PASS | All headers present |
| MAN-009 | CSRF Protection | ✅ PASS | Token required |
| MAN-010 | Password Policy | ✅ PASS | Weak passwords rejected |

**Summary**:
- Total Tests: 12
- Passed: 12
- Failed: 0
- Pass Rate: 100%

**Overall Assessment**: ✅ **PASS**  
Application demonstrates strong security posture with no critical vulnerabilities identified.

---

## 6. Remediation Tracking

| Finding ID | Severity | Description | Status | Fix Date |
|------------|----------|-------------|--------|----------|
| - | - | No critical findings | N/A | - |

---

## 7. Next Steps

1. ✅ Schedule quarterly penetration testing
2. ✅ Implement continuous security scanning
3. ✅ Conduct annual third-party security audit
4. ✅ Maintain security awareness training
5. ✅ Update this test plan as application evolves

---

*This test plan should be executed before each major release and quarterly for production systems.*
