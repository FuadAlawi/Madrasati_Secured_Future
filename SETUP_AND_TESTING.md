# Madrasati Demo Application - Setup & Testing Guide

## Quick Start

This guide helps you run the Madrasati demo application and perform security testing with OWASP ZAP.

---

## Prerequisites

Before you begin, ensure you have:

- **Node.js** (v16 or higher): [Download here](https://nodejs.org/)
- **OWASP ZAP**: [Download here](https://www.zaproxy.org/download/)
- **Git** (optional, for version control)

### Check Prerequisites

```bash
# Verify Node.js installation
node --version  # Should show v16.x.x or higher
npm --version   # Should show 8.x.x or higher

# Verify OWASP ZAP installation (macOS)
ls /Applications/ZAP.app  # Should exist
```

---

## Part 1: Running the Demo Application

### Step 1: Navigate to Demo App Directory

```bash
cd "/Users/fuadxxx/Desktop/Madrasati Secured Future/src/demo-app"
```

### Step 2: Install Dependencies

```bash
npm install
```

This will install:
- express (web framework)
- helmet (security headers)
- bcrypt (password hashing)
- jsonwebtoken (JWT tokens)
- express-rate-limit (rate limiting)
- And other security dependencies

**Expected output**: Installation of ~50 packages

### Step 3: Create Environment File

```bash
cp .env.example .env
```

The `.env` file contains:
```
NODE_ENV=development
PORT=3000
SESSION_SECRET=madrasati-demo-secret-please-change-in-production-32-chars-min
```

### Step 4: Start the Application

```bash
npm start
```

**Expected output**:
```
🚀 Madrasati Demo Application running on http://localhost:3000
   Environment: development

   Demo Credentials:
   Student: student001 / Student@123
   Teacher: teacher001 / Teacher@123
```

### Step 5: Test the Application in Browser

1. Open browser: http://localhost:3000
2. Click login or navigate to: http://localhost:3000/login
3. Test login with:
   - Username: `student001`
   - Password: `Student@123`
4. Explore the dashboard and features

**Available Routes**:
- `/` - Home page
- `/login` - Login page
- `/dashboard` - User dashboard (requires login)
- `/grades` - View grades (students only)
- `/manage-grades` - Manage grades (teachers only)
- `/profile` - User profile
- `/logout` - Logout

---

## Part 2: Security Testing with OWASP ZAP

### Step 1: Start OWASP ZAP

**macOS**:
```bash
open /Applications/ZAP.app
```

**Or from command line**:
```bash
/Applications/ZAP.app/Contents/Java/zap.sh
```

### Step 2: Configure ZAP Proxy

1. In ZAP, go to: **Tools → Options → Local Proxies**
2. Note the proxy settings (default: localhost:8080)
3. Leave ZAP running

### Step 3: Configure Browser Proxy (Firefox Recommended)

**Firefox**:
1. Open Firefox
2. Go to: **Preferences → General → Network Settings → Settings**
3. Select: **Manual proxy configuration**
4. HTTP Proxy: `localhost`
5. Port: `8080`
6. Check: **Also use this proxy for HTTPS**
7. Click **OK**

**Alternative**: Use ZAP's built-in browser (easier)
- In ZAP, click **Quick Start → Manual Explore**
- Enter URL: `http://localhost:3000`
- Click **Launch Browser**

### Step 4: Spider the Application (Discovery)

1. In ZAP, enter target: `http://localhost:3000`
2. Go to: **Attack → Spider**
3. Click **Start Scan**
4. **Important**: Login to the application during spidering:
   - Use: student001 / Student@123
   - Navigate through all pages
   - ZAP will record all URLs
5. Wait for spider to complete (~2-5 minutes)

**Expected Results**: ~20-25 URLs discovered

### Step 5: Active Scan (Vulnerability Testing)

1. In ZAP **Sites** tree, right-click on `http://localhost:3000`
2. Select: **Attack → Active Scan**
3. In the dialog:
   - Policy: Select **Default Policy** (or create custom)
   - Click **Start Scan**
4. Wait for scan to complete (~30-60 minutes depending on thoroughness)

**What ZAP Tests**:
- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Server vulnerabilities
- Security header checks
- Session management
- And 50+ more tests

### Step 6: Review Results

1. Click on **Alerts** tab
2. Review findings by risk level:
   - 🔴 **High**: Critical issues (should be 0)
   - 🟠 **Medium**: Important issues (should be 0)
   - 🟡 **Low**: Minor issues
   - ℹ️ **Informational**: Best practices

**Expected Results for Madrasati Demo**:
- High: 0
- Medium: 0
- Low: 2-3 (informational)
- Informational: 5-10

### Step 7: Generate Reports

1. Go to: **Report → Generate HTML Report**
2. Choose save location: `/Users/fuadxxx/Desktop/Madrasati Secured Future/testing/results/zap-report.html`
3. Also generate:
   - **Report → Generate XML Report** (for CI/CD integration)
   - **Report → Generate JSON Report** (for processing)

---

## Part 3: Manual Security Testing

### Test 1: SQL Injection Attack

**Objective**: Verify the application blocks SQL injection

**Steps**:
1. Go to login page: http://localhost:3000/login
2. In username field, enter: `admin' OR '1'='1'--`
3. In password field, enter: `anything`
4. Click "Login"

**Expected Result**: ✅ Login fails with generic error message  
**Pass Criteria**: No SQL error exposed, login rejected

---

### Test 2: Cross-Site Scripting (XSS)

**Objective**: Verify output encoding prevents XSS

**Steps**:
1. Login as: student001 / Student@123
2. Go to: http://localhost:3000/profile
3. In name field, enter: `<script>alert('XSS')</script>`
4. Click "Save"
5. Reload the page

**Expected Result**: ✅ Script not executed, shown as text  
**Pass Criteria**: Input sanitized, no popup appears

---

### Test 3: Authorization Bypass

**Objective**: Verify students cannot access teacher functions

**Steps**:
1. Login as: student001 / Student@123
2. Manually navigate to: http://localhost:3000/manage-grades
3. Observe the response

**Expected Result**: ✅ 403 Forbidden or redirect  
**Pass Criteria**: Access denied

---

### Test 4: Brute Force Protection

**Objective**: Verify rate limiting prevents brute force

**Steps**:
1. Logout if logged in
2. Attempt login with wrong password 6 times rapidly
3. Observe the response on 6th attempt

**Expected Result**: ✅ "Too many login attempts" message  
**Pass Criteria**: Account temporarily locked

---

### Test 5: Session Security

**Objective**: Verify session cookies are secure

**Steps**:
1. Login successfully
2. Open browser DevTools (F12)
3. Go to: **Application → Cookies → http://localhost:3000**
4. Inspect the session cookie

**Expected Attributes**:
- ✅ HttpOnly: true
- ✅ SameSite: Strict
- ⚠️ Secure: false (true only with HTTPS)

---

### Test 6: Security Headers

**Objective**: Verify presence of security headers

**Steps**:
1. Open browser DevTools (F12) → Network tab
2. Visit any page on the application
3. Click on the request
4. View **Response Headers**

**Expected Headers**:
```
✅ X-Content-Type-Options: nosniff
✅ X-Frame-Options: DENY
✅ X-XSS-Protection: 1; mode=block
✅ Content-Security-Policy: default-src 'self'...
✅ Referrer-Policy: strict-origin-when-cross-origin
```

---

## Part 4: Troubleshooting

### Application Won't Start

**Error**: Port 3000 already in use

**Solution**:
```bash
# Find and kill process using port 3000
lsof -ti:3000 | xargs kill -9

# Or use different port
PORT=3001 npm start
```

---

### Cannot Install Dependencies

**Error**: npm install fails

**Solution**:
```bash
# Clear npm cache
npm cache clean --force

# Delete node_modules and retry
rm -rf node_modules
npm install
```

---

### ZAP Cannot Connect

**Error**: ZAP shows connection errors

**Solution**:
1. Verify app is running: http://localhost:3000
2. Check ZAP proxy settings (localhost:8080)
3. Verify browser proxy configuration
4. Try ZAP's built-in browser instead

---

### Login Not Working

**Error**: "Invalid username or password"

**Solution**:
- Use exact credentials (case-sensitive):
  - Student: `student001` / `Student@123`
  - Teacher: `teacher001` / `Teacher@123`
- Check browser console for JavaScript errors

---

## Part 5: Next Steps

After completing testing:

1. **Document Results**:
   - Save ZAP HTML report to `testing/results/`
   - Take screenshots of key findings
   - Document any issues found

2. **Review Code**:
   - Examine secure code in `src/authentication/`
   - Review input validation in `src/data-protection/`
   - Study architecture in docs

3. **Prepare Report**:
   - Compile all documentation
   - Include test results
   - Add screenshots and diagrams
   - Generate PDF

4. **GitHub Repository** (Optional):
   ```bash
   cd "/Users/fuadxxx/Desktop/Madrasati Secured Future"
   git init
   git add .
   git commit -m "Initial commit: Madrasati Security Framework"
   git remote add origin YOUR_GITHUB_URL
   git push -u origin main
   ```

---

## Test Results Template

Use this template to document your findings:

```markdown
# Security Test Results - Madrasati Demo

**Test Date**: [Date]
**Tester**: [Name]
**Environment**: Development (localhost:3000)

## Automated Testing (OWASP ZAP)
- URLs Scanned: [Number]
- High Vulnerabilities: 0 ✅
- Medium Vulnerabilities: 0 ✅
- Low Findings: [Number]

## Manual Testing
- Test 1 - SQL Injection: PASS ✅
- Test 2 - XSS: PASS ✅
- Test 3 - Authorization: PASS ✅
- Test 4 - Brute Force: PASS ✅
- Test 5 - Session Security: PASS ✅
- Test 6 - Security Headers: PASS ✅

## Overall Assessment
**Status**: PASS ✅
**Recommendation**: Application demonstrates strong security posture
```

---

## Additional Resources

- **OWASP ZAP Documentation**: https://www.zaproxy.org/docs/
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **Node.js Security Best Practices**: https://nodejs.org/en/docs/guides/security/

---

**Happy Testing! 🔒**

For questions or issues, refer to the comprehensive documentation in the `docs/` directory.
