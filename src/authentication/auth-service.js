/**
 * Madrasati Authentication Service
 * Implements OAuth 2.0 with MFA and secure session management
 */

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { sendSMS } = require('../utils/sms-service');
const { AuditLogger } = require('../utils/audit-logger');

const SALT_ROUNDS = 12;
const MFA_CODE_EXPIRY = 5 * 60 * 1000; // 5 minutes
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

class AuthenticationService {
  
  /**
   * Register a new user with secure password hashing
   */
  async registerUser(userData) {
    try {
      // Validate input
      this.validateRegistrationData(userData);
      
      // Hash password with bcrypt
      const passwordHash = await bcrypt.hash(userData.password, SALT_ROUNDS);
      
      // Create user record
      const user = await db.users.create({
        username: userData.username,
        email: userData.email,
        password_hash: passwordHash,
        role: userData.role,
        school_id: userData.school_id,
        mobile_number: userData.mobile_number,
        is_active: true,
        created_at: new Date()
      });
      
      // Log registration
      await AuditLogger.log({
        event_type: 'user_registration',
        user_id: user.id,
        details: {
          username: user.username,
          role: user.role
        }
      });
      
      return {
        success: true,
        user_id: user.id,
        message: 'Registration successful'
      };
      
    } catch (error) {
      AuditLogger.log({
        event_type: 'registration_failed',
        details: { error: error.message }
      });
      throw error;
    }
  }
  
  /**
   * Authenticate user with username and password
   * Implements rate limiting and account lockout
   */
  async authenticateUser(username, password, ipAddress, userAgent) {
    try {
      // Check for account lockout
      const lockoutStatus = await this.checkAccountLockout(username);
      if (lockoutStatus.isLocked) {
        await AuditLogger.log({
          event_type: 'login_attempt_locked_account',
          username,
          ip_address: ipAddress,
          lockout_until: lockoutStatus.lockoutUntil
        });
        
        throw new Error(`Account locked. Try again in ${lockoutStatus.remainingMinutes} minutes`);
      }
      
      // Fetch user from database
      const user = await db.users.findOne({ 
        where: { username },
        attributes: ['id', 'username', 'password_hash', 'role', 'is_active', 'school_id', 'mobile_number']
      });
      
      if (!user) {
        // Generic error message to prevent username enumeration
        await this.recordFailedLogin(username, ipAddress, 'user_not_found');
        throw new Error('Invalid username or password');
      }
      
      // Check if account is active
      if (!user.is_active) {
        await AuditLogger.log({
          event_type: 'login_attempt_inactive_account',
          user_id: user.id,
          ip_address: ipAddress
        });
        throw new Error('Account is inactive. Please contact support.');
      }
      
      // Verify password
      const isPasswordValid = await bcrypt.compare(password, user.password_hash);
      
      if (!isPasswordValid) {
        await this.recordFailedLogin(username, ipAddress, 'invalid_password');
        
        // Check if account should be locked
        const failedAttempts = await this.getFailedLoginAttempts(username);
        if (failedAttempts >= MAX_LOGIN_ATTEMPTS) {
          await this.lockAccount(username);
          throw new Error(`Account locked due to too many failed attempts. Try again in 15 minutes.`);
        }
        
        const remainingAttempts = MAX_LOGIN_ATTEMPTS - failedAttempts;
        throw new Error(`Invalid username or password. ${remainingAttempts} attempts remaining.`);
      }
      
      // Clear failed login attempts
      await this.clearFailedLoginAttempts(username);
      
      // Generate MFA code
      const mfaCode = this.generateMFACode();
      const mfaToken = crypto.randomBytes(32).toString('hex');
      
      // Store MFA code temporarily (in Redis with expiry)
      await redis.setex(
        `mfa:${mfaToken}`,
        300, // 5 minutes
        JSON.stringify({
          user_id: user.id,
          code: mfaCode,
          username: user.username,
          role: user.role,
          school_id: user.school_id,
          created_at: Date.now()
        })
      );
      
      // Send MFA code via SMS
      await sendSMS(user.mobile_number, `Your Madrasati verification code is: ${mfaCode}. Valid for 5 minutes.`);
      
      // Log initial authentication success
      await AuditLogger.log({
        event_type: 'authentication_initial_success',
        user_id: user.id,
        username: user.username,
        ip_address: ipAddress,
        user_agent: userAgent,
        mfa_pending: true
      });
      
      return {
        success: true,
        mfa_required: true,
        mfa_token: mfaToken,
        message: 'MFA code sent to your mobile number'
      };
      
    } catch (error) {
      throw error;
    }
  }
  
  /**
   * Verify MFA code and issue JWT tokens
   */
  async verifyMFA(mfaToken, mfaCode, ipAddress, userAgent) {
    try {
      // Retrieve MFA data from Redis
      const mfaDataStr = await redis.get(`mfa:${mfaToken}`);
      
      if (!mfaDataStr) {
        throw new Error('MFA code expired or invalid token');
      }
      
      const mfaData = JSON.parse(mfaDataStr);
      
      // Verify MFA code
      if (mfaData.code !== mfaCode) {
        await AuditLogger.log({
          event_type: 'mfa_verification_failed',
          user_id: mfaData.user_id,
          ip_address: ipAddress,
          reason: 'invalid_code'
        });
        throw new Error('Invalid MFA code');
      }
      
      // Check expiry
      const now = Date.now();
      if (now - mfaData.created_at > MFA_CODE_EXPIRY) {
        await redis.del(`mfa:${mfaToken}`);
        throw new Error('MFA code expired');
      }
      
      // Delete used MFA token
      await redis.del(`mfa:${mfaToken}`);
      
      // Generate JWT tokens
      const accessToken = this.generateAccessToken({
        user_id: mfaData.user_id,
        username: mfaData.username,
        role: mfaData.role,
        school_id: mfaData.school_id
      });
      
      const refreshToken = this.generateRefreshToken({
        user_id: mfaData.user_id
      });
      
      // Store refresh token in database
      await db.refresh_tokens.create({
        user_id: mfaData.user_id,
        token: refreshToken,
        ip_address: ipAddress,
        user_agent: userAgent,
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        created_at: new Date()
      });
      
      // Log successful authentication
      await AuditLogger.log({
        event_type: 'authentication_success',
        user_id: mfaData.user_id,
        username: mfaData.username,
        role: mfaData.role,
        ip_address: ipAddress,
        user_agent: userAgent,
        mfa_verified: true
      });
      
      return {
        success: true,
        access_token: accessToken,
        refresh_token: refreshToken,
        expires_in: 900, // 15 minutes in seconds
        token_type: 'Bearer',
        user: {
          user_id: mfaData.user_id,
          username: mfaData.username,
          role: mfaData.role
        }
      };
      
    } catch (error) {
      throw error;
    }
  }
  
  /**
   * Generate JWT access token
   */
  generateAccessToken(payload) {
    return jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { 
        expiresIn: ACCESS_TOKEN_EXPIRY,
        issuer: 'madrasati.edu.sa',
        audience: 'madrasati-api'
      }
    );
  }
  
  /**
   * Generate JWT refresh token
   */
  generateRefreshToken(payload) {
    return jwt.sign(
      payload,
      process.env.JWT_REFRESH_SECRET,
      { 
        expiresIn: REFRESH_TOKEN_EXPIRY,
        issuer: 'madrasati.edu.sa',
        audience: 'madrasati-api'
      }
    );
  }
  
  /**
   * Verify and decode JWT token
   */
  verifyAccessToken(token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET, {
        issuer: 'madrasati.edu.sa',
        audience: 'madrasati-api'
      });
      return decoded;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('Access token expired');
      }
      throw new Error('Invalid access token');
    }
  }
  
  /**
   * Refresh access token using refresh token
   */
  async refreshAccessToken(refreshToken, ipAddress) {
    try {
      // Verify refresh token
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      
      // Check if refresh token exists in database and is valid
      const tokenRecord = await db.refresh_tokens.findOne({
        where: {
          token: refreshToken,
          user_id: decoded.user_id,
          revoked: false
        }
      });
      
      if (!tokenRecord) {
        throw new Error('Invalid refresh token');
      }
      
      // Check expiry
      if (new Date() > tokenRecord.expires_at) {
        throw new Error('Refresh token expired');
      }
      
      // Fetch user data
      const user = await db.users.findOne({
        where: { id: decoded.user_id },
        attributes: ['id', 'username', 'role', 'school_id', 'is_active']
      });
      
      if (!user || !user.is_active) {
        throw new Error('User account inactive');
      }
      
      // Generate new access token
      const newAccessToken = this.generateAccessToken({
        user_id: user.id,
        username: user.username,
        role: user.role,
        school_id: user.school_id
      });
      
      // Log token refresh
      await AuditLogger.log({
        event_type: 'token_refreshed',
        user_id: user.id,
        ip_address: ipAddress
      });
      
      return {
        success: true,
        access_token: newAccessToken,
        expires_in: 900,
        token_type: 'Bearer'
      };
      
    } catch (error) {
      throw error;
    }
  }
  
  /**
   * Logout and revoke refresh token
   */
  async logout(refreshToken, userId) {
    try {
      // Revoke refresh token
      await db.refresh_tokens.update(
        { revoked: true, revoked_at: new Date() },
        { where: { token: refreshToken, user_id: userId } }
      );
      
      // Log logout
      await AuditLogger.log({
        event_type: 'user_logout',
        user_id: userId
      });
      
      return { success: true, message: 'Logged out successfully' };
    } catch (error) {
      throw error;
    }
  }
  
  /**
   * Generate random 6-digit MFA code
   */
  generateMFACode() {
    return crypto.randomInt(100000, 999999).toString();
  }
  
  /**
   * Validate registration data
   */
  validateRegistrationData(data) {
    // Username validation (alphanumeric, 3-30 characters)
    if (!/^[a-zA-Z0-9_]{3,30}$/.test(data.username)) {
      throw new Error('Invalid username format');
    }
    
    // Password validation (12+ chars, complexity)
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
    if (!passwordRegex.test(data.password)) {
      throw new Error('Password must be at least 12 characters with uppercase, lowercase, number, and special character');
    }
    
    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.email)) {
      throw new Error('Invalid email format');
    }
    
    // Saudi mobile number validation (05XXXXXXXX)
    const mobileRegex = /^05[0-9]{8}$/;
    if (!mobileRegex.test(data.mobile_number)) {
      throw new Error('Invalid Saudi mobile number format');
    }
    
    // Role validation
    const validRoles = ['student', 'teacher', 'parent', 'school_admin', 'ministry_admin'];
    if (!validRoles.includes(data.role)) {
      throw new Error('Invalid role');
    }
  }
  
  /**
   * Check if account is locked
   */
  async checkAccountLockout(username) {
    const lockoutKey = `lockout:${username}`;
    const lockoutUntil = await redis.get(lockoutKey);
    
    if (lockoutUntil) {
      const now = Date.now();
      const lockoutTime = parseInt(lockoutUntil);
      
      if (now < lockoutTime) {
        const remainingMs = lockoutTime - now;
        const remainingMinutes = Math.ceil(remainingMs / 60000);
        
        return {
          isLocked: true,
          lockoutUntil: new Date(lockoutTime),
          remainingMinutes
        };
      } else {
        // Lockout expired, clear it
        await redis.del(lockoutKey);
      }
    }
    
    return { isLocked: false };
  }
  
  /**
   * Record failed login attempt
   */
  async recordFailedLogin(username, ipAddress, reason) {
    const key = `failed_login:${username}`;
    
    // Increment failed attempts counter (expires after lockout duration)
    await redis.multi()
      .incr(key)
      .expire(key, LOCKOUT_DURATION / 1000)
      .exec();
    
    // Log failed attempt
    await AuditLogger.log({
      event_type: 'login_failed',
      username,
      ip_address: ipAddress,
      reason
    });
  }
  
  /**
   * Get failed login attempts count
   */
  async getFailedLoginAttempts(username) {
    const key = `failed_login:${username}`;
    const count = await redis.get(key);
    return parseInt(count) || 0;
  }
  
  /**
   * Clear failed login attempts
   */
  async clearFailedLoginAttempts(username) {
    const key = `failed_login:${username}`;
    await redis.del(key);
  }
  
  /**
   * Lock account for lockout duration
   */
  async lockAccount(username) {
    const lockoutKey = `lockout:${username}`;
    const lockoutUntil = Date.now() + LOCKOUT_DURATION;
    
    await redis.setex(lockoutKey, LOCKOUT_DURATION / 1000, lockoutUntil.toString());
    
    await AuditLogger.log({
      event_type: 'account_locked',
      username,
      lockout_duration_minutes: LOCKOUT_DURATION / 60000,
      reason: 'max_failed_login_attempts'
    });
  }
  
}

module.exports = new AuthenticationService();
