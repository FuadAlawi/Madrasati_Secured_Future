/**
 * Madrasati Data Protection Module
 * Implements encryption for sensitive data
 */

const crypto = require('crypto');

// Encryption configuration
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16; // 128 bits
const AUTH_TAG_LENGTH = 16; // 128 bits

class EncryptionService {

    constructor() {
        // Load encryption key from environment (in production, use KMS/HSM)
        this.masterKey = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');

        if (this.masterKey.length !== KEY_LENGTH) {
            throw new Error('Encryption key must be 32 bytes (256 bits)');
        }
    }

    /**
     * Encrypt sensitive data using AES-256-GCM
     * @param {string} plaintext - Data to encrypt
     * @returns {object} - {iv, encryptedData, authTag}
     */
    encrypt(plaintext) {
        try {
            // Generate random IV for each encryption
            const iv = crypto.randomBytes(IV_LENGTH);

            // Create cipher
            const cipher = crypto.createCipheriv(ALGORITHM, this.masterKey, iv);

            // Encrypt data
            let encrypted = cipher.update(plaintext, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            // Get authentication tag (for integrity verification)
            const authTag = cipher.getAuthTag();

            return {
                iv: iv.toString('hex'),
                encryptedData: encrypted,
                authTag: authTag.toString('hex')
            };
        } catch (error) {
            throw new Error(`Encryption failed: ${error.message}`);
        }
    }

    /**
     * Decrypt data encrypted with encrypt()
     * @param {object} encrypted - {iv, encryptedData, authTag}
     * @returns {string} - Decrypted plaintext
     */
    decrypt(encrypted) {
        try {
            // Create decipher
            const decipher = crypto.createDecipheriv(
                ALGORITHM,
                this.masterKey,
                Buffer.from(encrypted.iv, 'hex')
            );

            // Set authentication tag
            decipher.setAuthTag(Buffer.from(encrypted.authTag, 'hex'));

            // Decrypt data
            let decrypted = decipher.update(encrypted.encryptedData, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            return decrypted;
        } catch (error) {
            throw new Error(`Decryption failed: ${error.message}`);
        }
    }

    /**
     * Encrypt student national ID for storage
     * @param {string} nationalId - Saudi national ID (10 digits)
     * @returns {string} - JSON string of encrypted data
     */
    encryptNationalId(nationalId) {
        const encrypted = this.encrypt(nationalId);
        return JSON.stringify(encrypted);
    }

    /**
     * Decrypt student national ID
     * @param {string} encryptedData - JSON string of encrypted data
     * @returns {string} - Decrypted national ID
     */
    decryptNationalId(encryptedData) {
        const encrypted = JSON.parse(encryptedData);
        return this.decrypt(encrypted);
    }

    /**
     * Hash sensitive data for comparison (one-way)
     * Used for data that needs to be searched but not decrypted
     * @param {string} data - Data to hash
     * @returns {string} - SHA-256 hash
     */
    hashData(data) {
        return crypto.createHash('sha256').update(data).digest('hex');
    }

    /**
     * Encrypt grade data with metadata
     * @param {object} gradeData - {student_id, course_id, grade, graded_by, date}
     * @returns {string} - Encrypted grade record
     */
    encryptGradeRecord(gradeData) {
        const dataString = JSON.stringify(gradeData);
        const encrypted = this.encrypt(dataString);

        // Add timestamp and version for key rotation
        return JSON.stringify({
            ...encrypted,
            encrypted_at: new Date().toISOString(),
            key_version: process.env.ENCRYPTION_KEY_VERSION || '1'
        });
    }

    /**
     * Decrypt grade record
     * @param {string} encryptedRecord - Encrypted grade record
     * @returns {object} - Decrypted grade data
     */
    decryptGradeRecord(encryptedRecord) {
        const record = JSON.parse(encryptedRecord);

        // Check key version for rotation
        if (record.key_version !== process.env.ENCRYPTION_KEY_VERSION) {
            // In production: use old key to decrypt, re-encrypt with new key
            console.warn('Grade encrypted with old key version, consider re-encryption');
        }

        const decryptedString = this.decrypt({
            iv: record.iv,
            encryptedData: record.encryptedData,
            authTag: record.authTag
        });

        return JSON.parse(decryptedString);
    }

    /**
     * Generate cryptographically secure random token
     * Used for password reset tokens, API keys, etc.
     * @param {number} bytes - Number of random bytes (default 32)
     * @returns {string} - Hex-encoded random token
     */
    generateSecureToken(bytes = 32) {
        return crypto.randomBytes(bytes).toString('hex');
    }

    /**
     * Constant-time comparison to prevent timing attacks
     * @param {string} a - First string
     * @param {string} b - Second string
     * @returns {boolean} - True if equal
     */
    secureCompare(a, b) {
        if (a.length !== b.length) {
            return false;
        }
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    }

    /**
     * Derive encryption key from password (for password-protected exports)
     * @param {string} password - User password
     * @param {string} salt - Salt (hex string)
     * @returns {Buffer} - Derived key
     */
    deriveKeyFromPassword(password, salt) {
        return crypto.pbkdf2Sync(
            password,
            Buffer.from(salt, 'hex'),
            100000, // iterations
            KEY_LENGTH,
            'sha256'
        );
    }

}

/**
 * Data masking utilities for non-production environments
 */
class DataMasker {

    /**
     * Mask student national ID (show last 4 digits only)
     * @param {string} nationalId - Full national ID
     * @returns {string} - Masked ID (e.g., "******5678")
     */
    static maskNationalId(nationalId) {
        if (!nationalId || nationalId.length !== 10) {
            return '**********';
        }
        return '******' + nationalId.slice(-4);
    }

    /**
     * Mask email address
     * @param {string} email - Email address
     * @returns {string} - Masked email (e.g., "st***@madrasati.edu.sa")
     */
    static maskEmail(email) {
        const [localPart, domain] = email.split('@');
        if (localPart.length <= 2) {
            return `**@${domain}`;
        }
        return `${localPart.slice(0, 2)}***@${domain}`;
    }

    /**
     * Mask mobile number (show last 4 digits)
     * @param {string} mobile - Mobile number
     * @returns {string} - Masked number (e.g., "05****5678")
     */
    static maskMobile(mobile) {
        if (!mobile || mobile.length !== 10) {
            return '**********';
        }
        return mobile.slice(0, 2) + '****' + mobile.slice(-4);
    }

    /**
     * Mask student name for privacy
     * @param {string} fullName - Full name
     * @returns {string} - Masked name (e.g., "Ahmed A.")
     */
    static maskName(fullName) {
        const parts = fullName.split(' ');
        if (parts.length === 1) {
            return fullName;
        }
        return `${parts[0]} ${parts[1].charAt(0)}.`;
    }

    /**
     * Anonymize student data for analytics
     * @param {object} studentData - Student record
     * @returns {object} - Anonymized data
     */
    static anonymizeStudentData(studentData) {
        return {
            student_id_hash: crypto.createHash('sha256').update(studentData.student_id.toString()).digest('hex'),
            school_id: studentData.school_id,
            grade_level: studentData.grade_level,
            gender: studentData.gender,
            academic_performance: studentData.grades,
            // Remove all PII
            // No: name, national_id, email, mobile, address
        };
    }

}

module.exports = {
    EncryptionService: new EncryptionService(),
    DataMasker
};
