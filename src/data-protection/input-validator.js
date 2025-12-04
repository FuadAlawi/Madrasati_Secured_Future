/**
 * Madrasati Input Validation Module
 * Prevents injection attacks and ensures data integrity
 */

const validator = require('validator');
const sanitizeHtml = require('sanitize-html');

/**
 * Validation error class
 */
class ValidationError extends Error {
    constructor(message, field) {
        super(message);
        this.name = 'ValidationError';
        this.field = field;
        this.statusCode = 400;
    }
}

/**
 * Input validation service
 */
class InputValidator {

    /**
     * Validate Saudi national ID
     * Format: 10 digits, starts with 1 or 2
     */
    static validateNationalId(nationalId, fieldName = 'national_id') {
        if (!nationalId) {
            throw new ValidationError('National ID is required', fieldName);
        }

        const pattern = /^[12][0-9]{9}$/;
        if (!pattern.test(nationalId)) {
            throw new ValidationError('Invalid Saudi national ID format (must be 10 digits starting with 1 or 2)', fieldName);
        }

        return nationalId;
    }

    /**
     * Validate student ID
     * Format: 10 digit number
     */
    static validateStudentId(studentId, fieldName = 'student_id') {
        if (!studentId) {
            throw new ValidationError('Student ID is required', fieldName);
        }

        const id = parseInt(studentId);
        if (isNaN(id) || id <= 0 || id > 9999999999) {
            throw new ValidationError('Invalid student ID', fieldName);
        }

        return id;
    }

    /**
     * Validate name (Arabic or English)
     * Allows: Arabic letters, English letters, spaces
     * Length: 2-100 characters
     */
    static validateName(name, fieldName = 'name') {
        if (!name || typeof name !== 'string') {
            throw new ValidationError('Name is required', fieldName);
        }

        // Trim whitespace
        name = name.trim();

        // Check length
        if (name.length < 2 || name.length > 100) {
            throw new ValidationError('Name must be between 2 and 100 characters', fieldName);
        }

        // Allow Arabic (U+0600-U+06FF), English, and spaces
        const pattern = /^[\u0600-\u06FFa-zA-Z\s'-]+$/;
        if (!pattern.test(name)) {
            throw new ValidationError('Name can only contain Arabic or English letters', fieldName);
        }

        return name;
    }

    /**
     * Validate email address
     */
    static validateEmail(email, fieldName = 'email') {
        if (!email) {
            throw new ValidationError('Email is required', fieldName);
        }

        email = email.trim().toLowerCase();

        if (!validator.isEmail(email)) {
            throw new ValidationError('Invalid email format', fieldName);
        }

        // Optional: restrict to specific domains for school emails
        // if (!email.endsWith('@madrasati.edu.sa')) {
        //   throw new ValidationError('Email must be from madrasati.edu.sa domain', fieldName);
        // }

        return email;
    }

    /**
     * Validate Saudi mobile number
     * Format: 05XXXXXXXX (10 digits starting with 05)
     */
    static validateMobileNumber(mobile, fieldName = 'mobile_number') {
        if (!mobile) {
            throw new ValidationError('Mobile number is required', fieldName);
        }

        // Remove any spaces or dashes
        mobile = mobile.replace(/[\s-]/g, '');

        const pattern = /^05[0-9]{8}$/;
        if (!pattern.test(mobile)) {
            throw new ValidationError('Invalid Saudi mobile number (must start with 05 and be 10 digits)', fieldName);
        }

        return mobile;
    }

    /**
     * Validate password strength
     * Requirements:
     * - At least 12 characters
     * - At least one uppercase letter
     * - At least one lowercase letter
     * - At least one digit
     * - At least one special character
     */
    static validatePassword(password, fieldName = 'password') {
        if (!password) {
            throw new ValidationError('Password is required', fieldName);
        }

        if (password.length < 12) {
            throw new ValidationError('Password must be at least 12 characters long', fieldName);
        }

        if (!/[A-Z]/.test(password)) {
            throw new ValidationError('Password must contain at least one uppercase letter', fieldName);
        }

        if (!/[a-z]/.test(password)) {
            throw new ValidationError('Password must contain at least one lowercase letter', fieldName);
        }

        if (!/[0-9]/.test(password)) {
            throw new ValidationError('Password must contain at least one digit', fieldName);
        }

        if (!/[@$!%*?&]/.test(password)) {
            throw new ValidationError('Password must contain at least one special character (@$!%*?&)', fieldName);
        }

        // Check against common passwords
        const commonPasswords = ['Password123!', 'Madrasati123!', 'Saudi123!'];
        if (commonPasswords.includes(password)) {
            throw new ValidationError('Password is too common, please choose a stronger password', fieldName);
        }

        return password;
    }

    /**
     * Validate grade value
     * Range: 0-100
     */
    static validateGrade(grade, fieldName = 'grade') {
        if (grade === null || grade === undefined) {
            throw new ValidationError('Grade is required', fieldName);
        }

        const gradeNum = parseFloat(grade);

        if (isNaN(gradeNum)) {
            throw new ValidationError('Grade must be a number', fieldName);
        }

        if (gradeNum < 0 || gradeNum > 100) {
            throw new ValidationError('Grade must be between 0 and 100', fieldName);
        }

        // Round to 2 decimal places
        return Math.round(gradeNum * 100) / 100;
    }

    /**
     * Validate course code
     * Format: XXXX-XXX (e.g., MATH-101, ARAB-201)
     */
    static validateCourseCode(courseCode, fieldName = 'course_code') {
        if (!courseCode) {
            throw new ValidationError('Course code is required', fieldName);
        }

        courseCode = courseCode.trim().toUpperCase();

        const pattern = /^[A-Z]{3,4}-[0-9]{3}$/;
        if (!pattern.test(courseCode)) {
            throw new ValidationError('Invalid course code format (e.g., MATH-101)', fieldName);
        }

        return courseCode;
    }

    /**
     * Validate date (not in future)
     */
    static validatePastDate(date, fieldName = 'date') {
        if (!date) {
            throw new ValidationError('Date is required', fieldName);
        }

        const dateObj = new Date(date);

        if (isNaN(dateObj.getTime())) {
            throw new ValidationError('Invalid date format', fieldName);
        }

        if (dateObj > new Date()) {
            throw new ValidationError('Date cannot be in the future', fieldName);
        }

        return dateObj;
    }

    /**
     * Validate and sanitize rich text content
     * Used for assignments, announcements, etc.
     */
    static sanitizeRichText(html, fieldName = 'content') {
        if (!html) {
            throw new ValidationError('Content is required', fieldName);
        }

        // Sanitize HTML to prevent XSS
        const clean = sanitizeHtml(html, {
            allowedTags: [
                'p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
                'ul', 'ol', 'li', 'blockquote', 'a', 'img', 'table', 'thead', 'tbody',
                'tr', 'th', 'td', 'code', 'pre'
            ],
            allowedAttributes: {
                'a': ['href', 'title', 'target'],
                'img': ['src', 'alt', 'title', 'width', 'height']
            },
            allowedSchemes: ['http', 'https', 'mailto'],
            allowedSchemesByTag: {
                img: ['http', 'https', 'data']
            },
            transformTags: {
                'a': (tagName, attribs) => {
                    return {
                        tagName: 'a',
                        attribs: {
                            ...attribs,
                            rel: 'noopener noreferrer' // Security: prevent window.opener access
                        }
                    };
                }
            }
        });

        // Check length
        if (clean.length > 50000) {
            throw new ValidationError('Content exceeds maximum length (50,000 characters)', fieldName);
        }

        return clean;
    }

    /**
     * Validate and escape search query
     * Prevents SQL injection and XSS in search
     */
    static validateSearchQuery(query, fieldName = 'search') {
        if (!query || typeof query !== 'string') {
            return '';
        }

        // Trim and limit length
        query = query.trim().substring(0, 100);

        // Remove potential SQL injection characters
        // Note: Use parameterized queries as primary defense
        query = query.replace(/[';\"\\]/g, '');

        // Escape HTML to prevent XSS
        query = validator.escape(query);

        return query;
    }

    /**
     * Validate file upload
     * @param {object} file - Uploaded file object
     * @param {array} allowedTypes - Array of allowed MIME types
     * @param {number} maxSizeMB - Maximum file size in MB
     */
    static validateFileUpload(file, allowedTypes, maxSizeMB = 10) {
        if (!file) {
            throw new ValidationError('File is required', 'file');
        }

        // Check file size
        const maxSizeBytes = maxSizeMB * 1024 * 1024;
        if (file.size > maxSizeBytes) {
            throw new ValidationError(`File size exceeds maximum of ${maxSizeMB}MB`, 'file');
        }

        // Check MIME type
        if (!allowedTypes.includes(file.mimetype)) {
            throw new ValidationError(`File type not allowed. Allowed types: ${allowedTypes.join(', ')}`, 'file');
        }

        // Check file extension matches MIME type
        const ext = file.originalname.split('.').pop().toLowerCase();
        const mimeToExt = {
            'application/pdf': ['pdf'],
            'image/jpeg': ['jpg', 'jpeg'],
            'image/png': ['png'],
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['docx'],
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['xlsx']
        };

        const validExtensions = mimeToExt[file.mimetype];
        if (validExtensions && !validExtensions.includes(ext)) {
            throw new ValidationError('File extension does not match content type', 'file');
        }

        return true;
    }

    /**
     * Validate role
     */
    static validateRole(role, fieldName = 'role') {
        const validRoles = ['student', 'teacher', 'parent', 'school_admin', 'ministry_admin'];

        if (!validRoles.includes(role)) {
            throw new ValidationError(`Invalid role. Must be one of: ${validRoles.join(', ')}`, fieldName);
        }

        return role;
    }

    /**
     * Validate academic year
     * Format: YYYY-YYYY (e.g., 2024-2025)
     */
    static validateAcademicYear(year, fieldName = 'academic_year') {
        if (!year) {
            throw new ValidationError('Academic year is required', fieldName);
        }

        const pattern = /^(20[2-9][0-9])-(20[2-9][0-9])$/;
        const match = year.match(pattern);

        if (!match) {
            throw new ValidationError('Invalid academic year format (e.g., 2024-2025)', fieldName);
        }

        const startYear = parseInt(match[1]);
        const endYear = parseInt(match[2]);

        if (endYear !== startYear + 1) {
            throw new ValidationError('Academic year must be consecutive years', fieldName);
        }

        return year;
    }

}

/**
 * SQL Injection Prevention Helpers
 */
class SQLSafeValidator {

    /**
     * Validate integer ID for SQL queries
     */
    static sanitizeIntegerId(id) {
        const num = parseInt(id);
        if (isNaN(num) || num <= 0) {
            throw new ValidationError('Invalid ID');
        }
        return num;
    }

    /**
     * Validate array of integer IDs
     */
    static sanitizeIntegerArray(ids) {
        if (!Array.isArray(ids)) {
            throw new ValidationError('IDs must be an array');
        }

        return ids.map(id => {
            const num = parseInt(id);
            if (isNaN(num) || num <= 0) {
                throw new ValidationError('Invalid ID in array');
            }
            return num;
        });
    }

    /**
     * Example of safe parameterized query builder
     * ALWAYS use this instead of string concatenation
     */
    static buildSafeQuery(baseQuery, params) {
        // params should be passed separately to database driver
        // This is just a validation helper
        return {
            query: baseQuery,
            params: params.map(p => {
                if (typeof p === 'number') {
                    return p;
                } else if (typeof p === 'string') {
                    return p; // Database driver will escape
                } else {
                    throw new ValidationError('Invalid parameter type');
                }
            })
        };
    }

}

module.exports = {
    InputValidator,
    SQLSafeValidator,
    ValidationError
};
