/**
 * Madrasati Authorization Middleware
 * Implements Role-Based Access Control (RBAC)
 */

const jwt = require('jsonwebtoken');
const { AuditLogger } = require('../utils/audit-logger');

/**
 * Role hierarchy and permissions
 */
const ROLE_PERMISSIONS = {
    student: {
        canRead: ['own_profile', 'own_courses', 'own_grades', 'own_assignments'],
        canWrite: ['own_profile', 'assignment_submission'],
        canDelete: ['own_assignment_submission']
    },

    teacher: {
        canRead: ['own_profile', 'assigned_courses', 'class_roster', 'student_submissions'],
        canWrite: ['own_profile', 'course_content', 'assignments', 'grades'],
        canDelete: ['own_assignments', 'own_course_content']
    },

    parent: {
        canRead: ['own_profile', 'child_grades', 'child_attendance', 'child_courses'],
        canWrite: ['own_profile', 'parent_teacher_messages'],
        canDelete: []
    },

    school_admin: {
        canRead: ['school_users', 'school_courses', 'school_reports', 'school_analytics'],
        canWrite: ['school_users', 'school_courses', 'school_announcements'],
        canDelete: ['school_courses']
    },

    ministry_admin: {
        canRead: ['all_schools', 'all_users', 'system_analytics', 'audit_logs'],
        canWrite: ['system_config', 'all_schools', 'security_policies'],
        canDelete: ['expired_data']
    }
};

/**
 * Middleware to verify JWT token and authenticate user
 */
function authenticateToken(req, res, next) {
    try {
        // Extract token from Authorization header
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

        if (!token) {
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'Access token required'
            });
        }

        // Verify token
        jwt.verify(token, process.env.JWT_SECRET, {
            issuer: 'madrasati.edu.sa',
            audience: 'madrasati-api'
        }, (err, user) => {
            if (err) {
                if (err.name === 'TokenExpiredError') {
                    return res.status(401).json({
                        error: 'Token Expired',
                        message: 'Please refresh your access token'
                    });
                }

                return res.status(403).json({
                    error: 'Forbidden',
                    message: 'Invalid access token'
                });
            }

            // Attach user info to request
            req.user = user;
            next();
        });

    } catch (error) {
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'An error occurred during authentication'
        });
    }
}

/**
 * Middleware to check if user has required role
 * @param {string|string[]} allowedRoles - Single role or array of allowed roles
 */
function requireRole(allowedRoles) {
    return async (req, res, next) => {
        try {
            const userRole = req.user.role;

            // Convert to array if single role
            const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

            if (!roles.includes(userRole)) {
                // Log unauthorized access attempt
                await AuditLogger.log({
                    event_type: 'unauthorized_access_attempt',
                    user_id: req.user.user_id,
                    username: req.user.username,
                    user_role: userRole,
                    required_roles: roles,
                    requested_endpoint: req.path,
                    ip_address: req.ip,
                    user_agent: req.headers['user-agent']
                });

                return res.status(403).json({
                    error: 'Forbidden',
                    message: 'Insufficient permissions'
                });
            }

            next();
        } catch (error) {
            return res.status(500).json({
                error: 'Internal Server Error',
                message: 'An error occurred during authorization'
            });
        }
    };
}

/**
 * Middleware to check if user has specific permission
 * @param {string} action - 'read', 'write', or 'delete'
 * @param {string} resource - Resource type being accessed
 */
function requirePermission(action, resource) {
    return async (req, res, next) => {
        try {
            const userRole = req.user.role;
            const permissions = ROLE_PERMISSIONS[userRole];

            if (!permissions) {
                return res.status(403).json({
                    error: 'Forbidden',
                    message: 'Invalid role'
                });
            }

            // Check if user has permission
            const permissionKey = `can${action.charAt(0).toUpperCase() + action.slice(1)}`;
            const hasPermission = permissions[permissionKey]?.includes(resource);

            if (!hasPermission) {
                // Log permission denial
                await AuditLogger.log({
                    event_type: 'permission_denied',
                    user_id: req.user.user_id,
                    user_role: userRole,
                    required_permission: `${action}:${resource}`,
                    requested_endpoint: req.path,
                    ip_address: req.ip
                });

                return res.status(403).json({
                    error: 'Forbidden',
                    message: `You do not have permission to ${action} ${resource}`
                });
            }

            next();
        } catch (error) {
            return res.status(500).json({
                error: 'Internal Server Error',
                message: 'An error occurred during permission check'
            });
        }
    };
}

/**
 * Middleware to verify user owns the resource being accessed
 * Prevents students from viewing other students' data
 * @param {string} resourceType - 'student', 'teacher', etc.
 * @param {string} paramName - Name of route parameter containing resource ID
 */
function requireOwnership(resourceType, paramName = 'id') {
    return async (req, res, next) => {
        try {
            const userId = req.user.user_id;
            const resourceId = parseInt(req.params[paramName]);

            // For students, only allow access to own resources
            if (req.user.role === 'student') {
                if (resourceType === 'student' && resourceId !== userId) {
                    await AuditLogger.log({
                        event_type: 'unauthorized_resource_access',
                        user_id: userId,
                        attempted_resource_id: resourceId,
                        resource_type: resourceType,
                        ip_address: req.ip
                    });

                    return res.status(403).json({
                        error: 'Forbidden',
                        message: 'You can only access your own data'
                    });
                }
            }

            // For teachers, verify they teach the student/course
            if (req.user.role === 'teacher') {
                if (resourceType === 'student') {
                    const isTeaching = await db.enrollments.findOne({
                        where: {
                            student_id: resourceId,
                            course_id: {
                                [db.Sequelize.Op.in]: db.Sequelize.literal(
                                    `(SELECT course_id FROM course_assignments WHERE teacher_id = ${userId})`
                                )
                            }
                        }
                    });

                    if (!isTeaching) {
                        await AuditLogger.log({
                            event_type: 'unauthorized_student_access',
                            teacher_id: userId,
                            attempted_student_id: resourceId,
                            ip_address: req.ip
                        });

                        return res.status(403).json({
                            error: 'Forbidden',
                            message: 'You can only access students in your classes'
                        });
                    }
                }
            }

            // For parents, verify it's their child
            if (req.user.role === 'parent') {
                if (resourceType === 'student') {
                    const isParent = await db.parent_child.findOne({
                        where: {
                            parent_id: userId,
                            student_id: resourceId
                        }
                    });

                    if (!isParent) {
                        await AuditLogger.log({
                            event_type: 'unauthorized_child_access',
                            parent_id: userId,
                            attempted_student_id: resourceId,
                            ip_address: req.ip
                        });

                        return res.status(403).json({
                            error: 'Forbidden',
                            message: 'You can only access your own children\'s data'
                        });
                    }
                }
            }

            // For school admins, verify resource belongs to their school
            if (req.user.role === 'school_admin') {
                const schoolId = req.user.school_id;

                if (resourceType === 'student') {
                    const student = await db.users.findOne({
                        where: { id: resourceId, school_id: schoolId }
                    });

                    if (!student) {
                        return res.status(403).json({
                            error: 'Forbidden',
                            message: 'You can only access users in your school'
                        });
                    }
                }
            }

            next();
        } catch (error) {
            return res.status(500).json({
                error: 'Internal Server Error',
                message: 'An error occurred during ownership verification'
            });
        }
    };
}

/**
 * Middleware to verify user belongs to the same school
 * Used for school-level resources
 */
function requireSameSchool(req, res, next) {
    const userSchoolId = req.user.school_id;
    const requestedSchoolId = parseInt(req.params.school_id || req.body.school_id);

    // Ministry admins can access all schools
    if (req.user.role === 'ministry_admin') {
        return next();
    }

    if (userSchoolId !== requestedSchoolId) {
        AuditLogger.log({
            event_type: 'cross_school_access_denied',
            user_id: req.user.user_id,
            user_school_id: userSchoolId,
            attempted_school_id: requestedSchoolId,
            ip_address: req.ip
        });

        return res.status(403).json({
            error: 'Forbidden',
            message: 'You can only access resources in your school'
        });
    }

    next();
}

/**
 * Middleware to log authorized resource access
 * Use for sensitive operations (grade viewing, data exports)
 */
function logResourceAccess(resourceType) {
    return async (req, res, next) => {
        await AuditLogger.log({
            event_type: 'resource_accessed',
            user_id: req.user.user_id,
            user_role: req.user.role,
            resource_type: resourceType,
            resource_id: req.params.id,
            action: req.method,
            endpoint: req.path,
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });

        next();
    };
}

/**
 * Check if user has admin privileges
 */
function isAdmin(req) {
    return ['school_admin', 'ministry_admin'].includes(req.user.role);
}

/**
 * Check if user is ministry admin
 */
function isMinistryAdmin(req) {
    return req.user.role === 'ministry_admin';
}

module.exports = {
    authenticateToken,
    requireRole,
    requirePermission,
    requireOwnership,
    requireSameSchool,
    logResourceAccess,
    isAdmin,
    isMinistryAdmin,
    ROLE_PERMISSIONS
};
