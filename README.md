# Madrasati Security Framework 🛡️

**A Comprehensive Security Assessment & Enhancement Project**

This repository contains the complete security framework designed for the **Madrasati** platform, Saudi Arabia's national learning management system. The project follows the **EMAM** methodology (Understand, Practice, Master, Excel) to deliver a robust, defense-in-depth security architecture aligned with **Saudi Vision 2030** and **NCA** regulations.

## 📂 Project Structure

The repository is organized into the following key directories:

*   **`docs/`**: Comprehensive documentation for each phase of the framework.
    *   [Phase 1 Understand](docs/phase1-understand.md): Architecture & Threat Landscape.
    *   [Phase 2 Practice](docs/phase2-practice.md): Threat Modeling (STRIDE) & Analysis.
    *   [Phase 3 Master](docs/phase3-master.md): Security Implementation & Code.
    *   [Phase 4 Excel](docs/phase4-excel.md): Testing Results & Future Innovation.
*   **`src/`**: Source code for the security implementations and demo application.
    *   `demo-app/`: A working Node.js/Express application demonstrating the security controls.
    *   `authentication/`: Secure auth service with Bcrypt and Rate Limiting.
    *   `data-protection/`: Encryption and Input Validation modules.
*   **`diagrams/`**: Visual representations of the system.
    *   `threat-model.drawio`: Detailed STRIDE threat model diagram.
*   **`testing/`**: Test plans and procedures.

## 🚀 Getting Started (Demo App)

This project includes a fully functional demo application that showcases the security controls in action (Rate Limiting, XSS Protection, RBAC, etc.).

### Prerequisites
*   Node.js (v14 or higher)
*   npm

### Installation & Running
1.  Navigate to the demo app directory:
    ```bash
    cd src/demo-app
    ```
2.  Install dependencies:
    ```bash
    npm install
    ```
3.  Start the server:
    ```bash
    npm start
    ```
4.  Open your browser and visit: `http://localhost:3000`

## 🔒 Key Security Features Implemented

*   **Defense in Depth**: Multi-layered security from edge to data.
*   **Secure Authentication**: Bcrypt hashing, Account Lockout, and Session Management.
*   **RBAC Middleware**: Strict Role-Based Access Control for all routes.
*   **Input Sanitization**: Whitelist-based validation to prevent SQLi and XSS.
*   **Rate Limiting**: Protection against Brute Force and DoS attacks.
*   **Audit Logging**: Immutable logs for non-repudiation.

## 🇸🇦 Vision 2030 Alignment

This framework directly supports the **Human Capability Development** and **Digital Government** programs by ensuring a secure, reliable, and trusted educational environment for over 6 million students.

---
*Developed by Fuad Alawi*