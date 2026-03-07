# PolicyNav – Milestone 2

This milestone focuses on extending the functionality of the PolicyNav platform by adding new features that improve **security, usability, and document analysis capabilities**. Along with the core authentication system developed earlier, additional modules were implemented to enhance user account recovery and policy document understanding.

## Features Implemented

### 🔐 Password Recovery using OTP
- Implemented a **Forgot Password feature** that allows users to reset their password securely.
- A **One-Time Password (OTP)** is sent to the user's registered email.
- The user must verify the OTP before creating a new password.
- Ensures secure account recovery while preventing unauthorized access.

### 📊 Policy Readability Checker
- Added a **Readability Analysis module** to evaluate policy documents.
- Calculates readability scores to determine how easy or difficult a document is to understand.
- Helps users quickly assess the **complexity of policy texts**.

### 🖥️ Application Improvements
- Integrated the new modules into the **Streamlit interface**.
- Improved overall workflow and user interaction with the platform.

## Technologies Used

- Python  
- Streamlit  
- SQLite  
- bcrypt  
- JWT (PyJWT)  
- SMTP (Email Service)

## Milestone Outcome

Milestone 2 enhances the PolicyNav platform by introducing **secure password recovery using OTP and readability analysis for policy documents**, improving both the **user experience and analytical capabilities** of the system.
