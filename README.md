This Project is the **user authentication** built using Node.js + Express backend using MongoDB and JWT. It handles all logic related to:

## Core Responsibilities

| Category             | Description                            |
| -------------------- | -------------------------------------- |
| **Authentication**   | Login, logout, register, refresh token |
| **User Management**  | Get, update, delete user               |
| **Session Handling** | Access & refresh token logic, cookies  |
| **Security**         | Password hashing, token validation     |
| **Email Service**    | Password reset email via Nodemailer    |

## Authentication & Tokens

-   **Login (`login`)**

    -   Verifies user credentials.
    -   Issues **access & refresh tokens**.
    -   Stores them as HTTP-only cookies.

-   **Refresh Token (`refreshToken`)**

    -   Verifies existing refresh token.
    -   Returns new access token and updates cookies.

-   **Logout (`logout`)**

    -   Invalidates the current token by removing it from the DB.

-   **Logout All (`logoutAll`)**
    -   Clears all tokens from the user (force logout all devices).

## User Management

-   **Register (`registerNewUser`)**

    -   Creates a new user if email is not already used.

-   **Get User (`getUserDetails`)**

    -   Returns the authenticated user's profile (by `slug`).

-   **Update User (`updateUserDetails`)**

    -   Updates allowed fields (excluding `email`, `name`, `password`).
    -   Supports field removal (if null is passed).

-   **Delete User (`deleteUser`)**
    -   Deletes user account by `slug`.

## Password Reset Logic

-   **Request Password Reset (`requestPasswordReset`)**

    -   Generates a JWT token and stores it in `PasswordResetToken`.
    -   Sends a reset email via **Nodemailer**.

-   **Reset Password (`resetPassword`)**
    -   Verifies reset token.
    -   Updates the user's password securely.

## Utilities & Config

-   **Bcrypt** for password hashing and checking.
-   **JWT** for access & refresh token generation.
-   **Cookies** for client storage with `HttpOnly`, `Secure`, `SameSite`.
-   **Custom middleware**: Uses `AuthenticatedRequest` to type-safe `req.user`.

## Models Used

-   `User` model – includes token storage and `generateAuthToken()` method.
-   `PasswordResetToken` – stores temporary reset tokens.

## Good Practices Used

-   Error handling with proper status codes.
-   Secure cookie handling.
-   JWT expiration and blacklist control via DB.
-   Token expiration logic (`expiresAt`) for refresh and reset flows.
-   Separation of concerns between controller, model, and middleware.
