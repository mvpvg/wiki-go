# Security Policy

## Supported Versions

Use this section to tell people about which versions of Wiki-Go are currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

We take the security of Wiki-Go seriously. If you believe you've found a security vulnerability, please follow these steps:

1. **Do not disclose the vulnerability publicly** or on the public issue tracker.
2. Submit your findings through our [contact form](https://leomoon.com/contact).
3. Allow time for us to review and address the vulnerability before any public disclosure.
4. We'll respond as quickly as possible to acknowledge receipt of your report.

## Security Features

Wiki-Go includes several security features:

- **Password Storage**: All passwords are hashed using bcrypt with appropriate cost factors.
- **Authentication**: Session-based authentication with secure, HTTP-only cookies.
- **TLS Support**: Built-in TLS support for encrypted connections.
- **Role-Based Access Control**: Fine-grained permissions through admin, editor, and viewer roles.
- **File Upload Validation**: MIME type checking for uploaded files (can be disabled if needed).
- **Private Wiki Mode**: Option to require authentication for all pages.

## Security Recommendations

For secure deployment of Wiki-Go, we recommend:

1. **Always use HTTPS** in production environments.
2. **Set `allow_insecure_cookies: false`** (the default) to enforce secure cookies.
3. **Change the default admin password** immediately after installation.
4. **Regularly update** to the latest version for security patches.
5. **Use a reverse proxy** like Nginx, Caddy, or Traefik for additional security layers.
6. **Back up your data** regularly to prevent data loss.
7. **Set appropriate file upload size limits** to prevent denial of service attacks.
8. **Implement rate limiting** at the reverse proxy level to prevent brute force attacks.

## Dependency Management

Wiki-Go uses Go modules for dependency management. All dependencies are vendored to ensure reproducible builds.

## Security Practices

Our security practices include:

1. Regular code review with a focus on security
2. Input validation to prevent injection attacks
3. Proper error handling to avoid information leakage
4. Use of standard libraries for cryptographic operations
5. Secure session management
6. Principle of least privilege for user roles

## Known Issues

No known security issues at this time.

## Security Contact

For security concerns, please use our [contact form](https://leomoon.com/contact).