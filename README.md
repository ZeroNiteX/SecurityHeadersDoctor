# SecurityHeaders Doctor

A .NET 8 Minimal API application that analyzes security headers of web applications and provides actionable fix recommendations.

## Purpose

SecurityHeaders Doctor helps developers and security teams identify missing or misconfigured security headers in web applications. It provides a comprehensive analysis of HTTP response headers and generates fix snippets for popular web frameworks.

## Quick Start

1. Clone the repository
2. Run the application:
   ```bash
   dotnet run
   ```
3. Open your browser to `https://localhost:5001` (or the displayed URL)
4. Enter a URL to analyze and click "Analyze"
5. Review the security grade, findings, and copy the provided fix snippets

## What Gets Checked?

The analyzer evaluates the following security headers:

- **Content-Security-Policy (CSP)**: Prevents XSS attacks by controlling resource loading
- **Strict-Transport-Security (HSTS)**: Enforces HTTPS connections
- **X-Frame-Options**: Prevents clickjacking attacks
- **X-Content-Type-Options**: Prevents MIME type sniffing
- **Referrer-Policy**: Controls referrer information sharing
- **Permissions-Policy**: Restricts browser feature access
- **Cross-Origin-Opener-Policy (COOP)**: Provides isolation for browsing contexts
- **Cross-Origin-Resource-Policy (CORP)**: Controls cross-origin resource access
- **Cross-Origin-Embedder-Policy (COEP)**: Enables cross-origin isolation
- **Set-Cookie**: Validates secure cookie attributes

## Limitations

- Analysis is based solely on HTTP response headers
- Does not understand application context or business logic
- CSP policies should be adapted to your specific environment
- Results are indicative and should be validated by security professionals

## Fix Snippets

The tool provides ready-to-use code snippets for:

- **.NET**: Middleware configuration for security headers
- **NGINX**: Server configuration directives
- **Express.js**: Helmet.js configuration

## API Endpoints

- `POST /inspect` - Analyze security headers of a given URL
- `GET /healthz` - Health check endpoint
- `GET /version` - Application version information

## Testing

Run the test suite:

```bash
dotnet test
```

The test suite includes unit tests for the analyzer and integration tests for the API endpoints.

## License

MIT License

