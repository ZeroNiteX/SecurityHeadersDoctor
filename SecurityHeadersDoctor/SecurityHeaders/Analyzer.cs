using SecurityHeadersDoctor.Models;

namespace SecurityHeadersDoctor.SecurityHeaders;

public static class Analyzer
{
    public static SecurityAnalysisResult Analyze(Dictionary<string, string> headers)
    {
        var findings = new List<Finding>();
        var headersDict = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);

        // 1. Content-Security-Policy (CSP)
        AnalyzeCsp(headersDict, findings);

        // 2. Strict-Transport-Security (HSTS)
        AnalyzeHsts(headersDict, findings);

        // 3. X-Frame-Options (XFO)
        AnalyzeXFrameOptions(headersDict, findings);

        // 4. X-Content-Type-Options (XCTO)
        AnalyzeXContentTypeOptions(headersDict, findings);

        // 5. Referrer-Policy
        AnalyzeReferrerPolicy(headersDict, findings);

        // 6. Permissions-Policy
        AnalyzePermissionsPolicy(headersDict, findings);

        // 7. Cross-Origin-Opener-Policy (COOP)
        AnalyzeCoop(headersDict, findings);

        // 8. Cross-Origin-Resource-Policy (CORP)
        AnalyzeCorp(headersDict, findings);

        // 9. Cross-Origin-Embedder-Policy (COEP)
        AnalyzeCoep(headersDict, findings);

        // 10. Set-Cookie
        AnalyzeSetCookie(headersDict, findings);

        var grade = CalculateGrade(findings);
        var snippets = GenerateFixSnippets();

        return new SecurityAnalysisResult(grade, findings, headersDict, snippets);
    }

    private static void AnalyzeCsp(Dictionary<string, string> headers, List<Finding> findings)
    {
        if (!headers.TryGetValue("Content-Security-Policy", out var csp))
        {
            findings.Add(new Finding(
                "Content-Security-Policy",
                "critical",
                "Content-Security-Policy header is missing",
                "Add CSP header: default-src 'self'; base-uri 'self'; frame-ancestors 'self'; object-src 'none'; upgrade-insecure-requests; block-all-mixed-content"
            ));
            return;
        }

        // Check for risky patterns
        if (csp.Contains("unsafe-inline"))
        {
            findings.Add(new Finding(
                "Content-Security-Policy",
                "warn",
                "CSP contains 'unsafe-inline' directive",
                "Replace 'unsafe-inline' with specific nonce or hash values for better security"
            ));
        }

        if (csp.Contains("unsafe-eval"))
        {
            findings.Add(new Finding(
                "Content-Security-Policy",
                "warn",
                "CSP contains 'unsafe-eval' directive",
                "Remove 'unsafe-eval' and use safer alternatives for dynamic code execution"
            ));
        }

        if (csp.Contains("default-src *"))
        {
            findings.Add(new Finding(
                "Content-Security-Policy",
                "warn",
                "CSP allows all sources with 'default-src *'",
                "Restrict default-src to specific trusted domains"
            ));
        }

        if (csp.Contains("data:"))
        {
            findings.Add(new Finding(
                "Content-Security-Policy",
                "warn",
                "CSP allows data: URLs",
                "Consider restricting data: URLs unless specifically needed"
            ));
        }
    }

    private static void AnalyzeHsts(Dictionary<string, string> headers, List<Finding> findings)
    {
        if (!headers.TryGetValue("Strict-Transport-Security", out var hsts))
        {
            findings.Add(new Finding(
                "Strict-Transport-Security",
                "warn",
                "HSTS header is missing",
                "Add HSTS header to enforce HTTPS connections"
            ));
            return;
        }

        // Check max-age (should be at least 180 days = 15552000 seconds)
        if (!hsts.Contains("max-age="))
        {
            findings.Add(new Finding(
                "Strict-Transport-Security",
                "warn",
                "HSTS max-age should be at least 180 days",
                "Set max-age to at least 15552000 (180 days)"
            ));
        }
        else
        {
            // Extract max-age value and check if it's less than 180 days
            var maxAgeMatch = System.Text.RegularExpressions.Regex.Match(hsts, @"max-age=(\d+)");
            if (maxAgeMatch.Success && int.TryParse(maxAgeMatch.Groups[1].Value, out var maxAge) && maxAge < 15552000)
            {
                findings.Add(new Finding(
                    "Strict-Transport-Security",
                    "warn",
                    "HSTS max-age should be at least 180 days",
                    "Set max-age to at least 15552000 (180 days)"
                ));
            }
        }

        if (!hsts.Contains("includeSubDomains"))
        {
            findings.Add(new Finding(
                "Strict-Transport-Security",
                "info",
                "Consider adding includeSubDomains to HSTS",
                "Add includeSubDomains to protect all subdomains"
            ));
        }

        if (!hsts.Contains("preload"))
        {
            findings.Add(new Finding(
                "Strict-Transport-Security",
                "info",
                "Consider adding preload to HSTS",
                "Add preload for browser preload list inclusion"
            ));
        }
    }

    private static void AnalyzeXFrameOptions(Dictionary<string, string> headers, List<Finding> findings)
    {
        var hasXfo = headers.ContainsKey("X-Frame-Options");
        var hasCspFrameAncestors = headers.TryGetValue("Content-Security-Policy", out var csp) && 
                                  csp.Contains("frame-ancestors");

        if (!hasXfo && !hasCspFrameAncestors)
        {
            findings.Add(new Finding(
                "X-Frame-Options",
                "warn",
                "X-Frame-Options header is missing and no CSP frame-ancestors directive",
                "Add X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors directive"
            ));
        }
    }

    private static void AnalyzeXContentTypeOptions(Dictionary<string, string> headers, List<Finding> findings)
    {
        if (!headers.TryGetValue("X-Content-Type-Options", out var xcto) || xcto != "nosniff")
        {
            findings.Add(new Finding(
                "X-Content-Type-Options",
                "warn",
                "X-Content-Type-Options header is missing or not set to 'nosniff'",
                "Add X-Content-Type-Options: nosniff to prevent MIME type sniffing"
            ));
        }
    }

    private static void AnalyzeReferrerPolicy(Dictionary<string, string> headers, List<Finding> findings)
    {
        if (!headers.ContainsKey("Referrer-Policy"))
        {
            findings.Add(new Finding(
                "Referrer-Policy",
                "warn",
                "Referrer-Policy header is missing",
                "Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer"
            ));
        }
    }

    private static void AnalyzePermissionsPolicy(Dictionary<string, string> headers, List<Finding> findings)
    {
        if (!headers.ContainsKey("Permissions-Policy"))
        {
            findings.Add(new Finding(
                "Permissions-Policy",
                "info",
                "Permissions-Policy header is missing",
                "Add Permissions-Policy: camera=(), geolocation=(), microphone=() to restrict browser features"
            ));
        }
    }

    private static void AnalyzeCoop(Dictionary<string, string> headers, List<Finding> findings)
    {
        if (!headers.ContainsKey("Cross-Origin-Opener-Policy"))
        {
            findings.Add(new Finding(
                "Cross-Origin-Opener-Policy",
                "info",
                "Cross-Origin-Opener-Policy header is missing",
                "Add Cross-Origin-Opener-Policy: same-origin for better isolation"
            ));
        }
    }

    private static void AnalyzeCorp(Dictionary<string, string> headers, List<Finding> findings)
    {
        if (!headers.ContainsKey("Cross-Origin-Resource-Policy"))
        {
            findings.Add(new Finding(
                "Cross-Origin-Resource-Policy",
                "info",
                "Cross-Origin-Resource-Policy header is missing",
                "Add Cross-Origin-Resource-Policy: same-origin (or cross-origin if needed)"
            ));
        }
    }

    private static void AnalyzeCoep(Dictionary<string, string> headers, List<Finding> findings)
    {
        if (!headers.ContainsKey("Cross-Origin-Embedder-Policy"))
        {
            findings.Add(new Finding(
                "Cross-Origin-Embedder-Policy",
                "info",
                "Cross-Origin-Embedder-Policy header is missing",
                "Add Cross-Origin-Embedder-Policy: require-corp if isolation is needed"
            ));
        }
    }

    private static void AnalyzeSetCookie(Dictionary<string, string> headers, List<Finding> findings)
    {
        if (!headers.TryGetValue("Set-Cookie", out var setCookie))
            return;

        var cookies = setCookie.Split(',');
        foreach (var cookie in cookies)
        {
            var cookieLower = cookie.ToLowerInvariant();
            
            if (!cookieLower.Contains("secure"))
            {
                findings.Add(new Finding(
                    "Set-Cookie",
                    "critical",
                    "Cookie missing Secure flag",
                    "Add Secure flag to cookies for HTTPS-only transmission"
                ));
            }

            if (!cookieLower.Contains("httponly"))
            {
                findings.Add(new Finding(
                    "Set-Cookie",
                    "warn",
                    "Cookie missing HttpOnly flag",
                    "Add HttpOnly flag to prevent JavaScript access"
                ));
            }

            if (!cookieLower.Contains("samesite"))
            {
                findings.Add(new Finding(
                    "Set-Cookie",
                    "warn",
                    "Cookie missing SameSite attribute",
                    "Add SameSite=Strict, Lax, or None (with Secure) based on cross-site requirements"
                ));
            }
        }
    }

    private static string CalculateGrade(List<Finding> findings)
    {
        var score = 100; // Start with A grade

        foreach (var finding in findings)
        {
            score -= finding.Severity switch
            {
                "critical" => 30,
                "warn" => 15,
                "info" => 5,
                _ => 0
            };
        }

        return score switch
        {
            >= 90 => "A",
            >= 80 => "B",
            >= 70 => "C",
            >= 60 => "D",
            >= 50 => "E",
            _ => "F"
        };
    }

    private static FixSnippets GenerateFixSnippets()
    {
        var dotNetSnippet = @"// Program.cs
app.UseHsts();

app.Use(async (context, next) =>
{
    context.Response.Headers.Add(""X-Content-Type-Options"", ""nosniff"");
    context.Response.Headers.Add(""X-Frame-Options"", ""SAMEORIGIN"");
    context.Response.Headers.Add(""Content-Security-Policy"", ""default-src 'self'; base-uri 'self'; frame-ancestors 'self'; object-src 'none'; upgrade-insecure-requests"");
    context.Response.Headers.Add(""Referrer-Policy"", ""strict-origin-when-cross-origin"");
    context.Response.Headers.Add(""Permissions-Policy"", ""camera=(), geolocation=(), microphone=()"");
    await next();
});";

        var nginxSnippet = @"# nginx.conf
add_header Strict-Transport-Security ""max-age=31536000; includeSubDomains; preload"" always;
add_header X-Content-Type-Options ""nosniff"" always;
add_header X-Frame-Options ""SAMEORIGIN"" always;
add_header Content-Security-Policy ""default-src 'self'; base-uri 'self'; frame-ancestors 'self'; object-src 'none'; upgrade-insecure-requests"" always;
add_header Referrer-Policy ""strict-origin-when-cross-origin"" always;
add_header Permissions-Policy ""camera=(), geolocation=(), microphone=()"" always;";

        var expressSnippet = @"// app.js
const helmet = require('helmet');

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: [""'self'""],
            baseUri: [""'self'""],
            frameAncestors: [""'self'""],
            objectSrc: [""'none'""],
            upgradeInsecureRequests: []
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));";

        return new FixSnippets(dotNetSnippet, nginxSnippet, expressSnippet);
    }
}
