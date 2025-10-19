using SecurityHeadersDoctor.Models;
using SecurityHeadersDoctor.SecurityHeaders;

namespace SecurityHeadersDoctor.Tests;

public class AnalyzerTests
{
    [Fact]
    public void Analyze_GoodSecurityHeaders_ReturnsGradeBOrBetter()
    {
        // Arrange - Good security headers
        var headers = new Dictionary<string, string>
        {
            ["Content-Security-Policy"] = "default-src 'self'; base-uri 'self'; frame-ancestors 'self'; object-src 'none'",
            ["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload",
            ["X-Content-Type-Options"] = "nosniff",
            ["X-Frame-Options"] = "SAMEORIGIN",
            ["Referrer-Policy"] = "strict-origin-when-cross-origin",
            ["Permissions-Policy"] = "camera=(), geolocation=(), microphone=()"
        };

        // Act
        var result = Analyzer.Analyze(headers);

        // Assert
        Assert.True(result.Grade == "A" || result.Grade == "B", $"Expected grade A or B, got {result.Grade}");
        // Good headers should have minimal findings (maybe some info-level suggestions)
        Assert.True(result.Findings.Count <= 4, $"Should have minimal findings for good headers, got {result.Findings.Count}");
    }

    [Fact]
    public void Analyze_NoSecurityHeaders_ReturnsGradeEOrWorse()
    {
        // Arrange - No security headers
        var headers = new Dictionary<string, string>
        {
            ["Content-Type"] = "text/html",
            ["Server"] = "nginx/1.18.0"
        };

        // Act
        var result = Analyzer.Analyze(headers);

        // Assert
        Assert.True(result.Grade == "E" || result.Grade == "F", $"Expected grade E or F, got {result.Grade}");
        
        // Should have critical findings for missing CSP
        var cspFinding = result.Findings.FirstOrDefault(f => f.Name == "Content-Security-Policy");
        Assert.NotNull(cspFinding);
        Assert.Equal("critical", cspFinding.Severity);
        
        // Should have warnings for missing HSTS, X-CTO, etc.
        var hstsFinding = result.Findings.FirstOrDefault(f => f.Name == "Strict-Transport-Security");
        Assert.NotNull(hstsFinding);
        Assert.Equal("warn", hstsFinding.Severity);
    }

    [Fact]
    public void Analyze_RiskyCsp_ReturnsWarning()
    {
        // Arrange - Risky CSP with unsafe-inline
        var headers = new Dictionary<string, string>
        {
            ["Content-Security-Policy"] = "default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
            ["Strict-Transport-Security"] = "max-age=31536000",
            ["X-Content-Type-Options"] = "nosniff"
        };

        // Act
        var result = Analyzer.Analyze(headers);

        // Assert
        var unsafeInlineFinding = result.Findings.FirstOrDefault(f => 
            f.Name == "Content-Security-Policy" && f.Message.Contains("unsafe-inline"));
        Assert.NotNull(unsafeInlineFinding);
        Assert.Equal("warn", unsafeInlineFinding.Severity);

        var unsafeEvalFinding = result.Findings.FirstOrDefault(f => 
            f.Name == "Content-Security-Policy" && f.Message.Contains("unsafe-eval"));
        Assert.NotNull(unsafeEvalFinding);
        Assert.Equal("warn", unsafeEvalFinding.Severity);

        var defaultSrcFinding = result.Findings.FirstOrDefault(f => 
            f.Name == "Content-Security-Policy" && f.Message.Contains("default-src *"));
        Assert.NotNull(defaultSrcFinding);
        Assert.Equal("warn", defaultSrcFinding.Severity);
    }

    [Fact]
    public void Analyze_WeakHsts_ReturnsWarning()
    {
        // Arrange - HSTS with short max-age
        var headers = new Dictionary<string, string>
        {
            ["Content-Security-Policy"] = "default-src 'self'",
            ["Strict-Transport-Security"] = "max-age=86400", // 1 day
            ["X-Content-Type-Options"] = "nosniff"
        };

        // Act
        var result = Analyzer.Analyze(headers);

        // Assert
        var hstsFinding = result.Findings.FirstOrDefault(f => 
            f.Name == "Strict-Transport-Security" && f.Message.Contains("max-age"));
        Assert.NotNull(hstsFinding);
        Assert.Equal("warn", hstsFinding.Severity);
    }

    [Fact]
    public void Analyze_UnsecureCookies_ReturnsCritical()
    {
        // Arrange - Cookies without Secure flag
        var headers = new Dictionary<string, string>
        {
            ["Content-Security-Policy"] = "default-src 'self'",
            ["Strict-Transport-Security"] = "max-age=31536000",
            ["X-Content-Type-Options"] = "nosniff",
            ["Set-Cookie"] = "sessionid=abc123; HttpOnly" // Missing Secure flag
        };

        // Act
        var result = Analyzer.Analyze(headers);

        // Assert
        var cookieFinding = result.Findings.FirstOrDefault(f => 
            f.Name == "Set-Cookie" && f.Message.Contains("Secure flag"));
        Assert.NotNull(cookieFinding);
        Assert.Equal("critical", cookieFinding.Severity);
    }

    [Fact]
    public void Analyze_GeneratesFixSnippets()
    {
        // Arrange
        var headers = new Dictionary<string, string>();

        // Act
        var result = Analyzer.Analyze(headers);

        // Assert
        Assert.NotNull(result.Snippets);
        Assert.NotEmpty(result.Snippets.DotNet);
        Assert.NotEmpty(result.Snippets.Nginx);
        Assert.NotEmpty(result.Snippets.Express);
        
        // Check that snippets contain expected content
        Assert.Contains("UseHsts", result.Snippets.DotNet);
        Assert.Contains("add_header", result.Snippets.Nginx);
        Assert.Contains("helmet", result.Snippets.Express);
    }

    [Fact]
    public void Analyze_CaseInsensitiveHeaders_WorksCorrectly()
    {
        // Arrange - Headers with different cases
        var headers = new Dictionary<string, string>
        {
            ["content-security-policy"] = "default-src 'self'",
            ["STRICT-TRANSPORT-SECURITY"] = "max-age=31536000",
            ["X-Content-Type-Options"] = "nosniff"
        };

        // Act
        var result = Analyzer.Analyze(headers);

        // Assert
        Assert.NotNull(result.RawHeaders);
        Assert.True(result.RawHeaders.ContainsKey("content-security-policy"));
        Assert.True(result.RawHeaders.ContainsKey("STRICT-TRANSPORT-SECURITY"));
        Assert.True(result.RawHeaders.ContainsKey("X-Content-Type-Options"));
        
        // Should not have critical findings for CSP since it exists
        var cspFinding = result.Findings.FirstOrDefault(f => f.Name == "Content-Security-Policy" && f.Severity == "critical");
        Assert.Null(cspFinding);
    }
}
