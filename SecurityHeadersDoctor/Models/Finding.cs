namespace SecurityHeadersDoctor.Models;

public record Finding(string Name, string Severity, string Message, string Suggestion);
