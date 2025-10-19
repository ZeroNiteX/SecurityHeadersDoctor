namespace SecurityHeadersDoctor.Models;

public record SecurityAnalysisResult(
    string Grade,
    List<Finding> Findings,
    Dictionary<string, string> RawHeaders,
    FixSnippets Snippets
);

public record FixSnippets(string DotNet, string Nginx, string Express);
