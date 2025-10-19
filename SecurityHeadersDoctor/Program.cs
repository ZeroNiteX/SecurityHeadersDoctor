using System.Text.Json.Serialization;
using SecurityHeadersDoctor.Models;
using SecurityHeadersDoctor.SecurityHeaders;

var builder = WebApplication.CreateSlimBuilder(args);

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
});

builder.Services.AddHttpClient();

var app = builder.Build();

// Global error handling
app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (TaskCanceledException)
    {
        context.Response.StatusCode = 504;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync("""{"error": "Request timeout"}""");
    }
    catch (Exception ex)
    {
        context.Response.StatusCode = 500;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync($$"""{"error": "Internal server error: {{ex.Message}}"}""");
    }
});

// Serve static files
app.UseDefaultFiles();
app.UseStaticFiles();

// API endpoints
app.MapPost("/inspect", async (InspectRequest request, HttpClient httpClient) =>
{
    try
    {
        var response = await httpClient.GetAsync(request.Url);
        var headers = new Dictionary<string, string>();
        
        foreach (var header in response.Headers)
        {
            headers[header.Key] = string.Join(", ", header.Value);
        }
        
        foreach (var header in response.Content.Headers)
        {
            headers[header.Key] = string.Join(", ", header.Value);
        }

        var result = Analyzer.Analyze(headers);
        return Results.Ok(result);
    }
    catch (HttpRequestException ex)
    {
        return Results.BadRequest(new { error = $"Failed to fetch URL: {ex.Message}" });
    }
    catch (UriFormatException)
    {
        return Results.BadRequest(new { error = "Invalid URL format" });
    }
    catch (ArgumentException)
    {
        return Results.BadRequest(new { error = "Invalid URL format" });
    }
});

app.MapGet("/healthz", () => Results.Ok(new { status = "ok", time = DateTime.UtcNow }));

app.MapGet("/version", () => Results.Ok(new { name = "SecurityHeadersDoctor", version = "0.1.0" }));

app.Run();

[JsonSerializable(typeof(InspectRequest))]
[JsonSerializable(typeof(SecurityAnalysisResult))]
[JsonSerializable(typeof(Finding))]
[JsonSerializable(typeof(FixSnippets))]
internal partial class AppJsonSerializerContext : JsonSerializerContext
{
}

// Make Program class accessible for testing
public partial class Program { }