using DesktopAuditTool.Core.Models;

namespace DesktopAuditTool.Reporting;

public class ReportManager
{
    private readonly JsonReportGenerator _jsonGen = new();
    private readonly CsvReportGenerator _csvGen = new();
    private readonly HtmlReportGenerator _htmlGen = new();
    private readonly PdfReportGenerator _pdfGen = new();
    private readonly ExcelReportGenerator _excelGen = new();
    private readonly CertInReportGenerator _certInGen = new();

    public async Task<List<string>> ExportAllFormatsAsync(AuditReport report, string outputDirectory, CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(outputDirectory)) Directory.CreateDirectory(outputDirectory);
        var baseName = $"SecurityAuditReport_{report.TargetHostname}_{DateTime.UtcNow:yyyyMMdd_HHmmss}";
        var exportedFiles = new List<string>();

        // 1. JSON
        var jsonPath = Path.Combine(outputDirectory, $"{baseName}.json");
        await _jsonGen.ExportToFileAsync(report, jsonPath, cancellationToken);
        exportedFiles.Add(jsonPath);

        // 2. CSV
        var csvPath = Path.Combine(outputDirectory, $"{baseName}.csv");
        await _csvGen.ExportToFileAsync(report, csvPath, cancellationToken);
        exportedFiles.Add(csvPath);

        // 3. HTML
        var htmlPath = Path.Combine(outputDirectory, $"{baseName}.html");
        await _htmlGen.ExportToFileAsync(report, htmlPath, cancellationToken);
        exportedFiles.Add(htmlPath);

        // 4. Excel
        var excelPath = Path.Combine(outputDirectory, $"{baseName}.xls");
        await _excelGen.ExportToFileAsync(report, excelPath, cancellationToken);
        exportedFiles.Add(excelPath);

        // 5. PDF (Printable HTML-to-PDF / PDF payload)
        var pdfPath = Path.Combine(outputDirectory, $"{baseName}.pdf.html");
        await _pdfGen.ExportToFileAsync(report, pdfPath, cancellationToken);
        exportedFiles.Add(pdfPath);

        // 6. CERT-In Incident Report
        var certInPath = Path.Combine(outputDirectory, $"{baseName}_CERT-In_Annexure-I.txt");
        var certInText = _certInGen.GenerateCertInAnnexure1(report);
        await File.WriteAllTextAsync(certInPath, certInText, cancellationToken);
        exportedFiles.Add(certInPath);

        return exportedFiles;
    }

    public HtmlReportGenerator HtmlGenerator => _htmlGen;
    public CertInReportGenerator CertInGenerator => _certInGen;
}
