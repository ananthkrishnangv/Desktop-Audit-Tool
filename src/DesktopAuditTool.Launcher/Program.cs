using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;

namespace DesktopAuditTool.Launcher;

static class Program
{
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);

    private const uint MB_OK = 0x00000000;
    private const uint MB_ICONERROR = 0x00000010;
    private const uint MB_ICONINFORMATION = 0x00000040;

    [STAThread]
    static int Main(string[] args)
    {
        try
        {
            // Handle --help
            if (args.Length > 0 && (args[0] == "--help" || args[0] == "-h" || args[0] == "/?"))
            {
                MessageBox(IntPtr.Zero,
                    "Enterprise Desktop Security Audit Tool - Standalone Portable Launcher\n\n" +
                    "Usage:\n" +
                    "  DesktopAuditTool-Portable.exe [options]\n\n" +
                    "Options:\n" +
                    "  --extract-only <directory>   Extract all tool files & documentation to directory without running\n" +
                    "  --portable                   Extract to local folder next to the executable\n" +
                    "  --reinstall                  Force re-extraction of all runtime files\n" +
                    "  --cli [cli args]             Run the headless CLI audit tool directly",
                    "Desktop Security Audit Tool", MB_OK | MB_ICONINFORMATION);
                return 0;
            }

            // Handle --extract-only
            if (args.Length >= 2 && (args[0] == "--extract-only" || args[0] == "-x"))
            {
                var targetDir = Path.GetFullPath(args[1]);
                ExtractPayload(targetDir, force: true);
                MessageBox(IntPtr.Zero,
                    $"Application and documentation successfully extracted to:\n{targetDir}",
                    "Extraction Complete", MB_OK | MB_ICONINFORMATION);
                return 0;
            }

            bool forceReinstall = args.Contains("--reinstall");
            bool isPortableLocal = args.Contains("--portable");
            bool isCliMode = args.Contains("--cli");

            string appDir;
            if (isPortableLocal)
            {
                var exeDir = AppContext.BaseDirectory;
                appDir = Path.Combine(exeDir, "DesktopAuditTool_App");
            }
            else
            {
                var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                appDir = Path.Combine(localAppData, "DesktopAuditTool", "v1.0.0");
            }

            var winUiExe = Path.Combine(appDir, "DesktopAuditTool.WinUI.exe");
            var cliExe = Path.Combine(appDir, "CLI", "DesktopAuditTool.App.exe");
            var stampFile = Path.Combine(appDir, ".extracted_stamp");

            var assembly = Assembly.GetExecutingAssembly();
            long payloadLength = 0;
            using (var stream = assembly.GetManifestResourceStream("Payload.zip"))
            {
                if (stream != null) payloadLength = stream.Length;
            }

            bool stampMatches = File.Exists(stampFile) && File.Exists(winUiExe) && (File.ReadAllText(stampFile) == payloadLength.ToString());

            // Extract if not present, forced, or payload updated
            if (forceReinstall || !stampMatches)
            {
                ExtractPayload(appDir, force: true);
                try { File.WriteAllText(stampFile, payloadLength.ToString()); } catch { }
            }

            string exeToLaunch = isCliMode && File.Exists(cliExe) ? cliExe : winUiExe;

            if (!File.Exists(exeToLaunch))
            {
                MessageBox(IntPtr.Zero,
                    $"Failed to locate executable after extraction:\n{exeToLaunch}",
                    "Launch Error", MB_OK | MB_ICONERROR);
                return 1;
            }

            // Forward arguments
            var filteredArgs = args.Where(a => a != "--reinstall" && a != "--portable").ToArray();
            var startInfo = new ProcessStartInfo
            {
                FileName = exeToLaunch,
                Arguments = string.Join(" ", filteredArgs.Select(a => a.Contains(' ') ? $"\"{a}\"" : a)),
                WorkingDirectory = appDir,
                UseShellExecute = true
            };

            var process = Process.Start(startInfo);
            if (process == null)
            {
                MessageBox(IntPtr.Zero,
                    "Failed to start desktop audit process.",
                    "Launch Error", MB_OK | MB_ICONERROR);
                return 1;
            }

            return 0;
        }
        catch (Exception ex)
        {
            MessageBox(IntPtr.Zero,
                $"An unexpected error occurred during launch:\n{ex.Message}",
                "Desktop Security Audit Tool - Error", MB_OK | MB_ICONERROR);
            return 1;
        }
    }

    private static void ExtractPayload(string destinationDirectory, bool force = false)
    {
        Directory.CreateDirectory(destinationDirectory);

        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream("Payload.zip");
        if (stream == null)
        {
            throw new InvalidOperationException("Embedded payload resource 'Payload.zip' was not found inside the executable.");
        }

        using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
        foreach (var entry in archive.Entries)
        {
            if (string.IsNullOrEmpty(entry.Name) && entry.FullName.EndsWith('/'))
            {
                // Directory
                Directory.CreateDirectory(Path.Combine(destinationDirectory, entry.FullName));
                continue;
            }

            var fullPath = Path.Combine(destinationDirectory, entry.FullName);
            var parentDir = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrEmpty(parentDir))
            {
                Directory.CreateDirectory(parentDir);
            }

            // Skip if exists and not force
            if (!force && File.Exists(fullPath))
            {
                continue;
            }

            entry.ExtractToFile(fullPath, overwrite: true);
        }
    }
}
