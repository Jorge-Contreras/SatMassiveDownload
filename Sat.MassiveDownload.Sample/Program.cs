using Microsoft.Extensions.Configuration;
using Sat.MassiveDownload;
using Sat.MassiveDownload.Core;
using Sat.MassiveDownload.Crypto;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

var config = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json", optional: false)
    .AddEnvironmentVariables()
    .Build();

var s = config.GetSection("Sat");
bool usePfx = s.GetValue("UsePfx", true);
string pfxPath = s["PfxPath"]!;
string pfxPass = s["PfxPassword"]!;
string cerPath = s["CerPath"]!;
string keyPath = s["KeyPath"]!;
string keyPass = s["KeyPassword"]!;
string rfcSolicitante = s["RfcSolicitante"]!;
bool issued = bool.Parse(s["Issued"] ?? "false");
DateTime startUtc = DateTime.Parse(s["StartDateUtc"]!);
DateTime endUtc = DateTime.Parse(s["EndDateUtc"]!);
string? filterRfc = s["FilterRfc"];
string tipoSolicitud = s["TipoSolicitud"] ?? "CFDI";
string? estado = s["Estado"];
string outputDir = s["OutputDir"] ?? ".";

usePfx = false;
Directory.CreateDirectory(outputDir);

// 1) Load certificate
X509Certificate2 cert = usePfx
    ? CertificateLoader.FromPfx(pfxPath, pfxPass)
    : CertificateLoader.FromCerAndKey(cerPath, keyPath, keyPass);

SmokeTestCert(cert);
SmokeTestPrivateKey(cert);



// 2) Create service
ISatMassiveService svc = new SatMassiveClient();



// 3) Authenticate
Console.WriteLine("Authenticating with SAT...");
await svc.AuthenticateAsync(cert);
Console.WriteLine("OK");

// 4) Request
Console.WriteLine($"Requesting {(issued ? "Emitidos" : "Recibidos")} from {startUtc:u} to {endUtc:u}...");
var idSolicitud = await svc.RequestAsync(startUtc, endUtc, issued, rfcSolicitante, filterRfc, tipoSolicitud, estado);
Console.WriteLine($"Folio (IdSolicitud): {idSolicitud}");

// 5) Verify loop (simple)
Console.Write("Verifying");
while (true)
{
    var v = await svc.VerifyAsync(idSolicitud, rfcSolicitante);
    Console.Write($".");
    if (v.Status.Equals("Terminada", StringComparison.OrdinalIgnoreCase))
    {
        Console.WriteLine("\nSolicitud Terminada.");
        if (v.PackageIds.Count == 0)
        {
            Console.WriteLine("No packages returned.");
            break;
        }

        // 6) Download packages
        foreach (var pkgId in v.PackageIds)
        {
            Console.WriteLine($"Downloading package {pkgId}...");
            var zipBytes = await svc.DownloadPackageAsync(pkgId, rfcSolicitante);
            if (zipBytes is null) { Console.WriteLine("No data"); continue; }
            var zipPath = Path.Combine(outputDir, $"{pkgId}.zip");
            await File.WriteAllBytesAsync(zipPath, zipBytes);
            Console.WriteLine($"Saved: {zipPath}");
        }
        break;
    }
    if (v.Status.Equals("Rechazada", StringComparison.OrdinalIgnoreCase) || v.Status.Equals("Error", StringComparison.OrdinalIgnoreCase))
    {
        Console.WriteLine($"\nSolicitud rechazada o con error: {v.Code} {v.Message}");
        break;
    }

    await Task.Delay(TimeSpan.FromSeconds(15)); // simple polling for demo
}
Console.WriteLine("Done.");

static void SmokeTestCert(X509Certificate2 cert)
{
    Console.WriteLine($"Subject: {cert.Subject}");
    Console.WriteLine($"Thumbprint: {cert.Thumbprint}");
    Console.WriteLine($"HasPrivateKey: {cert.HasPrivateKey}");
    if (!cert.HasPrivateKey)
        throw new InvalidOperationException("El PFX/llave no tiene private key. Revisa clave o PFX.");
}

static void SmokeTestPrivateKey(X509Certificate2 cert)
{
    Console.WriteLine($"HasPrivateKey: {cert.HasPrivateKey}");
    using var rsa = cert.GetRSAPrivateKey();
    if (rsa is null) throw new InvalidOperationException("No se adjuntó la private key.");
    var test = rsa.Encrypt(new byte[16], RSAEncryptionPadding.Pkcs1);
    Console.WriteLine($"RSA OK, bytes: {test.Length}");
}