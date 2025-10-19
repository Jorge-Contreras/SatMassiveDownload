using Microsoft.Extensions.Configuration;
using Sat.MassiveDownload;
using Sat.MassiveDownload.Core;
using Sat.MassiveDownload.Crypto;
using Sat.MassiveDownload.Models;
using System.Globalization;
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
DateTime startUtc = ParseToUtc(s["StartDateUtc"]!);
DateTime endUtc = ParseToUtc(s["EndDateUtc"]!);
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
var pollDelay = TimeSpan.FromSeconds(15);
var timeout = TimeSpan.FromMinutes(12);
var started = DateTime.UtcNow;

while (true)
{
    var v = await svc.VerifyAsync(idSolicitud, rfcSolicitante);
    Console.Write('.');

    // If packages are already listed, we can safely download now
    if (v.PackageIds.Count > 0)
    {
        Console.WriteLine("\nPaquetes listos (descargando)...");
        foreach (var pkgId in v.PackageIds)
        {
            var bytes = await svc.DownloadPackageAsync(pkgId, rfcSolicitante);
            var path = Path.Combine(outputDir, $"{pkgId}.zip");
            await File.WriteAllBytesAsync(path, bytes!);
            Console.WriteLine($"ZIP guardado: {path}");
        }
        break; // <-- exit after download
    }

    if (v.Estado == EstadoSolicitud.Terminada)
    {
        Console.WriteLine("\nSolicitud Terminada.");
        if (v.NumeroCfdis == 0 || v.PackageIds.Count == 0)
        {
            Console.WriteLine("Terminada sin paquetes/CFDIs.");
        }
        else
        {
            foreach (var pkgId in v.PackageIds)
            {
                var bytes = await svc.DownloadPackageAsync(pkgId, rfcSolicitante);
                var path = Path.Combine(outputDir, $"{pkgId}.zip");
                await File.WriteAllBytesAsync(path, bytes!);
                Console.WriteLine($"ZIP guardado: {path}");
            }
        }
        break; // <-- exit
    }
    else if (v.Estado == EstadoSolicitud.Rechazada || v.Estado == EstadoSolicitud.Error || v.Estado == EstadoSolicitud.Vencida)
    {
        Console.WriteLine($"\nFinalizada sin éxito: {v.HumanStatus} (CodEstatus={v.CodEstatus}, CodigoEstadoSolicitud={v.CodigoEstadoSolicitud})");
        break; // <-- exit
    }
    else if (v.CodigoEstadoSolicitud == "5004") // No se encontró info
    {
        Console.WriteLine("\nNo hay información para esos parámetros (5004).");
        break; // <-- exit
    }
    else
    {
        Console.WriteLine($" Aún en proceso: {v.HumanStatus}");
    }

    // Timeout / cancellation safety
    if (DateTime.UtcNow - started > timeout)
    {
        Console.WriteLine("\nTiempo de espera agotado esperando la terminación.");
        break; // <-- exit
    }

    await Task.Delay(pollDelay);
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

static DateTime ParseToUtc(string text)
{
    // Accepts "Z", explicit offsets, or local, and normalizes to UTC exactly once
    var dto = DateTimeOffset.Parse(text, CultureInfo.InvariantCulture,
        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
    return dto.UtcDateTime; // Kind=Utc
}