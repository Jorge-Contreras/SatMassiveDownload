using System.Security.Cryptography.X509Certificates;
using Sat.MassiveDownload.Models;

namespace Sat.MassiveDownload.Core;

public interface ISatMassiveService
{
    Task AuthenticateAsync(X509Certificate2 cert, CancellationToken ct = default);
    Task<string> RequestAsync(DateTime startUtc, DateTime endUtc, bool issued,
                              string? rfcSolicitante, string? rfcFiltro = null,
                              string tipoSolicitud = "CFDI", string? estado = null,
                              CancellationToken ct = default);

    // MUST return Task<VerifyResult> from Models
    Task<VerifyResult> VerifyAsync(string idSolicitud, string rfcSolicitante, CancellationToken ct = default);

    Task<byte[]?> DownloadPackageAsync(string idPaquete, string rfcSolicitante, CancellationToken ct = default);
}
