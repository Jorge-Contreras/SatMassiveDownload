// Models/VerifyResult.cs
namespace Sat.MassiveDownload.Models;

public enum EstadoSolicitud
{
    Aceptada = 1,
    EnProceso = 2,
    Terminada = 3,
    Error = 4,
    Rechazada = 5,
    Vencida = 6
}

public sealed class VerifyResult
{
    public string Mensaje { get; init; } = "";
    public string CodEstatus { get; init; } = "";
    public string CodigoEstadoSolicitud { get; init; } = "";
    public EstadoSolicitud Estado { get; init; } = EstadoSolicitud.Error;
    public int NumeroCfdis { get; init; }
    public List<string> PackageIds { get; init; } = new();
    public bool IsFinal { get; init; }
    public string HumanStatus { get; init; } = "";
}
