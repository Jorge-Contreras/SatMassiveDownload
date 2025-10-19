// Core/SatMassiveClient.cs
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Sat.MassiveDownload.Core;
using Sat.MassiveDownload.Models;




namespace Sat.MassiveDownload;

public sealed class SatMassiveClient : ISatMassiveService
{
    private readonly HttpClient _http;
    private string? _token; // WRAP access_token
    private X509Certificate2? _cert;

    // Endpoints (adjust to SAT official portal if they change):
    private const string AuthUrl = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc";
    private const string RequestUrl = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc";
    private const string VerifyUrl = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc";
    private const string DownloadUrl = "https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc";

    //Soap constants
    private const string SoapNs = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string WsseNs = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private const string WsuNs = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private const string DsNs = "http://www.w3.org/2000/09/xmldsig#";
    private const string SatNs = "http://DescargaMasivaTerceros.gob.mx";
    private const string X509V3ValueType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
    private const string Base64Encoding = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";


    public SatMassiveClient(HttpClient? http = null) => _http = http ?? new HttpClient();

    public async Task AuthenticateAsync(X509Certificate2 cert, CancellationToken ct = default)
    {
        // 1) Build WS-Security header: Timestamp + BinarySecurityToken + Signature(RSA-SHA1)
        // 2) Build SOAP envelope with <Autentica/>
        // 3) POST with SOAPAction: http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica
        // 4) Parse token from response into _token

        var soapXml = BuildAuthEnvelope(cert);                 // TODO: implement
        var req = new HttpRequestMessage(HttpMethod.Post, AuthUrl)
        {
            Content = new StringContent(soapXml, Encoding.UTF8, "text/xml")
        };
        req.Headers.Add("SOAPAction", "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica");

        var resp = await _http.SendAsync(req, ct);
        var xml = await resp.Content.ReadAsStringAsync(ct);
        resp.EnsureSuccessStatusCode();
        _cert = cert;

        _token = ExtractToken(xml);                            // TODO: implement
        if (string.IsNullOrWhiteSpace(_token))
            throw new InvalidOperationException("SAT token not found");
    }

    public async Task<string> RequestAsync(DateTime startUtc, DateTime endUtc, bool issued,
                                           string? rfcSolicitante, string? rfcFiltro = null,
                                           string tipoSolicitud = "CFDI", string? estado = null,
                                           CancellationToken ct = default)
    {
        EnsureToken();
        var envelope = BuildRequestEnvelope(startUtc, endUtc, issued, rfcSolicitante, rfcFiltro, tipoSolicitud, estado); // signature inside
        var action = issued
            ? "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaEmitidos"
            : "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaRecibidos";

        var req = new HttpRequestMessage(HttpMethod.Post, RequestUrl)
        {
            Content = new StringContent(envelope, Encoding.UTF8, "text/xml")
        };
        req.Headers.Add("SOAPAction", action);
        req.Headers.TryAddWithoutValidation("Authorization", $@"WRAP access_token=""{_token}""");

        var resp = await _http.SendAsync(req, ct);
        var xml = await resp.Content.ReadAsStringAsync(ct);
        resp.EnsureSuccessStatusCode();

        return ExtractIdSolicitud(xml); // TODO: implement
    }

    public async Task<VerifyResult> VerifyAsync(string idSolicitud, string rfcSolicitante, CancellationToken ct = default)
    {
        EnsureToken();
        var envelope = BuildVerifyEnvelope(idSolicitud, rfcSolicitante);

        var req = new HttpRequestMessage(HttpMethod.Post, VerifyUrl)
        {
            Content = new StringContent(envelope, Encoding.UTF8, "text/xml")
        };
        req.Headers.Add("SOAPAction", "http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga");
        req.Headers.TryAddWithoutValidation("Authorization", $@"WRAP access_token=""{_token}""");

        var resp = await _http.SendAsync(req, ct);
        var xml = await resp.Content.ReadAsStringAsync(ct);
        resp.EnsureSuccessStatusCode();

        return ParseVerify(xml); // <- returns Sat.MassiveDownload.Models.VerifyResult
    }


    public async Task<byte[]?> DownloadPackageAsync(string idPaquete, string rfcSolicitante, CancellationToken ct = default)
    {
        EnsureToken();
        var envelope = BuildDownloadEnvelope(idPaquete, rfcSolicitante); // signature inside

        var req = new HttpRequestMessage(HttpMethod.Post, DownloadUrl)
        {
            Content = new StringContent(envelope, Encoding.UTF8, "text/xml")
        };
        req.Headers.Add("SOAPAction", "http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar");
        req.Headers.TryAddWithoutValidation("Authorization", $@"WRAP access_token=""{_token}""");

        var resp = await _http.SendAsync(req, ct);
        var xml = await resp.Content.ReadAsStringAsync(ct);
        resp.EnsureSuccessStatusCode();

        var base64 = ExtractTag(xml, "Paquete"); // TODO
        return string.IsNullOrWhiteSpace(base64) ? null : Convert.FromBase64String(base64);
    }

    private void EnsureToken()
    {
        if (string.IsNullOrWhiteSpace(_token))
            throw new InvalidOperationException("Not authenticated: call AuthenticateAsync first");
    }

    // ===== Helpers to implement =====
    // Dentro de SatMassiveClient

    private static string ExtractIdSolicitud(string xml)
    {
        var d = new XmlDocument { PreserveWhitespace = true };
        d.LoadXml(xml);

        // Try attribute on the *Result element* first (newer SAT shape).
        var result = d.SelectSingleNode("//*[local-name()='SolicitaDescargaEmitidosResult' or local-name()='SolicitaDescargaRecibidosResult']") as XmlElement;
        var id = result?.GetAttribute("IdSolicitud");
        if (!string.IsNullOrWhiteSpace(id))
            return id.Trim();

        // Fallbacks: nested node or any IdSolicitud anywhere.
        var n = d.SelectSingleNode("//*[local-name()='IdSolicitud']");
        return n?.InnerText?.Trim() ?? string.Empty;
    }



    private static string BuildAuthEnvelope(X509Certificate2 cert)
    {
        // Validaciones básicas
        RSA? rsa = cert.GetRSAPrivateKey();
        if (rsa is null) throw new InvalidOperationException("El certificado no contiene llave privada RSA.");

        var doc = new XmlDocument { PreserveWhitespace = true };

        // Envelope
        var env = doc.CreateElement("s", "Envelope", SoapNs);
        doc.AppendChild(env);

        // Header
        var header = doc.CreateElement("s", "Header", SoapNs);
        env.AppendChild(header);

        // wsse:Security (con mustUnderstand="1")
        var security = doc.CreateElement("wsse", "Security", WsseNs);
        var mustUnderstand = doc.CreateAttribute("s", "mustUnderstand", SoapNs);
        mustUnderstand.Value = "1";
        security.Attributes.Append(mustUnderstand);
        //// Asegura que el prefijo wsu esté declarado en el scope del Security
        //var attrWsuNs = doc.CreateAttribute("xmlns", "wsu", "http://www.w3.org/2000/xmlns/");
        //attrWsuNs.Value = WsuNs;
        //security.Attributes.Append(attrWsuNs);

        header.AppendChild(security);

        // wsu:Timestamp (Id = _0)
        var timestamp = doc.CreateElement("wsu", "Timestamp", WsuNs);
        var idAttr = doc.CreateAttribute("wsu", "Id", WsuNs);
        idAttr.Value = "_0";
        timestamp.Attributes.Append(idAttr);
        // AYUDA a SignedXml: atributo sin namespace para resolver el #_0
        var idAttrCompat = doc.CreateAttribute("Id");
        idAttrCompat.Value = "_0";
        timestamp.Attributes.Append(idAttrCompat);

        var created = doc.CreateElement("wsu", "Created", WsuNs);
        created.InnerText = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

        var expires = doc.CreateElement("wsu", "Expires", WsuNs);
        expires.InnerText = DateTime.UtcNow.AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ssZ");

        timestamp.AppendChild(created);
        timestamp.AppendChild(expires);
        security.AppendChild(timestamp);

        // wsse:BinarySecurityToken con el .cer en Base64
        var bst = doc.CreateElement("wsse", "BinarySecurityToken", WsseNs);
        string bstId = "uuid-" + Guid.NewGuid().ToString("D");
        var bstIdAttr = doc.CreateAttribute("wsu", "Id", WsuNs);
        bstIdAttr.Value = bstId;
        bst.Attributes.Append(bstIdAttr);

        var valueTypeAttr = doc.CreateAttribute("ValueType");
        valueTypeAttr.Value = X509V3ValueType;
        bst.Attributes.Append(valueTypeAttr);

        var encodingAttr = doc.CreateAttribute("EncodingType");
        encodingAttr.Value = Base64Encoding;
        bst.Attributes.Append(encodingAttr);

        bst.InnerText = Convert.ToBase64String(cert.RawData);
        security.AppendChild(bst);

        // ds:Signature sobre el Timestamp (#_0) con RSA-SHA1 y KeyInfo apuntando al BinarySecurityToken
        var signedXml = new SignedXml(doc)
        {
            SigningKey = rsa
        };
        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;    // exc-c14n
        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;                    // rsa-sha1 (requisito SAT)

        var reference = new Reference("#_0")
        {
            DigestMethod = SignedXml.XmlDsigSHA1Url
        };
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);

        // KeyInfo con wsse:SecurityTokenReference → wsse:Reference URI="#{bstId}"
        var str = doc.CreateElement("wsse", "SecurityTokenReference", WsseNs);
        var refNode = doc.CreateElement("wsse", "Reference", WsseNs);

        var uriAttr = doc.CreateAttribute("URI");
        uriAttr.Value = "#" + bstId;
        refNode.Attributes.Append(uriAttr);

        var vtAttr = doc.CreateAttribute("ValueType");
        vtAttr.Value = X509V3ValueType;
        refNode.Attributes.Append(vtAttr);

        str.AppendChild(refNode);

        var ki = new KeyInfo();
        ki.AddClause(new KeyInfoNode(str));
        signedXml.KeyInfo = ki;

        signedXml.ComputeSignature();
        XmlElement sig = signedXml.GetXml();
        security.AppendChild(sig);

        // Body con Autentica
        var body = doc.CreateElement("s", "Body", SoapNs);
        env.AppendChild(body);

        var autentica = doc.CreateElement("Autentica", SatNs);
        body.AppendChild(autentica);

        return doc.OuterXml;
    }
    
    private string BuildRequestEnvelope(
    DateTime s, DateTime e, bool issued,
    string? rfcSol, string? rfcFiltro,
    string tipo, string? estado)
    {
        if (_cert is null) throw new InvalidOperationException("Cert not set. Call AuthenticateAsync first.");
        RSA? rsa = _cert.GetRSAPrivateKey();
        if (rsa is null) throw new InvalidOperationException("Certificate has no RSA private key.");

        var doc = new XmlDocument { PreserveWhitespace = true };

        // <s:Envelope><s:Header/><s:Body>...</s:Body></s:Envelope>
        var env = doc.CreateElement("s", "Envelope", SoapNs);
        doc.AppendChild(env);
        var header = doc.CreateElement("s", "Header", SoapNs); env.AppendChild(header);
        var body = doc.CreateElement("s", "Body", SoapNs); env.AppendChild(body);

        // Root operation
        string opName = issued ? "SolicitaDescargaEmitidos" : "SolicitaDescargaRecibidos";
        var op = doc.CreateElement("des", opName, "http://DescargaMasivaTerceros.sat.gob.mx");
        body.AppendChild(op);

        // <des:solicitud ...>
        var solicitud = doc.CreateElement("des", "solicitud", "http://DescargaMasivaTerceros.sat.gob.mx");
        op.AppendChild(solicitud);

        void SetAttr(string name, string value)
        {
            var a = doc.CreateAttribute(name);
            a.Value = value;
            solicitud.Attributes.Append(a);
        }
        // Common required
        if (!string.IsNullOrWhiteSpace(rfcSol)) SetAttr("RfcSolicitante", rfcSol);
        SetAttr("FechaInicial", s.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"));
        SetAttr("FechaFinal", e.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"));
        if (!string.IsNullOrWhiteSpace(tipo)) SetAttr("TipoSolicitud", tipo);

        // v1.5 rule: Recibidos + XML => only Vigente is allowed
        if (!issued && string.Equals(tipo, "CFDI", StringComparison.OrdinalIgnoreCase))
        {
            SetAttr("EstadoComprobante", "Vigente");  // default to Vigente to avoid 301
        }
        else if (!string.IsNullOrWhiteSpace(estado))
        {
            SetAttr("EstadoComprobante", estado);
        }

        // REQUIRED pairs by mode (don’t change these)
        if (issued)
        {
            // Emitidos: Emisor = solicitante, optional filter Receptor
            if (!string.IsNullOrWhiteSpace(rfcSol)) SetAttr("RfcEmisor", rfcSol);
            if (!string.IsNullOrWhiteSpace(rfcFiltro)) SetAttr("RfcReceptor", rfcFiltro);
        }
        else
        {
            // Recibidos: Receptor = solicitante, optional filter Emisor
            if (!string.IsNullOrWhiteSpace(rfcSol)) SetAttr("RfcReceptor", rfcSol);
            if (!string.IsNullOrWhiteSpace(rfcFiltro)) SetAttr("RfcEmisor", rfcFiltro);
        }


        // Sign <des:solicitud> (enveloped, exc-c14n, RSA-SHA1)
        var signedXml = new SignedXml(solicitud) { SigningKey = rsa };
        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;

        var reference = new Reference("") { DigestMethod = SignedXml.XmlDsigSHA1Url };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);

        var ki = new KeyInfo();
        var x509 = new KeyInfoX509Data(_cert);
        x509.AddCertificate(_cert);
        ki.AddClause(x509);
        signedXml.KeyInfo = ki;

        signedXml.ComputeSignature();
        solicitud.AppendChild(doc.ImportNode(signedXml.GetXml(), true));

        return doc.OuterXml;
    }


    private string BuildVerifyEnvelope(string idSolicitud, string rfcSolicitante)
{
    if (_cert is null) throw new InvalidOperationException("Cert not set.");
    RSA? rsa = _cert.GetRSAPrivateKey();
    if (rsa is null) throw new InvalidOperationException("Certificate has no RSA private key.");

    var doc = new XmlDocument { PreserveWhitespace = true };

    var env = doc.CreateElement("s", "Envelope", SoapNs);
    doc.AppendChild(env);
    var header = doc.CreateElement("s", "Header", SoapNs); env.AppendChild(header);
    var body   = doc.CreateElement("s", "Body",   SoapNs); env.AppendChild(body);

    var root = doc.CreateElement("des", "VerificaSolicitudDescarga", "http://DescargaMasivaTerceros.sat.gob.mx");
    body.AppendChild(root);

    var sol = doc.CreateElement("des", "solicitud", "http://DescargaMasivaTerceros.sat.gob.mx");
    root.AppendChild(sol);

    void SetAttr(string n, string v)
    {
        var a = doc.CreateAttribute(n); a.Value = v; sol.Attributes.Append(a);
    }
    SetAttr("IdSolicitud", idSolicitud);
    SetAttr("RfcSolicitante", rfcSolicitante);

    var sx = new SignedXml(sol) { SigningKey = rsa };
    sx.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
    sx.SignedInfo.SignatureMethod        = SignedXml.XmlDsigRSASHA1Url;

    var r = new Reference("") { DigestMethod = SignedXml.XmlDsigSHA1Url };
    r.AddTransform(new XmlDsigEnvelopedSignatureTransform());
    r.AddTransform(new XmlDsigExcC14NTransform());
    sx.AddReference(r);

    var ki = new KeyInfo();
    var x509 = new KeyInfoX509Data(_cert);
    x509.AddCertificate(_cert);
    ki.AddClause(x509);
    sx.KeyInfo = ki;

    sx.ComputeSignature();
    sol.AppendChild(doc.ImportNode(sx.GetXml(), true));

    return doc.OuterXml;
}

    private string BuildDownloadEnvelope(string idPaquete, string rfcSolicitante)
    {
        if (_cert is null) throw new InvalidOperationException("Cert not set.");
        RSA? rsa = _cert.GetRSAPrivateKey();
        if (rsa is null) throw new InvalidOperationException("Certificate has no RSA private key.");

        var doc = new XmlDocument { PreserveWhitespace = true };

        var env = doc.CreateElement("s", "Envelope", SoapNs);
        doc.AppendChild(env);
        var header = doc.CreateElement("s", "Header", SoapNs); env.AppendChild(header);
        var body = doc.CreateElement("s", "Body", SoapNs); env.AppendChild(body);

        // Service expects: des:PeticionDescargaMasivaTercerosEntrada / des:peticionDescarga
        var root = doc.CreateElement("des", "PeticionDescargaMasivaTercerosEntrada", "http://DescargaMasivaTerceros.sat.gob.mx");
        body.AppendChild(root);

        var pet = doc.CreateElement("des", "peticionDescarga", "http://DescargaMasivaTerceros.sat.gob.mx");
        root.AppendChild(pet);

        void SetAttr(string n, string v)
        {
            var a = doc.CreateAttribute(n); a.Value = v; pet.Attributes.Append(a);
        }
        SetAttr("IdPaquete", idPaquete);
        SetAttr("RfcSolicitante", rfcSolicitante);

        var sx = new SignedXml(pet) { SigningKey = rsa };
        sx.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        sx.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;

        var r = new Reference("") { DigestMethod = SignedXml.XmlDsigSHA1Url };
        r.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        r.AddTransform(new XmlDsigExcC14NTransform());
        sx.AddReference(r);

        var ki = new KeyInfo();
        var x509 = new KeyInfoX509Data(_cert);
        x509.AddCertificate(_cert);
        ki.AddClause(x509);
        sx.KeyInfo = ki;

        sx.ComputeSignature();
        pet.AppendChild(doc.ImportNode(sx.GetXml(), true));

        return doc.OuterXml;
    }

    private static string ExtractTag(string xml, string tag)
    {
        var d = new XmlDocument { PreserveWhitespace = true };
        d.LoadXml(xml);
        return d.SelectSingleNode($"//*[local-name()='{tag}']")?.InnerText?.Trim() ?? string.Empty;
    }

    private static string ExtractToken(string xml)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);

        // Busca <AutenticaResult> en cualquier namespace
        var node = doc.SelectSingleNode("/*[local-name()='Envelope']/*[local-name()='Body']//*[local-name()='AutenticaResult']")
                   ?? doc.SelectSingleNode("//*[local-name()='AutenticaResult']");

        return node?.InnerText?.Trim() ?? string.Empty;
    }

   

    private static readonly IReadOnlyDictionary<string, string> CodigoEstadoSolicitudMap = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        // “Códigos de Solicitud de Descarga Masiva”
        ["5000"] = "Solicitud aceptada",
        ["5002"] = "Se agotó el límite de solicitudes (por vida) para esos parámetros",
        ["5003"] = "Tope máximo de resultados superado",
        ["5004"] = "No se encontró información para esa solicitud",
        ["5005"] = "Solicitud duplicada"
        // 5001 no aparece documentado aquí; si llega, lo tratamos como “desconocido”.
    };

    private static readonly IReadOnlyDictionary<string, string> CodEstatusMap = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        // Códigos del servicio de verificación (no del workflow de la solicitud)
        ["5000"] = "Verificación OK",
        ["300"] = "Usuario no válido",
        ["301"] = "XML mal formado",
        ["302"] = "Sello mal formado",
        ["303"] = "Sello no corresponde con RfcSolicitante",
        ["304"] = "Certificado revocado o caduco",
        ["305"] = "Certificado inválido",
        ["5003"] = "Tope máximo de elementos",
        ["5004"] = "No se encontró la información",
        ["5011"] = "Límite de descargas por folio por día"
    };

    private static VerifyResult ParseVerify(string xml)
    {
        var d = new XmlDocument { PreserveWhitespace = true };
        d.LoadXml(xml);

        var res = d.SelectSingleNode("//*[local-name()='VerificaSolicitudDescargaResult']") as XmlElement
                  ?? throw new InvalidOperationException("No se encontró VerificaSolicitudDescargaResult");

        string msg = res.GetAttribute("Mensaje");
        string codEst = res.GetAttribute("CodEstatus");
        string codSol = res.GetAttribute("CodigoEstadoSolicitud");
        string estStr = res.GetAttribute("EstadoSolicitud");
        string numStr = res.GetAttribute("NumeroCFDIs");

        int.TryParse(numStr, out int nCfdis);
        int.TryParse(estStr, out int estInt);

        var estadoEnum = Enum.IsDefined(typeof(EstadoSolicitud), estInt)
            ? (EstadoSolicitud)estInt
            : EstadoSolicitud.Error;

        // Ids de paquetes: atributo o elementos (robusto)
        var ids = new List<string>();
        var attrIds = res.GetAttribute("IdsPaquetes");
        if (!string.IsNullOrWhiteSpace(attrIds))
        {
            foreach (var p in attrIds.Split(new[] { ',', ' ', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries))
                ids.Add(p);
        }
        else
        {
            foreach (XmlNode n in res.SelectNodes("./*[local-name()='IdsPaquetes']"))
            {
                var t = n.InnerText?.Trim();
                if (!string.IsNullOrEmpty(t)) ids.Add(t);
            }
        }

        string human = estadoEnum switch
        {
            EstadoSolicitud.Terminada => "Terminada",
            EstadoSolicitud.EnProceso => "En proceso",
            EstadoSolicitud.Aceptada => "Aceptada",
            EstadoSolicitud.Rechazada => "Rechazada",
            EstadoSolicitud.Error => "Error",
            EstadoSolicitud.Vencida => "Vencida (72h)",
            _ => $"Estado {estStr}"
        };

        // Mensajes amigables (si aplica)
        if (!string.IsNullOrWhiteSpace(codSol) && CodigoEstadoSolicitudMap.TryGetValue(codSol, out var m1))
            human = $"{human} · {m1}";
        if (!string.IsNullOrWhiteSpace(codEst) && CodEstatusMap.TryGetValue(codEst, out var m2))
            human = $"{human} · {m2}";

        bool isFinal = (estadoEnum == EstadoSolicitud.Terminada) || (ids.Count > 0);

        return new VerifyResult
        {
            Mensaje = msg,
            CodEstatus = codEst,
            CodigoEstadoSolicitud = codSol,
            Estado = estadoEnum,
            NumeroCfdis = nCfdis,
            PackageIds = ids,
            IsFinal = isFinal,
            HumanStatus = string.IsNullOrWhiteSpace(human) ? msg : human
        };
    }






}
