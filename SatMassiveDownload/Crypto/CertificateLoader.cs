using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Sat.MassiveDownload.Crypto
{
    public static class CertificateLoader
    {
        public static X509Certificate2 FromPfx(string pfxPath, string pfxPassword)
            => new X509Certificate2(
                pfxPath,
                pfxPassword,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

        public static X509Certificate2 FromCerAndKey(string cerPath, string keyPath, string keyPassword)
        {
            var publicCert = new X509Certificate2(File.ReadAllBytes(cerPath));
            var keyBytes = File.ReadAllBytes(keyPath);

            RSA rsa;

            if (LooksLikePem(keyBytes))
            {
                // --- RUTA PEM (BouncyCastle) ---
                using var sr = new StreamReader(keyPath, Encoding.ASCII);
                var pemReader = new PemReader(sr, new PasswordFinder(keyPassword));
                var obj = pemReader.ReadObject()
                          ?? throw new InvalidOperationException("No se pudo leer la llave privada (PEM).");

                var rsaParams = obj switch
                {
                    AsymmetricCipherKeyPair kp => (RsaPrivateCrtKeyParameters)kp.Private,
                    RsaPrivateCrtKeyParameters rp => rp,
                    AsymmetricKeyParameter akp when akp.IsPrivate => (RsaPrivateCrtKeyParameters)akp,
                    _ => throw new InvalidOperationException($"Tipo de llave PEM no soportado: {obj.GetType().Name}")
                };

                rsa = DotNetUtilities.ToRSA(rsaParams);
            }
            else
            {
                // --- RUTA DER (nativa .NET) ---
                rsa = RSA.Create();
                try
                {
                    // PKCS#8 ENCRIPTADA (caso típico e.firma .key del SAT)
                    rsa.ImportEncryptedPkcs8PrivateKey(keyPassword.AsSpan(), keyBytes, out _);
                }
                catch (CryptographicException)
                {
                    try
                    {
                        // PKCS#8 SIN encriptar
                        rsa.ImportPkcs8PrivateKey(keyBytes, out _);
                    }
                    catch (CryptographicException ex)
                    {
                        rsa.Dispose();
                        throw new InvalidOperationException(
                            "No se pudo leer la llave privada (.key). Verifica contraseña y que sea PKCS#8 (DER).", ex);
                    }
                }
            }

            // Asociar la private key al certificado y devolver un X509 “bien horneado”
            using (rsa)
            {
                using var withPrivate = publicCert.CopyWithPrivateKey(rsa);
                var pfxBytes = withPrivate.Export(X509ContentType.Pkcs12);
                return new X509Certificate2(
                    pfxBytes,
                    (string?)null, // <- evita overload de SecureString
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
            }
        }

        private static bool LooksLikePem(byte[] data)
        {
            var head = Encoding.ASCII.GetString(data, 0, Math.Min(64, data.Length));
            return head.Contains("-----BEGIN", StringComparison.Ordinal);
        }

        private sealed class PasswordFinder(string pass) : IPasswordFinder
        {
            public char[] GetPassword() => pass.ToCharArray();
        }
    }
}
