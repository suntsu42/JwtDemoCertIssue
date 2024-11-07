using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

internal class Program
{
    public static void Main(string[] args)
    {
        const string certName = "CN=CertificateName";
        using (var certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
        {
            certStore.Open(OpenFlags.ReadOnly);
            var jwtCerts = certStore.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, certName, false);
            if (jwtCerts.Count == 0)
                throw new Exception($"Certificate {certName} not found");
            if (jwtCerts.Count > 1)
                throw new Exception($"More than one Certificate with Subject {certName} found");

            X509Certificate2 jwtCert = jwtCerts[0];

            DateTime now = DateTime.Now;
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            var token = new JwtSecurityToken
            (
                $"MyIssuerName",
                "MyAudienceName",
                null,
                // valid for a timeframe of 20 minute (-10min/+10min)
                now.AddMinutes(-10),
                now.AddMinutes(+10),
                // the certificate to sign the token
                new MySigningCredentials(jwtCert)
            );

            // Create the token. 
            // Results in an exception when the certificate in the windows certificate store is marked as non-exportable
            // Exception message: The CNG key handle being opened was detected to be ephemeral, but the EphemeralKey open option was not specified
            string? createdToken = tokenHandler.WriteToken(token);
        }
    }

    /// <summary>
    /// Custom implementation of <see cref="SigningCredentials"/> to use an <see cref="X509Certificate2"/> for signing.
    /// Required since the constructor of <see cref="SigningCredentials"/> is protected.
    /// </summary>
    private sealed class MySigningCredentials : SigningCredentials
    {
        internal MySigningCredentials(X509Certificate2 certificate) : base(certificate)
        {
        }
    }
}