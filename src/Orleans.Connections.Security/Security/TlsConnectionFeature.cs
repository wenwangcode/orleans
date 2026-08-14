using System;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Orleans.Runtime.Messaging;

#nullable disable
namespace Orleans.Connections.Security
{
    internal class TlsConnectionFeature : ITlsConnectionFeature, ITlsApplicationProtocolFeature, ITlsHandshakeFeature, INegotiatedAlpnFeature
    {
        public X509Certificate2 LocalCertificate { get; set; }

        public X509Certificate2 RemoteCertificate { get; set; }

        public ReadOnlyMemory<byte> ApplicationProtocol { get; set; }

        /// <summary>
        /// The negotiated ALPN protocol as a string, exposed via <see cref="INegotiatedAlpnFeature"/>
        /// so that middleware in <c>Orleans.Runtime</c> (which cannot reference the Security-internal
        /// <see cref="ITlsApplicationProtocolFeature"/>) can read it.
        /// </summary>
        public string NegotiatedProtocol =>
            ApplicationProtocol.IsEmpty ? null : Encoding.ASCII.GetString(ApplicationProtocol.Span);

        public SslProtocols Protocol { get; set; }

        public TlsCipherSuite? NegotiatedCipherSuite { get; set; }

        public string HostName { get; set; } = string.Empty;

#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB0058
#endif
        public CipherAlgorithmType CipherAlgorithm { get; set; }

        public int CipherStrength { get; set; }

        public HashAlgorithmType HashAlgorithm { get; set; }

        public int HashStrength { get; set; }

        public ExchangeAlgorithmType KeyExchangeAlgorithm { get; set; }

        public int KeyExchangeStrength { get; set; }
#if NET10_0_OR_GREATER
#pragma warning restore SYSLIB0058
#endif

        public Task<X509Certificate2> GetRemoteCertificateAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(RemoteCertificate);
        }
    }
}
