using System.Net.Security;
using Orleans.Configuration;

namespace Orleans.Connections.Security
{
    internal static class OrleansApplicationProtocol
    {
        public static readonly SslApplicationProtocol Orleans1 = new SslApplicationProtocol("Orleans1");

        /// <summary>
        /// Always advertised alongside <see cref="Orleans1"/> so that silo connection authentication
        /// (see <c>Orleans.Runtime.Messaging.ISiloConnectionAuthenticator</c>) can be negotiated
        /// automatically wherever both peers support it, without any extra TLS configuration.
        /// Negotiating this protocol has no effect unless silo connection authentication middleware
        /// is also registered on both sides via <c>UseSiloConnectionAuthentication</c>.
        /// </summary>
        public static readonly SslApplicationProtocol SiloAuth1 = new SslApplicationProtocol(SiloAuthOptions.AuthApplicationProtocol);
    }
}
