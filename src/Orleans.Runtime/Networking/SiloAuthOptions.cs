using System;

namespace Orleans.Configuration
{
    /// <summary>
    /// Options for silo-to-silo connection authentication.
    /// </summary>
    public class SiloAuthOptions
    {
        /// <summary>
        /// The TLS ALPN protocol label used to gate silo-to-silo authentication.
        /// <para>
        /// Orleans' TLS layer always advertises this protocol alongside its baseline application
        /// protocol, so it is negotiated automatically whenever both peers are running a version of
        /// Orleans that supports it — no additional TLS configuration is required. Negotiating this
        /// protocol has no effect by itself; the authentication middleware only exchanges a token
        /// when this protocol was negotiated <em>and</em> silo connection authentication is
        /// registered via <c>UseSiloConnectionAuthentication</c>. This makes rolling deployments
        /// safe: connections to/from silos that do not have authentication configured simply skip
        /// the token exchange rather than failing.
        /// </para>
        /// </summary>
        public const string AuthApplicationProtocol = "OrleansSiloAuth1";

        /// <summary>
        /// Gets or sets the timeout for the authentication token exchange.
        /// If the exchange does not complete within this duration, the connection is aborted.
        /// </summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Gets or sets the maximum token size in bytes.
        /// Tokens exceeding this size will be rejected to prevent resource exhaustion
        /// from unauthenticated peers.
        /// </summary>
        public int MaxTokenSize { get; set; } = 64 * 1024; // 64 KB
    }
}
