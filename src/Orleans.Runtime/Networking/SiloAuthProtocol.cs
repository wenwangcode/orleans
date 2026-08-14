using System;
using Microsoft.AspNetCore.Connections;
using Orleans.Configuration;

namespace Orleans.Runtime.Messaging
{
    /// <summary>
    /// Helpers for gating silo-to-silo authentication on the negotiated TLS ALPN protocol.
    /// </summary>
    internal static class SiloAuthProtocol
    {
        /// <summary>
        /// Returns <see langword="true"/> when the connection negotiated the silo-auth ALPN protocol
        /// (<see cref="SiloAuthOptions.AuthApplicationProtocol"/>).
        /// <para>
        /// TLS always advertises this protocol alongside the baseline Orleans protocol, so it is
        /// negotiated whenever both peers are running a version of Orleans that supports it. It says
        /// nothing about whether either peer has silo connection authentication configured — that is
        /// decided entirely by whether <see cref="ISiloConnectionAuthenticator"/> middleware is
        /// registered on each side. This method is therefore the single source of truth the
        /// authentication middleware uses to decide whether a token is exchanged on the connection.
        /// </para>
        /// <para>
        /// When the connection has no <see cref="INegotiatedAlpnFeature"/> (e.g. TLS is not in use),
        /// this returns <see langword="false"/> so the middleware degrades to "no auth" rather than
        /// failing the connection.
        /// </para>
        /// </summary>
        public static bool IsAuthNegotiated(ConnectionContext context)
        {
            var negotiated = context.Features.Get<INegotiatedAlpnFeature>()?.NegotiatedProtocol;
            return string.Equals(negotiated, SiloAuthOptions.AuthApplicationProtocol, StringComparison.Ordinal);
        }
    }
}
