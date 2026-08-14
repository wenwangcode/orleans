namespace Orleans.Runtime.Messaging
{
    /// <summary>
    /// Connection feature exposing the TLS ALPN (Application-Layer Protocol Negotiation) protocol
    /// negotiated during the TLS handshake, if any.
    /// <para>
    /// The TLS implementation lives in <c>Orleans.Connections.Security</c>, which depends on
    /// <c>Orleans.Runtime</c> (not the reverse). Middleware defined in <c>Orleans.Runtime</c>
    /// therefore cannot reference the Security-internal TLS feature types directly. This feature
    /// is defined here so that TLS middleware can publish the negotiated protocol, and other
    /// middleware (such as silo connection authentication) can read it without a circular
    /// project dependency.
    /// </para>
    /// </summary>
    public interface INegotiatedAlpnFeature
    {
        /// <summary>
        /// Gets the ALPN protocol negotiated during the TLS handshake, or <see langword="null"/> if
        /// no protocol was negotiated (including when TLS is not in use on this connection).
        /// </summary>
        string NegotiatedProtocol { get; }
    }
}
