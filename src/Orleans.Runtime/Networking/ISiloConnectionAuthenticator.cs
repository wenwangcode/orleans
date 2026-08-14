using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Orleans.Runtime.Messaging
{
    /// <summary>
    /// Pluggable authenticator for silo-to-silo connections.
    /// <para>
    /// Whether a connection carries a token is decided entirely by the negotiated TLS ALPN
    /// protocol (see <see cref="Orleans.Configuration.SiloAuthOptions.AuthApplicationProtocol"/>): the middleware only
    /// invokes this authenticator when both silos negotiated the auth protocol. The connecting
    /// (client) silo writes a self-issued token and the accepting (server) silo validates it —
    /// there is no challenge/response round-trip, so implementations do not need to correlate a
    /// server-issued challenge with the token they produce.
    /// </para>
    /// <para>
    /// Implementations can use any underlying mechanism (HMAC shared secret, JWT, mTLS-bound
    /// tokens, etc.) — Orleans has no knowledge of the token format or how it is validated.
    /// </para>
    /// </summary>
    public interface ISiloConnectionAuthenticator
    {
        /// <summary>
        /// Writes a self-issued token identifying the connecting (client/outbound) silo.
        /// Called only when the silo-auth ALPN protocol was negotiated on the connection.
        /// </summary>
        /// <param name="writer">The buffer writer to write the token to.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        ValueTask WriteTokenAsync(IBufferWriter<byte> writer, CancellationToken cancellationToken);

        /// <summary>
        /// Validates a token received from the connecting (client) silo.
        /// Called only when the silo-auth ALPN protocol was negotiated on the connection, on the
        /// accepting (server/inbound) side.
        /// </summary>
        /// <param name="token">The token received from the connecting silo.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// <see langword="true"/> if the connection should be allowed to proceed; otherwise
        /// <see langword="false"/>, which aborts the connection. Implementations that want a
        /// log-only (audit) enforcement mode can encode that by always returning
        /// <see langword="true"/> while still logging invalid tokens internally.
        /// </returns>
        ValueTask<bool> ValidateTokenAsync(ReadOnlySequence<byte> token, CancellationToken cancellationToken);

        /// <summary>
        /// Called on the server (inbound) side when the connection did NOT negotiate the auth ALPN
        /// protocol — i.e. the peer connected using only the baseline protocol and no token will
        /// ever be sent.
        /// <para>
        /// This is the sole gate against an ALPN-downgrade bypass: a peer that simply omits the auth
        /// protocol from its offered ALPN list skips <see cref="ValidateTokenAsync"/> entirely, since
        /// it is never invoked for a baseline-negotiated connection. An authenticator that enforces
        /// token auth (e.g. a "Required" mode) MUST override this to reject such connections; the
        /// default implementation preserves the original rolling-upgrade-safe behavior (always allow)
        /// so existing authenticators that predate this member keep compiling and behaving as before.
        /// </para>
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// <see langword="true"/> to allow the connection to proceed without auth; <see langword="false"/>
        /// to abort it.
        /// </returns>
        ValueTask<bool> OnAuthNotNegotiatedAsync(CancellationToken cancellationToken) => new(true);
    }
}
