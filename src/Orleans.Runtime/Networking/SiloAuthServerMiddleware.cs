using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Orleans.Configuration;

namespace Orleans.Runtime.Messaging
{
    /// <summary>
    /// Server-side (inbound) silo authentication middleware.
    /// <para>
    /// Gating is decided by the negotiated TLS ALPN protocol (see <see cref="SiloAuthProtocol"/>):
    /// the token is only read/validated when the auth protocol
    /// (<see cref="SiloAuthOptions.AuthApplicationProtocol"/>) was negotiated, which can only
    /// happen when both silos advertise it. When negotiated, the server reads a single token frame
    /// and validates it; there is no challenge and no ack — see <see cref="SiloAuthClientMiddleware"/>.
    /// </para>
    /// </summary>
    internal sealed class SiloAuthServerMiddleware : IConnectionMiddleware
    {
        private const byte FrameTypeToken = 1;

        private readonly ISiloConnectionAuthenticator _authenticator;
        private readonly SiloAuthOptions _options;
        private readonly ILogger<SiloAuthServerMiddleware> _logger;

        public SiloAuthServerMiddleware(
            ISiloConnectionAuthenticator authenticator,
            IOptions<SiloAuthOptions> options,
            ILogger<SiloAuthServerMiddleware> logger)
        {
            _authenticator = authenticator ?? throw new ArgumentNullException(nameof(authenticator));
            _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task OnConnectionAsync(ConnectionContext context, ConnectionDelegate next)
        {
            if (!SiloAuthProtocol.IsAuthNegotiated(context))
            {
                // The peer never offered the auth ALPN protocol, so no token will ever arrive on this
                // connection. Whether that is acceptable (e.g. a legacy silo during a rolling deploy) or
                // a bypass attempt (a hostile client deliberately avoiding the auth protocol) is a policy
                // decision only the authenticator can make, since it alone knows the current enforcement
                // mode. Fail closed if the policy hook itself throws — an authenticator bug must not
                // silently degrade into "always allow".
                bool allowed;
                try
                {
                    allowed = await _authenticator.OnAuthNotNegotiatedAsync(CancellationToken.None);
                }
                catch (Exception ex)
                {
                    _logger.LogError(
                        ex,
                        "Silo auth server: OnAuthNotNegotiatedAsync threw for {RemoteEndPoint}; aborting connection (fail-closed).",
                        context.RemoteEndPoint);
                    throw new ConnectionAbortedException("Authentication failed: ALPN downgrade policy check threw.", ex);
                }

                if (!allowed)
                {
                    _logger.LogWarning(
                        "Silo auth server: connection from {RemoteEndPoint} did not negotiate the auth ALPN protocol and was rejected by policy.",
                        context.RemoteEndPoint);
                    throw new ConnectionAbortedException("Authentication failed: auth ALPN protocol not negotiated.");
                }

                if (_logger.IsEnabled(LogLevel.Debug))
                {
                    _logger.LogDebug(
                        "Silo auth server: auth protocol not negotiated for {RemoteEndPoint}, skipping token validation.",
                        context.RemoteEndPoint);
                }

                await next(context);
                return;
            }

            using var cts = new CancellationTokenSource(_options.Timeout);
            var cancellationToken = cts.Token;

            try
            {
                var (frameType, tokenBytes) = await ConnectionFrameHelper.ReadFrameAsync(
                    context, cancellationToken, _options.MaxTokenSize + ConnectionFrameHelper.FramePrefixSize);

                if (frameType != FrameTypeToken)
                {
                    _logger.LogWarning(
                        "Silo auth server: expected token frame (type {Expected}), got type {Actual} from {RemoteEndPoint}.",
                        FrameTypeToken, frameType, context.RemoteEndPoint);
                    throw new ConnectionAbortedException("Authentication failed: unexpected frame type.");
                }

                var isValid = await _authenticator.ValidateTokenAsync(
                    new ReadOnlySequence<byte>(tokenBytes),
                    cancellationToken);

                if (!isValid)
                {
                    _logger.LogWarning("Silo auth server: token validation rejected connection from {RemoteEndPoint}.", context.RemoteEndPoint);
                    throw new ConnectionAbortedException("Authentication failed: invalid token.");
                }

                if (_logger.IsEnabled(LogLevel.Debug))
                {
                    _logger.LogDebug("Silo auth server: connection authenticated from {RemoteEndPoint}.", context.RemoteEndPoint);
                }
            }
            catch (OperationCanceledException) when (cts.IsCancellationRequested)
            {
                _logger.LogWarning("Silo auth server: token read timed out from {RemoteEndPoint}.", context.RemoteEndPoint);
                throw new ConnectionAbortedException("Authentication failed: token read timed out.");
            }

            await next(context);
        }
    }
}
