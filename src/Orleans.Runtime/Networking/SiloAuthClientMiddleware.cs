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
    /// Client-side (outbound) silo authentication middleware.
    /// <para>
    /// Gating is decided by the negotiated TLS ALPN protocol (see <see cref="SiloAuthProtocol"/>):
    /// a token is written only when the auth protocol (<see cref="SiloAuthOptions.AuthApplicationProtocol"/>)
    /// was negotiated, which can only happen when both silos advertise it. The token is written
    /// fire-and-forget — this side does not wait for any acknowledgement from the server — so
    /// there is no round-trip and therefore no deadlock window during connection establishment.
    /// Enforcement happens entirely on the server; a rejected connection is observed here only
    /// indirectly, as a dropped connection on subsequent messages.
    /// </para>
    /// </summary>
    internal sealed class SiloAuthClientMiddleware : IConnectionMiddleware
    {
        private const byte FrameTypeToken = 1;

        private readonly ISiloConnectionAuthenticator _authenticator;
        private readonly SiloAuthOptions _options;
        private readonly ILogger<SiloAuthClientMiddleware> _logger;

        public SiloAuthClientMiddleware(
            ISiloConnectionAuthenticator authenticator,
            IOptions<SiloAuthOptions> options,
            ILogger<SiloAuthClientMiddleware> logger)
        {
            _authenticator = authenticator ?? throw new ArgumentNullException(nameof(authenticator));
            _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task OnConnectionAsync(ConnectionContext context, ConnectionDelegate next)
        {
            if (!SiloAuthProtocol.IsAuthNegotiated(context))
            {
                if (_logger.IsEnabled(LogLevel.Debug))
                {
                    _logger.LogDebug(
                        "Silo auth client: auth protocol not negotiated for {RemoteEndPoint}, sending no token.",
                        context.RemoteEndPoint);
                }

                await next(context);
                return;
            }

            using var cts = new CancellationTokenSource(_options.Timeout);
            var cancellationToken = cts.Token;

            try
            {
                // Pre-acquire the token before writing any frame bytes, so that a slow/async token
                // provider cannot leave a partially-written frame on the wire.
                var tokenBuffer = new ArrayBufferWriter<byte>();
                await _authenticator.WriteTokenAsync(tokenBuffer, cancellationToken);

                await ConnectionFrameHelper.WriteFrameAsync(
                    context,
                    FrameTypeToken,
                    tokenBuffer.WrittenMemory.ToArray(),
                    cancellationToken);

                if (_logger.IsEnabled(LogLevel.Debug))
                {
                    _logger.LogDebug("Silo auth client: token sent to {RemoteEndPoint}.", context.RemoteEndPoint);
                }
            }
            catch (OperationCanceledException) when (cts.IsCancellationRequested)
            {
                _logger.LogWarning("Silo auth client: token write timed out to {RemoteEndPoint}.", context.RemoteEndPoint);
                throw new ConnectionAbortedException("Authentication failed: token write timed out.");
            }

            await next(context);
        }
    }
}
