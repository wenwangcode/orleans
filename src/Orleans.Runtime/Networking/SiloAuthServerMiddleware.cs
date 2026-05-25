using System;
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
    /// Protocol: Server sends challenge → Client responds with token → Server validates.
    /// </para>
    /// </summary>
    internal sealed class SiloAuthServerMiddleware : IConnectionMiddleware
    {
        private const byte FrameTypeChallenge = 1;
        private const byte FrameTypeToken = 2;
        private const byte FrameTypeSuccess = 3;
        private const byte FrameTypeFailure = 4;

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
            using var cts = new CancellationTokenSource(_options.Timeout);
            var cancellationToken = cts.Token;

            try
            {
                // Step 1: Generate and send challenge
                var challenge = await _authenticator.CreateChallengeAsync(cancellationToken);
                await ConnectionFrameHelper.WriteFrameAsync(context, FrameTypeChallenge, challenge, cancellationToken);

                // Step 2: Read token from client
                var (frameType, payload) = await ConnectionFrameHelper.ReadFrameAsync(
                    context, cancellationToken, _options.MaxTokenSize + ConnectionFrameHelper.FramePrefixSize);

                if (frameType != FrameTypeToken)
                {
                    _logger.LogWarning("Silo auth: expected token frame (type {Expected}), got type {Actual} from {RemoteEndPoint}.",
                        FrameTypeToken, frameType, context.RemoteEndPoint);
                    await ConnectionFrameHelper.WriteFrameAsync(context, FrameTypeFailure, Array.Empty<byte>(), cancellationToken);
                    throw new ConnectionAbortedException("Authentication failed: unexpected frame type.");
                }

                // Step 3: Validate token against original challenge
                var isValid = await _authenticator.ValidateTokenAsync(challenge, payload, cancellationToken);

                if (!isValid)
                {
                    _logger.LogWarning("Silo auth: token validation failed from {RemoteEndPoint}.", context.RemoteEndPoint);
                    await ConnectionFrameHelper.WriteFrameAsync(context, FrameTypeFailure, Array.Empty<byte>(), cancellationToken);
                    throw new ConnectionAbortedException("Authentication failed: invalid token.");
                }

                // Step 4: Send success and continue pipeline
                await ConnectionFrameHelper.WriteFrameAsync(context, FrameTypeSuccess, Array.Empty<byte>(), cancellationToken);

                if (_logger.IsEnabled(LogLevel.Debug))
                {
                    _logger.LogDebug("Silo auth: connection authenticated from {RemoteEndPoint}.", context.RemoteEndPoint);
                }
            }
            catch (OperationCanceledException) when (cts.IsCancellationRequested)
            {
                _logger.LogWarning("Silo auth: handshake timed out from {RemoteEndPoint}.", context.RemoteEndPoint);
                throw new ConnectionAbortedException("Authentication failed: handshake timed out.");
            }

            await next(context);
        }
    }
}
