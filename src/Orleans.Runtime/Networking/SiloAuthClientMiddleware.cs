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
    /// Client-side (outbound) silo authentication middleware.
    /// <para>
    /// Protocol: Receives challenge from server → Creates token → Sends token → Reads result.
    /// </para>
    /// </summary>
    internal sealed class SiloAuthClientMiddleware : IConnectionMiddleware
    {
        private const byte FrameTypeChallenge = 1;
        private const byte FrameTypeToken = 2;
        private const byte FrameTypeSuccess = 3;
        private const byte FrameTypeFailure = 4;

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
            using var cts = new CancellationTokenSource(_options.Timeout);
            var cancellationToken = cts.Token;

            try
            {
                // Step 1: Read challenge from server
                var (frameType, challenge) = await ConnectionFrameHelper.ReadFrameAsync(
                    context, cancellationToken, _options.MaxTokenSize + ConnectionFrameHelper.FramePrefixSize);

                if (frameType != FrameTypeChallenge)
                {
                    _logger.LogWarning("Silo auth client: expected challenge frame (type {Expected}), got type {Actual} from {RemoteEndPoint}.",
                        FrameTypeChallenge, frameType, context.RemoteEndPoint);
                    throw new ConnectionAbortedException("Authentication failed: unexpected frame type from server.");
                }

                // Step 2: Create token incorporating the challenge
                var token = await _authenticator.CreateTokenAsync(challenge, cancellationToken);

                // Step 3: Send token to server
                await ConnectionFrameHelper.WriteFrameAsync(context, FrameTypeToken, token, cancellationToken);

                // Step 4: Read result from server
                var (resultType, _) = await ConnectionFrameHelper.ReadFrameAsync(context, cancellationToken);

                if (resultType == FrameTypeFailure)
                {
                    _logger.LogWarning("Silo auth client: server rejected authentication for {RemoteEndPoint}.", context.RemoteEndPoint);
                    throw new ConnectionAbortedException("Authentication failed: server rejected token.");
                }

                if (resultType != FrameTypeSuccess)
                {
                    _logger.LogWarning("Silo auth client: unexpected result frame type {FrameType} from {RemoteEndPoint}.",
                        resultType, context.RemoteEndPoint);
                    throw new ConnectionAbortedException("Authentication failed: unexpected result from server.");
                }

                if (_logger.IsEnabled(LogLevel.Debug))
                {
                    _logger.LogDebug("Silo auth client: authenticated to {RemoteEndPoint}.", context.RemoteEndPoint);
                }
            }
            catch (OperationCanceledException) when (cts.IsCancellationRequested)
            {
                _logger.LogWarning("Silo auth client: handshake timed out to {RemoteEndPoint}.", context.RemoteEndPoint);
                throw new ConnectionAbortedException("Authentication failed: handshake timed out.");
            }

            await next(context);
        }
    }
}
