using System;
using System.Threading;
using System.Threading.Tasks;

namespace Orleans.Runtime.Messaging
{
    /// <summary>
    /// Provides authentication for silo-to-silo connections.
    /// <para>
    /// The protocol uses a challenge-response flow:
    /// 1. Server generates a challenge and sends it to the connecting silo.
    /// 2. Client creates a token incorporating the challenge (proving it is not a replay).
    /// 3. Server validates the token against the original challenge.
    /// </para>
    /// <para>
    /// Implementations can use any underlying mechanism (JWT, HMAC, certificates, etc.).
    /// </para>
    /// </summary>
    public interface ISiloConnectionAuthenticator
    {
        /// <summary>
        /// Creates a cryptographic challenge to send to the connecting silo.
        /// Called on the server (inbound) side.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The challenge bytes.</returns>
        ValueTask<byte[]> CreateChallengeAsync(CancellationToken cancellationToken);

        /// <summary>
        /// Creates a token that proves the caller's identity, incorporating the server's challenge.
        /// Called on the client (outbound) side.
        /// </summary>
        /// <param name="challenge">The challenge received from the server.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The authentication token bytes.</returns>
        ValueTask<byte[]> CreateTokenAsync(ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken);

        /// <summary>
        /// Validates a token against the original challenge.
        /// Called on the server (inbound) side.
        /// </summary>
        /// <param name="challenge">The challenge that was sent to the client.</param>
        /// <param name="token">The token received from the client.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns><c>true</c> if the token is valid; otherwise <c>false</c>.</returns>
        ValueTask<bool> ValidateTokenAsync(ReadOnlyMemory<byte> challenge, ReadOnlyMemory<byte> token, CancellationToken cancellationToken);
    }
}
