using System;

namespace Orleans.Configuration
{
    /// <summary>
    /// Options for silo-to-silo connection authentication.
    /// </summary>
    public class SiloAuthOptions
    {
        /// <summary>
        /// Gets or sets the timeout for the authentication handshake.
        /// If the handshake does not complete within this duration, the connection is aborted.
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
