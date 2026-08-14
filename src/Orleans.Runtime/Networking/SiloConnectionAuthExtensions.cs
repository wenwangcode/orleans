using System;
using Microsoft.Extensions.DependencyInjection;
using Orleans.Configuration;
using Orleans.Runtime.Messaging;

namespace Orleans.Hosting
{
    /// <summary>
    /// Extension methods for configuring silo-to-silo connection authentication.
    /// </summary>
    public static class SiloConnectionAuthExtensions
    {
        /// <summary>
        /// Enables silo-to-silo connection authentication using the specified <see cref="ISiloConnectionAuthenticator"/> implementation.
        /// <para>
        /// This registers authentication middleware on both inbound and outbound silo connections.
        /// Whether a token is exchanged on a given connection is decided by the negotiated TLS ALPN
        /// protocol (<see cref="SiloAuthOptions.AuthApplicationProtocol"/>), which Orleans' TLS layer
        /// advertises automatically — both silos must be TLS-enabled, but no additional TLS
        /// configuration is required. If either peer does not have authentication configured, the
        /// auth protocol is not negotiated and the connection proceeds without a token, which makes
        /// rolling deployments (enabling auth cluster-wide without a coordinated restart) safe.
        /// </para>
        /// <para>
        /// <b>Important:</b> Silo connection authentication requires TLS (<c>UseTls</c>) to be
        /// configured; ALPN negotiation only occurs within a TLS handshake.
        /// </para>
        /// </summary>
        /// <typeparam name="TAuthenticator">
        /// The authenticator implementation. Resolved from DI.
        /// </typeparam>
        /// <param name="builder">The silo builder.</param>
        /// <returns>The silo builder for chaining.</returns>
        public static ISiloBuilder UseSiloConnectionAuthentication<TAuthenticator>(this ISiloBuilder builder)
            where TAuthenticator : class, ISiloConnectionAuthenticator
        {
            builder.Services.AddSingleton<ISiloConnectionAuthenticator, TAuthenticator>();
            builder.Services.Configure<SiloConnectionOptions>(options =>
            {
                options.ConfigureSiloInboundConnection(conn => conn.UseMiddleware<SiloAuthServerMiddleware>());
                options.ConfigureSiloOutboundConnection(conn => conn.UseMiddleware<SiloAuthClientMiddleware>());
            });

            return builder;
        }

        /// <summary>
        /// Enables silo-to-silo connection authentication using the specified <see cref="ISiloConnectionAuthenticator"/> implementation
        /// with custom options.
        /// </summary>
        /// <typeparam name="TAuthenticator">
        /// The authenticator implementation. Resolved from DI.
        /// </typeparam>
        /// <param name="builder">The silo builder.</param>
        /// <param name="configureOptions">A delegate to configure <see cref="SiloAuthOptions"/>.</param>
        /// <returns>The silo builder for chaining.</returns>
        public static ISiloBuilder UseSiloConnectionAuthentication<TAuthenticator>(
            this ISiloBuilder builder,
            Action<SiloAuthOptions> configureOptions)
            where TAuthenticator : class, ISiloConnectionAuthenticator
        {
            if (configureOptions is null)
                throw new ArgumentNullException(nameof(configureOptions));

            builder.Services.Configure(configureOptions);
            return builder.UseSiloConnectionAuthentication<TAuthenticator>();
        }
    }
}
