using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Orleans.Configuration;
using Orleans.Runtime.Messaging;
using Xunit;

namespace Orleans.Runtime.Tests.Networking
{
    [Trait("Category", "BVT")]
    public class SiloAuthMiddlewareTests
    {
        [Fact]
        public async Task AuthNegotiated_ValidToken_BothSidesComplete()
        {
            var (serverContext, clientContext) = CreateConnectionPair(authNegotiated: true);

            var authenticator = new TestAuthenticator(shouldValidate: true);
            var options = Options.Create(new SiloAuthOptions { Timeout = TimeSpan.FromSeconds(5) });

            var serverMiddleware = new SiloAuthServerMiddleware(authenticator, options, NullLogger<SiloAuthServerMiddleware>.Instance);
            var clientMiddleware = new SiloAuthClientMiddleware(authenticator, options, NullLogger<SiloAuthClientMiddleware>.Instance);

            bool serverNextCalled = false;
            bool clientNextCalled = false;

            var serverTask = serverMiddleware.OnConnectionAsync(serverContext, _ => { serverNextCalled = true; return Task.CompletedTask; });
            var clientTask = clientMiddleware.OnConnectionAsync(clientContext, _ => { clientNextCalled = true; return Task.CompletedTask; });

            await Task.WhenAll(serverTask, clientTask);

            Assert.True(serverNextCalled, "Server should call next after successful auth.");
            Assert.True(clientNextCalled, "Client should call next after token is written.");
            Assert.True(authenticator.TokenWasWritten);
            Assert.True(authenticator.TokenWasValidated);
        }

        [Fact]
        public async Task AuthNegotiated_InvalidToken_ServerAbortsConnection()
        {
            var (serverContext, clientContext) = CreateConnectionPair(authNegotiated: true);

            var authenticator = new TestAuthenticator(shouldValidate: false);
            var options = Options.Create(new SiloAuthOptions { Timeout = TimeSpan.FromSeconds(5) });

            var serverMiddleware = new SiloAuthServerMiddleware(authenticator, options, NullLogger<SiloAuthServerMiddleware>.Instance);
            var clientMiddleware = new SiloAuthClientMiddleware(authenticator, options, NullLogger<SiloAuthClientMiddleware>.Instance);

            bool serverNextCalled = false;
            bool clientNextCalled = false;

            var serverTask = serverMiddleware.OnConnectionAsync(serverContext, _ => { serverNextCalled = true; return Task.CompletedTask; });
            var clientTask = clientMiddleware.OnConnectionAsync(clientContext, _ => { clientNextCalled = true; return Task.CompletedTask; });

            // The client is fire-and-forget: it writes the token and calls next() immediately.
            // Only the server, which validates, aborts the connection.
            var serverEx = await Assert.ThrowsAsync<ConnectionAbortedException>(() => serverTask);
            await clientTask;

            Assert.Contains("invalid token", serverEx.Message);
            Assert.False(serverNextCalled);
            Assert.True(clientNextCalled);
        }

        [Fact]
        public async Task AuthNotNegotiated_SkipsTokenExchangeOnBothSides()
        {
            // Simulates a peer that does not have silo connection authentication configured:
            // the ALPN feature reports a protocol other than the auth protocol.
            var (serverContext, clientContext) = CreateConnectionPair(authNegotiated: false);

            var authenticator = new TestAuthenticator(shouldValidate: true);
            var options = Options.Create(new SiloAuthOptions { Timeout = TimeSpan.FromSeconds(5) });

            var serverMiddleware = new SiloAuthServerMiddleware(authenticator, options, NullLogger<SiloAuthServerMiddleware>.Instance);
            var clientMiddleware = new SiloAuthClientMiddleware(authenticator, options, NullLogger<SiloAuthClientMiddleware>.Instance);

            bool serverNextCalled = false;
            bool clientNextCalled = false;

            await serverMiddleware.OnConnectionAsync(serverContext, _ => { serverNextCalled = true; return Task.CompletedTask; });
            await clientMiddleware.OnConnectionAsync(clientContext, _ => { clientNextCalled = true; return Task.CompletedTask; });

            Assert.True(serverNextCalled);
            Assert.True(clientNextCalled);
            Assert.False(authenticator.TokenWasWritten, "No token should be written when the auth protocol was not negotiated.");
            Assert.False(authenticator.TokenWasValidated, "No token should be validated when the auth protocol was not negotiated.");
        }

        /// <summary>
        /// Regression test for the ALPN-downgrade bypass (CWE-757): a peer that connects using only the
        /// baseline protocol must be rejected outright when the authenticator's policy says so, rather
        /// than always silently passing through. Proves the server middleware calls
        /// <see cref="ISiloConnectionAuthenticator.OnAuthNotNegotiatedAsync"/> and aborts when it
        /// returns <see langword="false"/>.
        /// </summary>
        [Fact]
        public async Task AuthNotNegotiated_PolicyRejects_ConnectionAborted()
        {
            var (serverContext, _) = CreateConnectionPair(authNegotiated: false);

            var authenticator = new PolicyControlledAuthenticator(allowWhenNotNegotiated: false);
            var options = Options.Create(new SiloAuthOptions { Timeout = TimeSpan.FromSeconds(5) });
            var serverMiddleware = new SiloAuthServerMiddleware(authenticator, options, NullLogger<SiloAuthServerMiddleware>.Instance);

            bool nextCalled = false;
            await Assert.ThrowsAsync<ConnectionAbortedException>(
                () => serverMiddleware.OnConnectionAsync(serverContext, _ => { nextCalled = true; return Task.CompletedTask; }));

            Assert.False(nextCalled, "The pipeline must not continue past a rejected ALPN-downgrade connection.");
        }

        /// <summary>
        /// Complements <see cref="AuthNotNegotiated_PolicyRejects_ConnectionAborted"/>: when the policy
        /// hook explicitly allows a baseline-negotiated connection, the pipeline must still proceed.
        /// </summary>
        [Fact]
        public async Task AuthNotNegotiated_PolicyAllows_ConnectionProceeds()
        {
            var (serverContext, _) = CreateConnectionPair(authNegotiated: false);

            var authenticator = new PolicyControlledAuthenticator(allowWhenNotNegotiated: true);
            var options = Options.Create(new SiloAuthOptions { Timeout = TimeSpan.FromSeconds(5) });
            var serverMiddleware = new SiloAuthServerMiddleware(authenticator, options, NullLogger<SiloAuthServerMiddleware>.Instance);

            bool nextCalled = false;
            await serverMiddleware.OnConnectionAsync(serverContext, _ => { nextCalled = true; return Task.CompletedTask; });

            Assert.True(nextCalled, "A baseline-negotiated connection explicitly allowed by policy must proceed.");
        }

        /// <summary>
        /// Proves fail-closed behavior: if the policy hook itself throws, the connection must be
        /// aborted rather than silently allowed through.
        /// </summary>
        [Fact]
        public async Task AuthNotNegotiated_PolicyHookThrows_ConnectionAbortedFailClosed()
        {
            var (serverContext, _) = CreateConnectionPair(authNegotiated: false);

            var authenticator = new ThrowingPolicyAuthenticator();
            var options = Options.Create(new SiloAuthOptions { Timeout = TimeSpan.FromSeconds(5) });
            var serverMiddleware = new SiloAuthServerMiddleware(authenticator, options, NullLogger<SiloAuthServerMiddleware>.Instance);

            bool nextCalled = false;
            var ex = await Assert.ThrowsAsync<ConnectionAbortedException>(
                () => serverMiddleware.OnConnectionAsync(serverContext, _ => { nextCalled = true; return Task.CompletedTask; }));

            Assert.False(nextCalled);
            Assert.Contains("policy check threw", ex.Message);
        }

        [Fact]
        public async Task AuthNegotiated_ServerTimesOutWhenNoTokenArrives()
        {
            var (serverContext, _) = CreateConnectionPair(authNegotiated: true);

            var authenticator = new TestAuthenticator(shouldValidate: true);
            var options = Options.Create(new SiloAuthOptions { Timeout = TimeSpan.FromMilliseconds(100) });

            var serverMiddleware = new SiloAuthServerMiddleware(authenticator, options, NullLogger<SiloAuthServerMiddleware>.Instance);

            // Nobody writes to the server's input, so it should time out reading the token frame.
            var ex = await Assert.ThrowsAsync<ConnectionAbortedException>(
                () => serverMiddleware.OnConnectionAsync(serverContext, _ => Task.CompletedTask));

            Assert.Contains("timed out", ex.Message);
        }

        private static (TestConnectionContext Server, TestConnectionContext Client) CreateConnectionPair(bool authNegotiated)
        {
            var clientToServer = new Pipe();
            var serverToClient = new Pipe();

            var negotiatedProtocol = authNegotiated ? SiloAuthOptions.AuthApplicationProtocol : "Orleans1";

            var serverContext = new TestConnectionContext(
                input: clientToServer.Reader,
                output: serverToClient.Writer,
                negotiatedProtocol: negotiatedProtocol);

            var clientContext = new TestConnectionContext(
                input: serverToClient.Reader,
                output: clientToServer.Writer,
                negotiatedProtocol: negotiatedProtocol);

            return (serverContext, clientContext);
        }

        #region Test helpers

        private sealed class TestAuthenticator : ISiloConnectionAuthenticator
        {
            private static readonly byte[] Token = { 0x01, 0x02, 0x03 };
            private readonly bool _shouldValidate;

            public TestAuthenticator(bool shouldValidate)
            {
                _shouldValidate = shouldValidate;
            }

            public bool TokenWasWritten { get; private set; }
            public bool TokenWasValidated { get; private set; }

            public ValueTask WriteTokenAsync(IBufferWriter<byte> writer, CancellationToken cancellationToken)
            {
                TokenWasWritten = true;
                writer.Write(Token);
                return default;
            }

            public ValueTask<bool> ValidateTokenAsync(ReadOnlySequence<byte> token, CancellationToken cancellationToken)
            {
                TokenWasValidated = true;
                return new ValueTask<bool>(_shouldValidate);
            }
        }

        /// <summary>
        /// Mock authenticator whose <see cref="OnAuthNotNegotiatedAsync"/> result is controlled by the
        /// constructor, simulating a "Required" vs. "LogOnly/Disabled" enforcement mode.
        /// </summary>
        private sealed class PolicyControlledAuthenticator : ISiloConnectionAuthenticator
        {
            private readonly bool _allowWhenNotNegotiated;

            public PolicyControlledAuthenticator(bool allowWhenNotNegotiated)
            {
                _allowWhenNotNegotiated = allowWhenNotNegotiated;
            }

            public ValueTask WriteTokenAsync(IBufferWriter<byte> writer, CancellationToken cancellationToken)
            {
                writer.Write(new byte[] { 0x01 });
                return default;
            }

            public ValueTask<bool> ValidateTokenAsync(ReadOnlySequence<byte> token, CancellationToken cancellationToken)
                => new(true);

            public ValueTask<bool> OnAuthNotNegotiatedAsync(CancellationToken cancellationToken)
                => new(_allowWhenNotNegotiated);
        }

        /// <summary>
        /// Mock authenticator whose <see cref="OnAuthNotNegotiatedAsync"/> throws, to prove the
        /// server middleware fails closed (aborts) rather than silently allowing the connection.
        /// </summary>
        private sealed class ThrowingPolicyAuthenticator : ISiloConnectionAuthenticator
        {
            public ValueTask WriteTokenAsync(IBufferWriter<byte> writer, CancellationToken cancellationToken)
            {
                writer.Write(new byte[] { 0x01 });
                return default;
            }

            public ValueTask<bool> ValidateTokenAsync(ReadOnlySequence<byte> token, CancellationToken cancellationToken)
                => new(true);

            public ValueTask<bool> OnAuthNotNegotiatedAsync(CancellationToken cancellationToken)
                => throw new InvalidOperationException("policy backend unavailable");
        }

        private sealed class TestNegotiatedAlpnFeature : INegotiatedAlpnFeature        {
            public TestNegotiatedAlpnFeature(string negotiatedProtocol) => NegotiatedProtocol = negotiatedProtocol;

            public string NegotiatedProtocol { get; }
        }

        private sealed class TestConnectionContext : ConnectionContext
        {
            private readonly IDuplexPipe _transport;

            public TestConnectionContext(PipeReader input, PipeWriter output, string negotiatedProtocol)
            {
                _transport = new DuplexPipe(input, output);
                Features = new TestFeatureCollection(new TestNegotiatedAlpnFeature(negotiatedProtocol));
            }

            public override string ConnectionId { get; set; } = Guid.NewGuid().ToString();
            public override IDuplexPipe Transport { get => _transport; set => throw new NotSupportedException(); }
            public override IFeatureCollection Features { get; }
            public override IDictionary<object, object> Items { get; set; } = new Dictionary<object, object>();
            public override EndPoint RemoteEndPoint { get; set; } = new IPEndPoint(IPAddress.Loopback, 11111);

            private sealed class DuplexPipe : IDuplexPipe
            {
                public DuplexPipe(PipeReader input, PipeWriter output)
                {
                    Input = input;
                    Output = output;
                }

                public PipeReader Input { get; }
                public PipeWriter Output { get; }
            }

            private sealed class TestFeatureCollection : IFeatureCollection
            {
                private readonly INegotiatedAlpnFeature _alpnFeature;

                public TestFeatureCollection(INegotiatedAlpnFeature alpnFeature) => _alpnFeature = alpnFeature;

                public object this[Type key] { get => Get(key); set { } }
                public bool IsReadOnly => false;
                public int Revision => 0;

                public TFeature Get<TFeature>()
                    => typeof(TFeature) == typeof(INegotiatedAlpnFeature) ? (TFeature)(object)_alpnFeature : default;

                public void Set<TFeature>(TFeature instance) { }

                private object Get(Type key)
                    => key == typeof(INegotiatedAlpnFeature) ? _alpnFeature : null;

                public IEnumerator<KeyValuePair<Type, object>> GetEnumerator()
                    => ((IEnumerable<KeyValuePair<Type, object>>)Array.Empty<KeyValuePair<Type, object>>()).GetEnumerator();
                System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
            }
        }

        #endregion
    }
}
