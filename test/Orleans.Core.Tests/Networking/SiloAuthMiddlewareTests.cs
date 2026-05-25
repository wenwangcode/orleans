using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
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
        public async Task SuccessfulAuthentication_BothSidesComplete()
        {
            // Arrange: two pipes connecting client and server
            var clientToServer = new Pipe();
            var serverToClient = new Pipe();

            var serverContext = new TestConnectionContext(
                input: clientToServer.Reader,
                output: serverToClient.Writer);

            var clientContext = new TestConnectionContext(
                input: serverToClient.Reader,
                output: clientToServer.Writer);

            var authenticator = new TestAuthenticator(shouldValidate: true);
            var options = Options.Create(new SiloAuthOptions { Timeout = TimeSpan.FromSeconds(5) });

            var serverMiddleware = new SiloAuthServerMiddleware(
                authenticator,
                options,
                NullLogger<SiloAuthServerMiddleware>.Instance);

            var clientMiddleware = new SiloAuthClientMiddleware(
                authenticator,
                options,
                NullLogger<SiloAuthClientMiddleware>.Instance);

            bool serverNextCalled = false;
            bool clientNextCalled = false;

            // Act: run both sides concurrently
            var serverTask = serverMiddleware.OnConnectionAsync(serverContext, _ =>
            {
                serverNextCalled = true;
                return Task.CompletedTask;
            });

            var clientTask = clientMiddleware.OnConnectionAsync(clientContext, _ =>
            {
                clientNextCalled = true;
                return Task.CompletedTask;
            });

            await Task.WhenAll(serverTask, clientTask);

            // Assert
            Assert.True(serverNextCalled, "Server should call next after successful auth.");
            Assert.True(clientNextCalled, "Client should call next after successful auth.");
        }

        [Fact]
        public async Task FailedAuthentication_ServerRejectsAndAborts()
        {
            var clientToServer = new Pipe();
            var serverToClient = new Pipe();

            var serverContext = new TestConnectionContext(
                input: clientToServer.Reader,
                output: serverToClient.Writer);

            var clientContext = new TestConnectionContext(
                input: serverToClient.Reader,
                output: clientToServer.Writer);

            var authenticator = new TestAuthenticator(shouldValidate: false);
            var options = Options.Create(new SiloAuthOptions { Timeout = TimeSpan.FromSeconds(5) });

            var serverMiddleware = new SiloAuthServerMiddleware(
                authenticator,
                options,
                NullLogger<SiloAuthServerMiddleware>.Instance);

            var clientMiddleware = new SiloAuthClientMiddleware(
                authenticator,
                options,
                NullLogger<SiloAuthClientMiddleware>.Instance);

            bool serverNextCalled = false;
            bool clientNextCalled = false;

            var serverTask = serverMiddleware.OnConnectionAsync(serverContext, _ =>
            {
                serverNextCalled = true;
                return Task.CompletedTask;
            });

            var clientTask = clientMiddleware.OnConnectionAsync(clientContext, _ =>
            {
                clientNextCalled = true;
                return Task.CompletedTask;
            });

            // Both should throw ConnectionAbortedException
            var serverEx = await Assert.ThrowsAsync<ConnectionAbortedException>(() => serverTask);
            var clientEx = await Assert.ThrowsAsync<ConnectionAbortedException>(() => clientTask);

            Assert.Contains("invalid token", serverEx.Message);
            Assert.Contains("server rejected", clientEx.Message);
            Assert.False(serverNextCalled);
            Assert.False(clientNextCalled);
        }

        [Fact]
        public async Task Timeout_AbortsBothSides()
        {
            // Only create one side of the pipe — server will never receive data
            var clientToServer = new Pipe();
            var serverToClient = new Pipe();

            var serverContext = new TestConnectionContext(
                input: clientToServer.Reader,
                output: serverToClient.Writer);

            var authenticator = new TestAuthenticator(shouldValidate: true);
            var options = Options.Create(new SiloAuthOptions { Timeout = TimeSpan.FromMilliseconds(100) });

            var serverMiddleware = new SiloAuthServerMiddleware(
                authenticator,
                options,
                NullLogger<SiloAuthServerMiddleware>.Instance);

            // Server sends challenge, then waits for token that never arrives
            // But first we need to NOT run the client so it times out reading

            // Actually: server writes challenge to serverToClient, then reads from clientToServer.
            // Nobody writes to clientToServer, so server times out.

            var ex = await Assert.ThrowsAsync<ConnectionAbortedException>(
                () => serverMiddleware.OnConnectionAsync(serverContext, _ => Task.CompletedTask));

            Assert.Contains("timed out", ex.Message);
        }

        [Fact]
        public async Task ChallengeIsUsedInTokenCreation()
        {
            var clientToServer = new Pipe();
            var serverToClient = new Pipe();

            var serverContext = new TestConnectionContext(
                input: clientToServer.Reader,
                output: serverToClient.Writer);

            var clientContext = new TestConnectionContext(
                input: serverToClient.Reader,
                output: clientToServer.Writer);

            var authenticator = new ChallengeVerifyingAuthenticator();
            var options = Options.Create(new SiloAuthOptions { Timeout = TimeSpan.FromSeconds(5) });

            var serverMiddleware = new SiloAuthServerMiddleware(
                authenticator,
                options,
                NullLogger<SiloAuthServerMiddleware>.Instance);

            var clientMiddleware = new SiloAuthClientMiddleware(
                authenticator,
                options,
                NullLogger<SiloAuthClientMiddleware>.Instance);

            var serverTask = serverMiddleware.OnConnectionAsync(serverContext, _ => Task.CompletedTask);
            var clientTask = clientMiddleware.OnConnectionAsync(clientContext, _ => Task.CompletedTask);

            await Task.WhenAll(serverTask, clientTask);

            // The authenticator verifies internally that challenge was incorporated into the token
            Assert.True(authenticator.ValidationWasCalled);
            Assert.True(authenticator.ChallengeWasIncorporated);
        }

        #region Test helpers

        private sealed class TestAuthenticator : ISiloConnectionAuthenticator
        {
            private readonly bool _shouldValidate;
            private readonly byte[] _challenge = new byte[] { 0xCA, 0xFE, 0xBA, 0xBE };

            public TestAuthenticator(bool shouldValidate)
            {
                _shouldValidate = shouldValidate;
            }

            public ValueTask<byte[]> CreateChallengeAsync(CancellationToken cancellationToken)
                => new ValueTask<byte[]>(_challenge);

            public ValueTask<byte[]> CreateTokenAsync(ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken)
                => new ValueTask<byte[]>(new byte[] { 0x01, 0x02, 0x03 });

            public ValueTask<bool> ValidateTokenAsync(ReadOnlyMemory<byte> challenge, ReadOnlyMemory<byte> token, CancellationToken cancellationToken)
                => new ValueTask<bool>(_shouldValidate);
        }

        /// <summary>
        /// An authenticator that verifies the client actually uses the challenge when creating the token.
        /// Token = challenge bytes + fixed suffix.
        /// </summary>
        private sealed class ChallengeVerifyingAuthenticator : ISiloConnectionAuthenticator
        {
            private static readonly byte[] Suffix = new byte[] { 0xDE, 0xAD };
            private byte[] _lastChallenge;

            public bool ValidationWasCalled { get; private set; }
            public bool ChallengeWasIncorporated { get; private set; }

            public ValueTask<byte[]> CreateChallengeAsync(CancellationToken cancellationToken)
            {
                _lastChallenge = Guid.NewGuid().ToByteArray();
                return new ValueTask<byte[]>(_lastChallenge);
            }

            public ValueTask<byte[]> CreateTokenAsync(ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken)
            {
                // Token = challenge + suffix
                var token = new byte[challenge.Length + Suffix.Length];
                challenge.Span.CopyTo(token);
                Suffix.CopyTo(token.AsSpan(challenge.Length));
                return new ValueTask<byte[]>(token);
            }

            public ValueTask<bool> ValidateTokenAsync(ReadOnlyMemory<byte> challenge, ReadOnlyMemory<byte> token, CancellationToken cancellationToken)
            {
                ValidationWasCalled = true;

                // Verify: token starts with challenge bytes
                if (token.Length >= challenge.Length)
                {
                    ChallengeWasIncorporated = token.Span.Slice(0, challenge.Length).SequenceEqual(challenge.Span);
                }

                return new ValueTask<bool>(ChallengeWasIncorporated);
            }
        }

        private sealed class TestConnectionContext : ConnectionContext
        {
            private readonly IDuplexPipe _transport;

            public TestConnectionContext(PipeReader input, PipeWriter output)
            {
                _transport = new DuplexPipe(input, output);
            }

            public override string ConnectionId { get; set; } = Guid.NewGuid().ToString();
            public override IDuplexPipe Transport { get => _transport; set => throw new NotSupportedException(); }
            public override IFeatureCollection Features { get; } = new TestFeatureCollection();
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
                public object this[Type key] { get => null; set { } }
                public bool IsReadOnly => false;
                public int Revision => 0;
                public TFeature Get<TFeature>() => default;
                public void Set<TFeature>(TFeature instance) { }
                public IEnumerator<KeyValuePair<Type, object>> GetEnumerator()
                    => ((IEnumerable<KeyValuePair<Type, object>>)Array.Empty<KeyValuePair<Type, object>>()).GetEnumerator();
                System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
            }
        }

        #endregion
    }
}
