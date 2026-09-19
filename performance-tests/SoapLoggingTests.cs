using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.Xml;
using Egelke.EHealth.Client.Helper;
using Microsoft.Extensions.Logging;
using Xunit;

public class SoapLoggingTests
{
    private sealed class Logger : ILogger
    {
        internal readonly List<string> Messages = new List<string>();
        public IDisposable BeginScope<TState>(TState state) => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception error, Func<TState, Exception, string> format)
            => Messages.Add(format(state, error));
    }
    private sealed class CountingBody : BodyWriter
    {
        internal int Writes;
        internal readonly string Content = new string('x', 20000);
        internal CountingBody() : base(false) { }
        protected override void OnWriteBodyContents(XmlDictionaryWriter writer) { Writes++; writer.WriteElementString("Data", Content); }
    }

    [Fact]
    public void MetadataLoggingDoesNotBufferEvenWhenTraceIsEnabled()
    {
        var logger = new Logger();
        var body = new CountingBody();
        var message = Message.CreateMessage(MessageVersion.Soap11, "test", body);
        new LoggingMessageInspector(logger).BeforeSendRequest(ref message, null);
        Assert.Equal(0, body.Writes);
        Assert.Single(logger.Messages);
        Assert.DoesNotContain("xxxxx", logger.Messages[0]);
        message.Close();
    }

    [Fact]
    public void OptInLoggingTruncatesButReplacementMessageRemainsReadable()
    {
        var logger = new Logger();
        var body = new CountingBody();
        var message = Message.CreateMessage(MessageVersion.Soap11, "test", body);
        var inspector = new LoggingMessageInspector(logger) { LogBodies = true, MaxBodyCharacters = 128 };
        inspector.AfterReceiveReply(ref message, null);
        Assert.Contains("[truncated]", logger.Messages[1]);
        Assert.True(logger.Messages[1].Length < 160);
        using (message)
        using (var reader = message.GetReaderAtBodyContents()) Assert.Equal(body.Content, reader.ReadElementContentAsString());
        Assert.Equal(1, body.Writes);
    }
}
