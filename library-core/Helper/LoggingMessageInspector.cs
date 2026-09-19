/*
 *  This file is part of eH-I.
 *  Copyright (C) 2025 Egelke BVBA
 *
 *  eH-I is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  eH-I is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with eH-I.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Dispatcher;
using System.Text;
using System.Xml;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Helper
{
    /// <summary>
    /// Logs the formatted messages to the provided logger.
    /// </summary>
    public class LoggingMessageInspector : IClientMessageInspector
    {

        private readonly ILogger _logger;

        /// <summary>Explicitly opts in to SOAP body logging at Trace. Off by default.</summary>
        public bool LogBodies { get; set; }

        /// <summary>Maximum formatted body characters. Opt-in tracing still buffers the transport message.</summary>
        public int MaxBodyCharacters { get; set; } = 4096;

        /// <summary>
        /// Default constructor
        /// </summary>
        /// <param name="logger">The logger to log the message to</param>
        public LoggingMessageInspector(ILogger logger)
        {
            _logger = logger;


        }
        
        /// <summary>
        /// Logs the response mesage
        /// </summary>
        /// <param name="reply">the response message to log</param>
        /// <param name="correlationState">correlation state, not used</param>
        public void AfterReceiveReply(ref Message reply, object correlationState)
        {
            LogMessage(ref reply, "Response");
        }

        /// <summary>
        /// Log the request message
        /// </summary>
        /// <param name="request">the request message to log</param>
        /// <param name="channel">the canneld, not used</param>
        /// <returns>a clone of the request, unaltered</returns>
        public object BeforeSendRequest(ref Message request, IClientChannel channel)
        {
            LogMessage(ref request, "Request");
            return null;
        }

        private void LogMessage(ref Message message, string direction)
        {
            if (_logger?.IsEnabled(LogLevel.Information) == true)
                _logger.LogInformation("SOAP {Direction}: action={Action}, messageId={MessageId}, isFault={IsFault}",
                    direction, message.Headers.Action, message.Headers.MessageId, message.IsFault);
            if (!LogBodies || _logger?.IsEnabled(LogLevel.Trace) != true) return;
            if (MaxBodyCharacters < 1) throw new ArgumentOutOfRangeException(nameof(MaxBodyCharacters));

            var original = message;
            using (var buffer = original.CreateBufferedCopy(int.MaxValue))
            {
                message = buffer.CreateMessage();
                original.Close();
                using (var copy = buffer.CreateMessage())
                    _logger.LogTrace("SOAP {Direction} body: {Body}", direction, MessageLogFormatter.Format(copy.WriteMessage, MaxBodyCharacters));
            }
        }

    }
}
