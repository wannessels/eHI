using System;
using System.IO;
using System.Text;
using System.Xml;

namespace Egelke.EHealth.Client.Helper
{
    internal static class MessageLogFormatter
    {
        internal static string Format(Action<XmlWriter> write, int maximumCharacters)
        {
            if (maximumCharacters < 1) throw new ArgumentOutOfRangeException(nameof(maximumCharacters));
            var text = new LimitedWriter(maximumCharacters);
            using (var writer = XmlWriter.Create(text, new XmlWriterSettings { OmitXmlDeclaration = true, Indent = false })) write(writer);
            return text.ToString();
        }

        private sealed class LimitedWriter : TextWriter
        {
            private readonly StringBuilder text;
            private readonly int maximum;
            private bool truncated;
            public override Encoding Encoding => Encoding.UTF8;
            internal LimitedWriter(int maximum) { this.maximum = maximum; text = new StringBuilder(Math.Min(maximum, 4096)); }
            public override void Write(char value)
            {
                if (text.Length < maximum) text.Append(value); else truncated = true;
            }
            public override void Write(char[] buffer, int index, int count)
            {
                int take = Math.Min(count, maximum - text.Length);
                text.Append(buffer, index, take);
                truncated |= take < count;
            }
            public override void Write(string value)
            {
                if (value == null) return;
                int take = Math.Min(value.Length, maximum - text.Length);
                text.Append(value, 0, take);
                truncated |= take < value.Length;
            }
            public override string ToString()
            {
                if (!truncated) return text.ToString();
                const string marker = "...[truncated]";
                int suffixLength = Math.Min(marker.Length, maximum);
                return text.ToString(0, maximum - suffixLength) + marker.Substring(0, suffixLength);
            }
        }
    }
}
