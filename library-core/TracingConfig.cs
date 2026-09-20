using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client
{
    /// <summary>
    /// Simplified Assembly info.
    /// </summary>
    public class SoftwareInfo
    {
        /// <summary>
        /// Name of the assembly.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Version of the assembly.
        /// </summary>
        public Version Version { get; set; }

    }

    /// <summary>
    /// eHealth tracing config, use for the "User-Agent" and "From" http-headers.
    /// </summary>
    public class TracingConfig
    {

        /// <summary>
        /// Information about your product, using the entry assembly or this library when hosted without one.
        /// </summary>
        public SoftwareInfo Product { get; set; } = Describe(Assembly.GetEntryAssembly() ?? typeof(TracingConfig).Assembly);

        /// <summary>
        /// Information about this library, default so to Executing Assembly.
        /// </summary>
        public SoftwareInfo Connector { get; set; } = Describe(typeof(TracingConfig).Assembly);

        private static SoftwareInfo Describe(Assembly assembly)
        {
            var name = assembly.GetName();
            return new SoftwareInfo { Name = name.Name, Version = name.Version ?? new Version(0, 0) };
        }

        /// <summary>
        /// Contact e-mail, default to null.
        /// </summary>
        public string Contact { get; set; }


        public string ToAgent()
        {
            return new StringBuilder()
                .Append(Product.Name)
                .Append('/')
                .Append(Product.Version.ToString())
                .Append(' ')
                .Append(Connector.Name)
                .Append('/')
                .Append(Connector.Version.ToString())
                .ToString();
        }

    }


}
