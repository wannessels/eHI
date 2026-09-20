using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Egelke.EHealth.Client;
using Xunit;

namespace library_core_tests
{
    public class TracingConfigTest
    {
        [Fact]
        public void Check()
        {
            var target = new TracingConfig();

            Assert.Null(target.Contact);

            Assert.Equal("Egelke.EHealth.Client", target.Connector.Name);
            Assert.Equal("3.0.0.2", target.Connector.Version.ToString());

            Assert.False(string.IsNullOrWhiteSpace(target.Product.Name));
            Assert.NotNull(target.Product.Version);
            Assert.Equal(target.Product.Name + "/" + target.Product.Version + " Egelke.EHealth.Client/3.0.0.2", target.ToAgent());
        }
    }
}
