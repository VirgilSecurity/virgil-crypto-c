using System;
using Xunit;

namespace NetCoreXUnitTest
{
    public class ExampleUnitTest
    {
        [Fact]
        public void AdditionTest()
        {
            var sum = Example.Addition(1, 2);
            Assert.Equal(3, sum);
        }
    }
}
