using System;
using NUnit.Framework;
using Virgil.Crypto.Foundation;

namespace Virgil.Crypto.Foundation.UnitTests
{
    [TestFixture()]
    public class Sha256Tests
    {
        [Test()]
        public void Construct_WithDefaultArguments_PrintMessage()
        {
            var hash = new Sha256();
            var digest = hash.hash(System.Text.Encoding.UTF8.GetBytes(""));
            Console.WriteLine(BitConverter.ToString(digest));
            Assert.AreEqual("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 
                            BitConverter.ToString(digest).Replace("-", "").ToLower());
        }
    }
}
