using System.Linq;
using NUnit.Framework;

namespace DuoUniversal.Tests
{
    [TestFixture]
    public class TestUtils
    {
        [SetUp]
        public void Setup()
        {
        }

        [Test]
        [TestCase(1)]
        [TestCase(10)]
        [TestCase(36)]
        [TestCase(100)]
        public void TestGenerateRandomString(int length)
        {
            string theString = Utils.GenerateRandomString(length);
            Assert.Multiple(() =>
            {
                Assert.AreEqual(length, theString.Length, "String was unexpected length.");
                Assert.IsTrue(theString.All(c => char.IsLetterOrDigit(c)), "String contained a character that was not a letter or digit.");
            });
        }
    }
}
