using System;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Test.Utilities;
using Xunit;
using System.Text;
using System.Security.Cryptography;

namespace Microsoft.NetCore.Analyzers.Security.UnitTests
{

    public class DoNotHardcodeEncryptionKeyTests : TaintedDataAnalyzerTestBase
    {
        protected override DiagnosticDescriptor Rule => DoNotHardcodeEncryptionKey.Rule;

        [Fact]
        public void TesEncodingDefaultGetBytesWithLiteralDiagnostic()
        {
            VerifyCSharp(@"
using System.Text;
using System.Security.Cryptography;

namespace TestNamespace
{
    class TestClass
    {
        private static void TestMethod()
        {
            SymmetricAlgorithm rijn = SymmetricAlgorithm.Create();
            rijn.Key = Encoding.Default.GetBytes(""jglfjgoifgjuioreutoajgn"");
        }
    }
}",
            GetCSharpResultAt(12, 13, 12, 24, "byte[] SymmetricAlgorithm.Key", "void TestClass.TestMethod()", "byte[] Encoding.GetBytes(string s)", "void TestClass.TestMethod()"));
        }

        [Fact]
        public void TestByteArrayInitializerWithLiteralDiagnostic()
        {
            VerifyCSharpWithDependencies(@"
using System;
using System.Text;
using System.Security.Cryptography;

namespace TestNamespace
{
    class TestClass
    {
        private static void TestMethod()
        {
            SymmetricAlgorithm rijn = SymmetricAlgorithm.Create();
            rijn.Key = new byte[] { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20};
        }
    }
}",
            GetCSharpResultAt(13, 13, 13, 24, "byte[] SymmetricAlgorithm.Key", "void TestClass.TestMethod()", "byte[]", "void TestClass.TestMethod()"));
        }

        [Fact]
        public void TestByteArrayInitializerWithLiteralArrayDiagnostic()
        {
            VerifyCSharpWithDependencies(@"
using System;
using System.Text;
using System.Security.Cryptography;

namespace TestNamespace
{
    class TestClass
    {
        private static void TestMethod()
        {
            var array1 = new byte[]{0x20, 0x20};
            var array2 = new byte[]{0x20, 0x20};
            SymmetricAlgorithm rijn = SymmetricAlgorithm.Create();
            rijn.Key = new byte[] { array1[0], array2[0]};
        }
    }
}",
            GetCSharpResultAt(15, 13, 13, 26, "byte[] SymmetricAlgorithm.Key", "void TestClass.TestMethod()", "byte[]", "void TestClass.TestMethod()"),
            GetCSharpResultAt(15, 13, 12, 26, "byte[] SymmetricAlgorithm.Key", "void TestClass.TestMethod()", "byte[]", "void TestClass.TestMethod()"));
        }

        [Fact]
        public void TestNoDiagnostic()
        {
            VerifyCSharpWithDependencies(@"
using System;
using System.Text;
using System.Security.Cryptography;

namespace TestNamespace
{
    class TestClass
    {
        private static void TestMethod()
        {
            SymmetricAlgorithm rijn1 = SymmetricAlgorithm.Create();
            SymmetricAlgorithm rijn2 = SymmetricAlgorithm.Create();
            rijn1.Key = new byte[]{rijn2.Key[0]};
        }
    }
}");
        }

        protected override DiagnosticAnalyzer GetBasicDiagnosticAnalyzer()
        {
            return new DoNotHardcodeEncryptionKey();
        }

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzer()
        {
            return new DoNotHardcodeEncryptionKey();
        }
    }
}
