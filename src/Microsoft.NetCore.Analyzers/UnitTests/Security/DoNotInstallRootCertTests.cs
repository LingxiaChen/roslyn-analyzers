// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using Microsoft.CodeAnalysis.Diagnostics;
using Test.Utilities;
using Xunit;

namespace Microsoft.NetCore.Analyzers.Security.UnitTests
{
    public class DoNotInstallRootCertTests : DiagnosticAnalyzerTestBase
    {
        [Fact]
        public void TestConstructorWithStoreNameParameterDiagnostic()
        {
            VerifyCSharp(@"
using System;
using System.Security.Cryptography.X509Certificates;

class TestClass
{
    public void TestMethod()
    {
        var storeName = StoreName.Root; 
        var x509Store = new X509Store(storeName);
        x509Store.Add(new X509Certificate2());
    }
}",
            GetCSharpResultAt(11, 9, DoNotInstallRootCert.Rule));
        }

        [Fact]
        public void TestConstructorWithStoreNameAndStoreLocationParametersDiagnostic()
        {
            VerifyCSharp(@"
using System;
using System.Security.Cryptography.X509Certificates;

class TestClass
{
    public void TestMethod()
    {
        var storeName = StoreName.Root; 
        var x509Store = new X509Store(storeName, StoreLocation.CurrentUser);
        x509Store.Add(new X509Certificate2());
    }
}",
            GetCSharpResultAt(11, 9, DoNotInstallRootCert.Rule));
        }

        [Fact]
        public void TestConstructorWithStringParameterDiagnostic()
        {
            VerifyCSharp(@"
using System;
using System.Security.Cryptography.X509Certificates;

class TestClass
{
    public void TestMethod()
    {
        var storeName = ""Root""; 
        var x509Store = new X509Store(storeName);
        x509Store.Add(new X509Certificate2());
    }
}",
            GetCSharpResultAt(11, 9, DoNotInstallRootCert.Rule));
        }

        [Fact]
        public void TestConstructorWithStringAndStoreLocationParametersDiagnostic()
        {
            VerifyCSharp(@"
using System;
using System.Security.Cryptography.X509Certificates;

class TestClass
{
    public void TestMethod()
    {
        var storeName = ""Root""; 
        var x509Store = new X509Store(storeName, StoreLocation.CurrentUser);
        x509Store.Add(new X509Certificate2());
    }
}",
            GetCSharpResultAt(11, 9, DoNotInstallRootCert.Rule));
        }

        [Fact]
        public void TestConstructorWithStoreNameParameterWithoutTemporaryObjectDiagnostic()
        {
            VerifyCSharp(@"
using System;
using System.Security.Cryptography.X509Certificates;

class TestClass
{
    public void TestMethod()
    {
        new X509Store(StoreName.Root).Add(new X509Certificate2());
    }
}",
            GetCSharpResultAt(9, 9, DoNotInstallRootCert.Rule));
        }

        [Fact]
        public void TestConstructorWithStringParameterWithoutTemporaryObjectDiagnostic()
        {
            VerifyCSharp(@"
using System;
using System.Security.Cryptography.X509Certificates;

class TestClass
{
    public void TestMethod()
    {
        new X509Store(""Root"").Add(new X509Certificate2());
    }
}",
            GetCSharpResultAt(9, 9, DoNotInstallRootCert.Rule));
        }

        [Fact]
        public void TestConstructorWithStoreNameParameterInOtherMethodDiagnosticWrongCase1()
        {
            VerifyCSharp(@"
using System;
using System.Security.Cryptography.X509Certificates;

class TestClass
{
    public void TestMethod()
    {
        var storeName = StoreName.Root; 
        var x509Store = new X509Store(storeName);
        TestMethod2(x509Store); 
    }

    public void TestMethod2(X509Store x509Store)
    {
        x509Store.Add(new X509Certificate2());
    }
}",
            GetCSharpResultAt(16, 9, DoNotInstallRootCert.Rule));
        }

        [Fact]
        public void TestConstructorWithStoreNameParameterInOtherMethodDiagnosticWrongCase2()
        {
            VerifyCSharp(@"
using System;
using System.Security.Cryptography.X509Certificates;

class TestClass
{
    public void TestMethod()
    {
        GetX509Store().Add(new X509Certificate2());

        X509Store GetX509Store() => new X509Store(StoreName.Root);
    }
}",
            GetCSharpResultAt(16, 9, DoNotInstallRootCert.Rule));
        }

        [Fact]
        public void TestConstructorWithStoreNameParameterInOtherMethodDiagnosticWrongCase3()
        {
            VerifyCSharp(@"
using System;
using System.Security.Cryptography.X509Certificates;

class TestClass
{
    public void TestMethod()
    {
        GetX509Store().Add(new X509Certificate2());
    }

    public X509Store GetX509Store()
    {
        return new X509Store(StoreName.Root);
    }
}",
            GetCSharpResultAt(16, 9, DoNotInstallRootCert.Rule));
        }

        [Fact]
        public void TestNotCallAddMethodNoDiagnostic()
        {
            VerifyCSharp(@"
using System;
using System.Security.Cryptography.X509Certificates;

class TestClass
{
    public void TestMethod()
    {
        var x509Store = new X509Store(""Root"");
    }
}");
        }

        [Fact]
        public void TestInstallCertToOtherStoreNoDiagnostic()
        {
            VerifyCSharp(@"
using System;
using System.Security.Cryptography.X509Certificates;

class TestClass
{
    public void TestMethod()
    {
        var x509Store = new X509Store(""My"");
        x509Store.Add(new X509Certificate2());
    }
}");
        }

        [Fact]
        public void TestInstallCertToOtherStoreInOtherMethodNoDiagnostic()
        {
            VerifyCSharp(@"
using System;
using System.Security.Cryptography.X509Certificates;

class TestClass
{
    public void TestMethod()
    {
        var storeName = StoreName.My; 
        var x509Store = new X509Store(storeName);
        TestMethod2(x509Store); 
    }

    public void TestMethod2(X509Store x509Store)
    {
        x509Store.Add(new X509Certificate2());
    }
}");
        }

        [Fact]
        public void TestCreateAStoreWithoutSettingStoreNameNoDiagnostic()
        {
            VerifyCSharp(@"
using System;
using System.Security.Cryptography.X509Certificates;

class TestClass
{
    public void TestMethod()
    {
        var x509Store = new X509Store();
        x509Store.Add(new X509Certificate2());
    }
}");
        }

        protected override DiagnosticAnalyzer GetBasicDiagnosticAnalyzer()
        {
            return new DoNotInstallRootCert();
        }

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzer()
        {
            return new DoNotInstallRootCert();
        }
    }
}
