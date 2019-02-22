﻿// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeQuality.CSharp.Analyzers.Maintainability;
using Microsoft.CodeQuality.VisualBasic.Analyzers.Maintainability;
using Test.Utilities;
using Xunit;

namespace Microsoft.CodeQuality.Analyzers.Maintainability.UnitTests
{
    public class UseNameOfInPlaceOfStringFixerTests : CodeFixTestBase
    {
        protected override DiagnosticAnalyzer GetBasicDiagnosticAnalyzer()
        {
            return new BasicUseNameofInPlaceOfStringAnalyzer();
        }

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzer()
        {
            return new CSharpUseNameofInPlaceOfStringAnalyzer();

        }

        protected override CodeFixProvider GetBasicCodeFixProvider()
        {
            return new BasicUseNameofInPlaceOfStringFixer();
        }

        protected override CodeFixProvider GetCSharpCodeFixProvider()
        {
            return new CSharpUseNameofInPlaceOfStringFixer();
        }

        [Fact]
        public void Fixer_CSharp_ArgumentMatchesAParameterInScope()
        {
            VerifyCSharpFix(@"
using System;
class C
{
    void M(int x)
    {
        throw new ArgumentNullException(""x"");
    }
}",
@"
using System;
class C
{
    void M(int x)
    {
        throw new ArgumentNullException(nameof(x));
    }
}");
        }

        [Fact]
        public void Fixer_CSharp_ArgumentWithComments()
        {
            VerifyCSharpFix(@"
using System;
class C
{
    void M(int x)
    {
        throw new ArgumentNullException(/*Leading*/""x""/*Trailing*/);
    }
}",
@"
using System;
class C
{
    void M(int x)
    {
        throw new ArgumentNullException(/*Leading*/nameof(x)/*Trailing*/);
    }
}");
        }

        [Fact]
        public void Fixer_CSharp_ArgumentWithComments2()
        {
            VerifyCSharpFix(@"
using System;
class C
{
    void M(int x)
    {
        throw new ArgumentException(""Somemessage"", /*Leading*/""x""/*Trailing*/);
    }
}",
@"
using System;
class C
{
    void M(int x)
    {
        throw new ArgumentException(""Somemessage"", /*Leading*/nameof(x)/*Trailing*/);
    }
}");
        }

        [Fact]
        public void Fixer_VB_ArgumentMatchesAParameterInScope()
        {
            VerifyBasicFix(@"
Imports System

Module Mod1
    Sub f(s As String)
        Throw New ArgumentNullException(""s"")
    End Sub
End Module",
@"
Imports System

Module Mod1
    Sub f(s As String)
        Throw New ArgumentNullException(NameOf(s))
    End Sub
End Module");
        }

        [Fact]
        public void Fixer_CSharp_ArgumentMatchesPropertyInScope()
        {
            VerifyCSharpFix(@"
using System.ComponentModel;

public class Person : INotifyPropertyChanged
{
    private string name;
    public event PropertyChangedEventHandler PropertyChanged;

    public string PersonName {
        get { return name; }
        set
        {
            name = value;
            OnPropertyChanged(""PersonName"");
        }
    }

    protected void OnPropertyChanged(string propertyName)
    {
        PropertyChangedEventHandler handler = PropertyChanged;
        if (handler != null)
        {
            handler(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}", @"
using System.ComponentModel;

public class Person : INotifyPropertyChanged
{
    private string name;
    public event PropertyChangedEventHandler PropertyChanged;

    public string PersonName {
        get { return name; }
        set
        {
            name = value;
            OnPropertyChanged(nameof(PersonName));
        }
    }

    protected void OnPropertyChanged(string propertyName)
    {
        PropertyChangedEventHandler handler = PropertyChanged;
        if (handler != null)
        {
            handler(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}");
        }
    }
}