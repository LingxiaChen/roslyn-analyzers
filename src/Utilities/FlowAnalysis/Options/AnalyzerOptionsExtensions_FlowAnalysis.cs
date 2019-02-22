﻿// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System.Threading;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow;

namespace Analyzer.Utilities
{
    internal static partial class AnalyzerOptionsExtensions
    {
        public static InterproceduralAnalysisKind GetInterproceduralAnalysisKindOption(
            this AnalyzerOptions options,
            DiagnosticDescriptor rule,
            InterproceduralAnalysisKind defaultValue,
            CancellationToken cancellationToken)
            => options.GetNonFlagsEnumOptionValue(EditorConfigOptionNames.InterproceduralAnalysisKind, rule, defaultValue, cancellationToken);
    }
}
