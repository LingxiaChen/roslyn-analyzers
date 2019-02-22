// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System.Collections.Immutable;
using Analyzer.Utilities.Extensions;
using Microsoft.CodeAnalysis;

namespace Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis
{
    internal static class KeySinks
    {
        /// <summary>
        /// <see cref="SinkInfo"/>s for tainted data Key sinks.
        /// </summary>
        public static ImmutableHashSet<SinkInfo> SinkInfos { get; }

        static KeySinks()
        {
            var sinkInfosBuilder = PooledHashSet<SinkInfo>.GetInstance();

            sinkInfosBuilder.AddSinkInfo(
                WellKnownTypeNames.SystemSecurityCryptographySymmetricAlgorithm,
                SinkKind.Key,
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: new string[] {
                    "Key",
                },
                sinkMethodParameters: null);

            SinkInfos = sinkInfosBuilder.ToImmutableAndFree();
        }
    }
}
