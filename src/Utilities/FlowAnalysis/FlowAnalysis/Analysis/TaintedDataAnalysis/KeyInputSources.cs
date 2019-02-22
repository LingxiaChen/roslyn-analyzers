// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System;
using System.Collections.Immutable;

namespace Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis
{
    internal static class KeyInputSources
    {
        /// <summary>
        /// <see cref="SourceInfo"/>s for key input tainted data sources.
        /// </summary>
        public static ImmutableHashSet<SourceInfo> SourceInfos { get; }

        /// <summary>
        /// Statically constructs.
        /// </summary>
        static KeyInputSources()
        {
            ImmutableHashSet<SourceInfo>.Builder sourceInfosBuilder = ImmutableHashSet.CreateBuilder<SourceInfo>();

            AddLiteralArraySource(
                sourceInfosBuilder,
                "System.Byte");

            AddConcreteSource(
                sourceInfosBuilder,
                WellKnownTypeNames.SystemTextEncoding,
                taintedProperties: null,
                taintedMethods: new string[] {
                    "GetBytes"
                });

            SourceInfos = sourceInfosBuilder.ToImmutable();
        }

        private static void AddConcreteSource(
            ImmutableHashSet<SourceInfo>.Builder builder,
            string fullTypeName,
            string[] taintedProperties,
            string[] taintedMethods)
        {
            AddSource(builder, fullTypeName, false, taintedProperties, taintedMethods, false);
        }

        private static void AddInterfaceSource(
            ImmutableHashSet<SourceInfo>.Builder builder,
            string fullTypeName,
            string[] taintedProperties,
            string[] taintedMethods)
        {
            AddSource(builder, fullTypeName, true, taintedProperties, taintedMethods, false);
        }

        private static void AddLiteralArraySource(
            ImmutableHashSet<SourceInfo>.Builder builder,
            string fullTypeName)
        {
            AddSource(builder, fullTypeName, false, null, null, true);
        }

        private static void AddSource(
            ImmutableHashSet<SourceInfo>.Builder builder,
            string fullTypeName,
            bool isInterface,
            string[] taintedProperties,
            string[] taintedMethods,
            bool fromLiteralArray)
        {
            SourceInfo metadata = new SourceInfo(
                fullTypeName,
                isInterface: isInterface,
                taintedProperties: taintedProperties != null
                    ? ImmutableHashSet.Create<string>(StringComparer.Ordinal, taintedProperties)
                    : ImmutableHashSet<string>.Empty,
                taintedMethods: taintedMethods != null
                    ? ImmutableHashSet.Create<string>(StringComparer.Ordinal, taintedMethods)
                    : ImmutableHashSet<string>.Empty,
                fromLiteralArray: fromLiteralArray);
            builder.Add(metadata);
        }
    }
}
