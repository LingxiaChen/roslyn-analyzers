﻿// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow;

namespace Analyzer.Utilities.FlowAnalysis.Analysis.PropertySetAnalysis
{
    /// <summary>
    /// Collection of <see cref="HazardousUsageEvaluator"/>s.
    /// </summary>
#pragma warning disable CA1812 // Is too instantiated.
    internal sealed class HazardousUsageEvaluatorCollection
#pragma warning restore CA1812
    {
        public HazardousUsageEvaluatorCollection(IEnumerable<HazardousUsageEvaluator> hazardousUsageEvaluators)
        {
            if (hazardousUsageEvaluators == null)
            {
                throw new ArgumentNullException(nameof(hazardousUsageEvaluators));
            }

            if (!hazardousUsageEvaluators.Any())
            {
                throw new ArgumentException("No HazardUsageEvaluators specified", nameof(hazardousUsageEvaluators));
            }

            this.HazardousUsageEvaluators =
                hazardousUsageEvaluators.ToImmutableDictionary<HazardousUsageEvaluator, (string InstanceTypeName, string MethodName, string ParameterName)>(
                    h => (h.InstanceTypeName, h.MethodName, h.ParameterNameOfPropertySetObject));
        }

        public HazardousUsageEvaluatorCollection(params HazardousUsageEvaluator[] hazardousUsageEvaluators)
            : this((IEnumerable<HazardousUsageEvaluator>)hazardousUsageEvaluators)
        {
        }

        private HazardousUsageEvaluatorCollection()
        {
        }

        private ImmutableDictionary<(string InstanceTypeName, string MethodName, string ParameterName), HazardousUsageEvaluator> HazardousUsageEvaluators { get; }

        internal bool TryGetHazardousUsageEvaluator(string trackedTypeMethodName, out HazardousUsageEvaluator hazardousUsageEvaluator)
        {
            return this.HazardousUsageEvaluators.TryGetValue((null, trackedTypeMethodName, null), out hazardousUsageEvaluator);
        }

        internal bool TryGetHazardousUsageEvaluator(string containingType, string methodName, string parameterName, out HazardousUsageEvaluator hazardousUsageEvaluator)
        {
            return this.HazardousUsageEvaluators.TryGetValue((containingType, methodName, parameterName), out hazardousUsageEvaluator);
        }

        internal ImmutableDictionary<INamedTypeSymbol, string> GetTypeToNameMapping(WellKnownTypeProvider wellKnownTypeProvider)
        {
            PooledDictionary<INamedTypeSymbol, string> pooledDictionary = PooledDictionary<INamedTypeSymbol, string>.GetInstance();
            try
            {
                foreach (KeyValuePair<(string InstanceTypeName, string MethodName, string ParameterName), HazardousUsageEvaluator> kvp
                    in this.HazardousUsageEvaluators)
                {
                    if (kvp.Key.InstanceTypeName == null)
                    {
                        continue;
                    }

                    if (wellKnownTypeProvider.TryGetTypeByMetadataName(kvp.Key.InstanceTypeName, out INamedTypeSymbol namedTypeSymbol))
                    {
                        pooledDictionary[namedTypeSymbol] = kvp.Key.InstanceTypeName;
                    }
                }

                return pooledDictionary.ToImmutableDictionaryAndFree();
            }
            catch (Exception)
            {
                pooledDictionary.Free();
                throw;
            }
        }
    }
}
