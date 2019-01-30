﻿// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.CopyAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.PointsToAnalysis;

#pragma warning disable CA1067 // Override Object.Equals(object) when implementing IEquatable<T>

namespace Analyzer.Utilities.FlowAnalysis.Analysis.PropertySetAnalysis
{
    using CopyAnalysisResult = DataFlowAnalysisResult<CopyBlockAnalysisResult, CopyAbstractValue>;
    using InterproceduralBinaryFormatterAnalysisData = InterproceduralAnalysisData<DictionaryAnalysisData<AbstractLocation, PropertySetAbstractValue>, PropertySetAnalysisContext, PropertySetAbstractValue>;
    using PointsToAnalysisResult = DataFlowAnalysisResult<PointsToBlockAnalysisResult, PointsToAbstractValue>;
    using PropertySetAnalysisData = DictionaryAnalysisData<AbstractLocation, PropertySetAbstractValue>;

    /// <summary>
    /// Analysis context for execution of <see cref="PropertySetAnalysis"/> on a control flow graph.
    /// </summary>
    internal sealed class PropertySetAnalysisContext : AbstractDataFlowAnalysisContext<PropertySetAnalysisData, PropertySetAnalysisContext, PropertySetAnalysisResult, PropertySetAbstractValue>
    {
        private PropertySetAnalysisContext(
            AbstractValueDomain<PropertySetAbstractValue> valueDomain,
            WellKnownTypeProvider wellKnownTypeProvider,
            ControlFlowGraph controlFlowGraph,
            ISymbol owningSymbol,
            InterproceduralAnalysisConfiguration interproceduralAnalysisConfig,
            bool pessimisticAnalysis,
            PointsToAnalysisResult pointsToAnalysisResultOpt,
            Func<PropertySetAnalysisContext, PropertySetAnalysisResult> getOrComputeAnalysisResult,
            ControlFlowGraph parentControlFlowGraphOpt,
            InterproceduralBinaryFormatterAnalysisData interproceduralAnalysisDataOpt,
            string typeToTrackMetadataName,
            bool isNewInstanceFlagged,
            string propertyToSetFlag,
            bool isNullPropertyFlagged,
            ImmutableHashSet<string> methodNamesToCheckForFlaggedUsage)
            : base(valueDomain, wellKnownTypeProvider, controlFlowGraph, owningSymbol, interproceduralAnalysisConfig, pessimisticAnalysis,
                  predicateAnalysis: false, copyAnalysisResultOpt: null, pointsToAnalysisResultOpt: pointsToAnalysisResultOpt,
                  getOrComputeAnalysisResult: getOrComputeAnalysisResult,
                  parentControlFlowGraphOpt: parentControlFlowGraphOpt,
                  interproceduralAnalysisDataOpt: interproceduralAnalysisDataOpt)
        {
            this.TypeToTrackMetadataName = typeToTrackMetadataName;
            this.IsNewInstanceFlagged = isNewInstanceFlagged;
            this.PropertyToSetFlag = propertyToSetFlag;
            this.IsNullPropertyFlagged = isNullPropertyFlagged;
            this.MethodNamesToCheckForFlaggedUsage = methodNamesToCheckForFlaggedUsage;
        }

        public static PropertySetAnalysisContext Create(
            AbstractValueDomain<PropertySetAbstractValue> valueDomain,
            WellKnownTypeProvider wellKnownTypeProvider,
            ControlFlowGraph controlFlowGraph,
            ISymbol owningSymbol,
            InterproceduralAnalysisConfiguration interproceduralAnalysisConfig,
            bool pessimisticAnalysis,
            PointsToAnalysisResult pointsToAnalysisResultOpt,
            Func<PropertySetAnalysisContext, PropertySetAnalysisResult> getOrComputeAnalysisResult,
            string typeToTrackMetadataName,
            bool isNewInstanceFlagged,
            string propertyToSetFlag,
            bool isNullPropertyFlagged,
            ImmutableHashSet<string> methodNamesToCheckForFlaggedUsage)

        {
            return new PropertySetAnalysisContext(
                valueDomain,
                wellKnownTypeProvider, 
                controlFlowGraph,
                owningSymbol,
                interproceduralAnalysisConfig,
                pessimisticAnalysis,
                pointsToAnalysisResultOpt, 
                getOrComputeAnalysisResult, 
                parentControlFlowGraphOpt: null,
                interproceduralAnalysisDataOpt: null,
                typeToTrackMetadataName: typeToTrackMetadataName,
                isNewInstanceFlagged: isNewInstanceFlagged,
                propertyToSetFlag: propertyToSetFlag,
                isNullPropertyFlagged: isNullPropertyFlagged,
                methodNamesToCheckForFlaggedUsage: methodNamesToCheckForFlaggedUsage);
        }

        public override PropertySetAnalysisContext ForkForInterproceduralAnalysis(
            IMethodSymbol invokedMethod,
            ControlFlowGraph invokedCfg,
            IOperation operation,
            PointsToAnalysisResult pointsToAnalysisResultOpt,
            CopyAnalysisResult copyAnalysisResultOpt,
            InterproceduralBinaryFormatterAnalysisData interproceduralAnalysisData)
        {
            Debug.Assert(pointsToAnalysisResultOpt != null);
            Debug.Assert(copyAnalysisResultOpt == null);

            return new PropertySetAnalysisContext(
                ValueDomain, WellKnownTypeProvider, invokedCfg, invokedMethod, InterproceduralAnalysisConfiguration,
                PessimisticAnalysis, pointsToAnalysisResultOpt, GetOrComputeAnalysisResult, ControlFlowGraph,
                interproceduralAnalysisData,
                this.TypeToTrackMetadataName,
                this.IsNewInstanceFlagged,
                this.PropertyToSetFlag,
                this.IsNullPropertyFlagged,
                this.MethodNamesToCheckForFlaggedUsage);
        }

        /// <summary>
        /// Metadata name of the type to track.
        /// </summary>
        public string TypeToTrackMetadataName { get; }

        /// <summary>
        /// How newly created instances should be considered: flagged or unflagged.
        /// </summary>
        public bool IsNewInstanceFlagged { get; }

        /// <summary>
        /// Name of the property that when assigned to, may change the abstract value.
        /// </summary>
        public string PropertyToSetFlag { get; }

        /// <summary>
        /// Whether to change the abstract value of the instance to flagged or not flagged,
        /// when the <see cref="PropertyToSetFlag"/> property is set to null or non-null.
        /// </summary>
        public bool IsNullPropertyFlagged { get; }

        /// <summary>
        /// Method names for invocations that check whether the instance is flagged or maybe flagged.
        /// </summary>
        public ImmutableHashSet<string> MethodNamesToCheckForFlaggedUsage { get; }

#pragma warning disable CA1307 // Specify StringComparison - string.GetHashCode(StringComparison) not available in all projects that reference this shared project
        protected override void ComputeHashCodePartsSpecific(ArrayBuilder<int> builder)
        {
            builder.Add(TypeToTrackMetadataName.GetHashCode());
            builder.Add(IsNewInstanceFlagged.GetHashCode());
            builder.Add(PropertyToSetFlag.GetHashCode());
            builder.Add(IsNullPropertyFlagged.GetHashCode());
            builder.Add(HashUtilities.Combine(MethodNamesToCheckForFlaggedUsage));
        }
#pragma warning restore CA1307 // Specify StringComparison
    }
}
