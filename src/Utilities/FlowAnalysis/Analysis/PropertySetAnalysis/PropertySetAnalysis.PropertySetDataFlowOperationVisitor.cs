﻿// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using Analyzer.Utilities.Extensions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.PointsToAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Analyzer.Utilities.FlowAnalysis.Analysis.PropertySetAnalysis
{
    using PropertySetAnalysisData = DictionaryAnalysisData<AbstractLocation, PropertySetAbstractValue>;

    internal partial class PropertySetAnalysis
    {
        /// <summary>
        /// Operation visitor to flow the location validation values across a given statement in a basic block.
        /// </summary>
        private sealed class PropertySetDataFlowOperationVisitor :
            AbstractLocationDataFlowOperationVisitor<PropertySetAnalysisData, PropertySetAnalysisContext, PropertySetAnalysisResult, PropertySetAbstractValue>
        {
            private readonly ImmutableDictionary<(Location Location, IMethodSymbol Method), PropertySetAbstractValue>.Builder _hazardousUsageBuilder;
            private INamedTypeSymbol DeserializerTypeSymbol;

            public PropertySetDataFlowOperationVisitor(PropertySetAnalysisContext analysisContext)
                : base(analysisContext)
            {
                Debug.Assert(analysisContext.PointsToAnalysisResultOpt != null);

                _hazardousUsageBuilder = ImmutableDictionary.CreateBuilder<(Location Location, IMethodSymbol Method), PropertySetAbstractValue>();

                this.WellKnownTypeProvider.TryGetTypeByMetadataName(analysisContext.TypeToTrackMetadataName, out this.DeserializerTypeSymbol);
            }

            public override int GetHashCode()
            {
                return HashUtilities.Combine(_hazardousUsageBuilder.GetHashCode(), base.GetHashCode());
            }

            public ImmutableDictionary<(Location Location, IMethodSymbol Method), PropertySetAbstractValue> HazardousUsages
            {
                get
                {
                    return _hazardousUsageBuilder.ToImmutable();
                }
            }

            protected override PropertySetAbstractValue GetAbstractDefaultValue(ITypeSymbol type) => ValueDomain.Bottom;

            protected override bool HasAnyAbstractValue(PropertySetAnalysisData data) => data.Count > 0;

            protected override PropertySetAbstractValue GetAbstractValue(AbstractLocation location)
                => this.CurrentAnalysisData.TryGetValue(location, out var value) ? value : ValueDomain.Bottom;

            protected override void ResetCurrentAnalysisData() => ResetAnalysisData(CurrentAnalysisData);

            protected override void StopTrackingAbstractValue(AbstractLocation location) => CurrentAnalysisData.Remove(location);

            protected override void SetAbstractValue(AbstractLocation location, PropertySetAbstractValue value)
            {
                if (value != PropertySetAbstractValue.Unknown
                    || this.CurrentAnalysisData.ContainsKey(location))
                {
                    this.CurrentAnalysisData[location] = value;
                }
            }

            protected override PropertySetAnalysisData MergeAnalysisData(PropertySetAnalysisData value1, PropertySetAnalysisData value2)
                => BinaryFormatterAnalysisDomainInstance.Merge(value1, value2);
            protected override PropertySetAnalysisData GetClonedAnalysisData(PropertySetAnalysisData analysisData)
                => GetClonedAnalysisDataHelper(analysisData);
            public override PropertySetAnalysisData GetEmptyAnalysisData()
                => GetEmptyAnalysisDataHelper();
            protected override PropertySetAnalysisData GetExitBlockOutputData(PropertySetAnalysisResult analysisResult)
                => GetClonedAnalysisDataHelper(analysisResult.ExitBlockOutput.Data);
            protected override bool Equals(PropertySetAnalysisData value1, PropertySetAnalysisData value2)
                => EqualsHelper(value1, value2);

            protected override void SetValueForParameterPointsToLocationOnEntry(IParameterSymbol parameter, PointsToAbstractValue pointsToAbstractValue)
            {
            }

            protected override void EscapeValueForParameterPointsToLocationOnExit(IParameterSymbol parameter, AnalysisEntity analysisEntity, PointsToAbstractValue pointsToAbstractValue)
            {
            }

            protected override void SetAbstractValueForArrayElementInitializer(IArrayCreationOperation arrayCreation, ImmutableArray<AbstractIndex> indices, ITypeSymbol elementType, IOperation initializer, PropertySetAbstractValue value)
            {
            }

            protected override void SetAbstractValueForAssignment(IOperation target, IOperation assignedValueOperation, PropertySetAbstractValue assignedValue, bool mayBeAssignment = false)
            {
            }

            public override PropertySetAbstractValue VisitObjectCreation(IObjectCreationOperation operation, object argument)
            {
                PropertySetAbstractValue abstractValue = base.VisitObjectCreation(operation, argument);
                if (operation.Type == this.DeserializerTypeSymbol)
                {
                    abstractValue = this.DataFlowAnalysisContext.IsNewInstanceFlagged 
                        ? PropertySetAbstractValue.Flagged 
                        : PropertySetAbstractValue.Unflagged;
                    PointsToAbstractValue pointsToAbstractValue = this.GetPointsToAbstractValue(operation);
                    this.SetAbstractValue(pointsToAbstractValue, abstractValue);
                    return abstractValue;
                }

                return abstractValue;
            }

            protected override PropertySetAbstractValue VisitAssignmentOperation(IAssignmentOperation operation, object argument)
            {
                PropertySetAbstractValue baseValue = base.VisitAssignmentOperation(operation, argument);
                if (operation.Target is IPropertyReferenceOperation propertyReferenceOperation
                    && propertyReferenceOperation.Property.MatchPropertyByName(
                        this.DeserializerTypeSymbol,
                        this.DataFlowAnalysisContext.PropertyToSetFlag))
                {
                    PointsToAbstractValue pointsToAbstractValue = GetPointsToAbstractValue(propertyReferenceOperation.Instance);
                    NullAbstractValue nullAbstractValue = this.GetNullAbstractValue(operation.Value);
                    PropertySetAbstractValue abstractValue;

                    if (nullAbstractValue == NullAbstractValue.Null)
                    {
                        abstractValue = this.DataFlowAnalysisContext.IsNullPropertyFlagged
                            ? PropertySetAbstractValue.Flagged
                            : PropertySetAbstractValue.Unflagged;
                    }
                    else if (nullAbstractValue == NullAbstractValue.NotNull)
                    {
                        abstractValue = this.DataFlowAnalysisContext.IsNullPropertyFlagged
                            ? PropertySetAbstractValue.Unflagged
                            : PropertySetAbstractValue.Flagged;
                    }
                    else
                    {
                        abstractValue = PropertySetAbstractValue.MaybeFlagged;
                    }

                    this.SetAbstractValue(pointsToAbstractValue, abstractValue);
                }

                return baseValue;
            }

            public override PropertySetAbstractValue VisitInvocation_NonLambdaOrDelegateOrLocalFunction(IMethodSymbol method, IOperation visitedInstance, ImmutableArray<IArgumentOperation> visitedArguments, bool invokedAsDelegate, IOperation originalOperation, PropertySetAbstractValue defaultValue)
            {
                PropertySetAbstractValue baseValue = base.VisitInvocation_NonLambdaOrDelegateOrLocalFunction(method, visitedInstance, visitedArguments, invokedAsDelegate, originalOperation, defaultValue);
                if (visitedInstance?.Type == this.DeserializerTypeSymbol
                    && this.DataFlowAnalysisContext.MethodNamesToCheckForFlaggedUsage.Contains(method.MetadataName))
                {
                    PointsToAbstractValue pointsToAbstractValue = this.GetPointsToAbstractValue(visitedInstance);
                    bool hasFlagged = false;
                    bool hasMaybeFlagged = false;
                    foreach (AbstractLocation location in pointsToAbstractValue.Locations)
                    {
                        PropertySetAbstractValue locationAbstractValue = this.GetAbstractValue(location);
                        if (locationAbstractValue == PropertySetAbstractValue.Flagged)
                        {
                            hasFlagged = true;
                        }
                        else if (locationAbstractValue == PropertySetAbstractValue.MaybeFlagged
                            || locationAbstractValue == PropertySetAbstractValue.Unknown)
                        {
                            // NotApplicable also means we don't know.
                            hasMaybeFlagged = true;
                        }
                    }

                    (Location, IMethodSymbol) key = (originalOperation.Syntax.GetLocation(), method);
                    if (hasFlagged && !hasMaybeFlagged)
                    {
                        this._hazardousUsageBuilder.Add(key, PropertySetAbstractValue.Flagged);
                    }
                    else if ((hasFlagged || hasMaybeFlagged)
                        && !this._hazardousUsageBuilder.ContainsKey(key))   // Keep existing value, if there is one.
                    {
                        this._hazardousUsageBuilder.Add(key, PropertySetAbstractValue.MaybeFlagged);
                    }
                }

                return baseValue;
            }
        }
    }
}
