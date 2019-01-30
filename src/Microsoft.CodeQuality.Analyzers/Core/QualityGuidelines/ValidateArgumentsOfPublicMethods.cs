﻿// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System.Collections.Immutable;
using System.Linq;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.ParameterValidationAnalysis;

namespace Microsoft.CodeQuality.Analyzers.QualityGuidelines
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public sealed class ValidateArgumentsOfPublicMethods : DiagnosticAnalyzer
    {
        internal const string RuleId = "CA1062";

        private static readonly LocalizableString s_localizableTitle = new LocalizableResourceString(nameof(MicrosoftQualityGuidelinesAnalyzersResources.ValidateArgumentsOfPublicMethodsTitle), MicrosoftQualityGuidelinesAnalyzersResources.ResourceManager, typeof(MicrosoftQualityGuidelinesAnalyzersResources));
        private static readonly LocalizableString s_localizableMessage = new LocalizableResourceString(nameof(MicrosoftQualityGuidelinesAnalyzersResources.ValidateArgumentsOfPublicMethodsMessage), MicrosoftQualityGuidelinesAnalyzersResources.ResourceManager, typeof(MicrosoftQualityGuidelinesAnalyzersResources));
        private static readonly LocalizableString s_localizableDescription = new LocalizableResourceString(nameof(MicrosoftQualityGuidelinesAnalyzersResources.ValidateArgumentsOfPublicMethodsDescription), MicrosoftQualityGuidelinesAnalyzersResources.ResourceManager, typeof(MicrosoftQualityGuidelinesAnalyzersResources));

        internal static DiagnosticDescriptor Rule = new DiagnosticDescriptor(RuleId,
                                                                             s_localizableTitle,
                                                                             s_localizableMessage,
                                                                             DiagnosticCategory.Design,
                                                                             DiagnosticHelpers.DefaultDiagnosticSeverity,
                                                                             isEnabledByDefault: DiagnosticHelpers.EnabledByDefaultIfNotBuildingVSIX,
                                                                             description: s_localizableDescription,
                                                                             helpLinkUri: "https://docs.microsoft.com/visualstudio/code-quality/ca1062-validate-arguments-of-public-methods",
                                                                             customTags: FxCopWellKnownDiagnosticTags.PortedFxCopDataflowRule);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            context.RegisterCompilationStartAction(compilationContext =>
            {
                compilationContext.RegisterOperationBlockAction(operationBlockContext =>
                {
                    // Analyze externally visible methods with reference type parameters.
                    if (!(operationBlockContext.OwningSymbol is IMethodSymbol containingMethod) ||
                        !containingMethod.IsExternallyVisible() ||
                        !containingMethod.Parameters.Any(p => p.Type.IsReferenceType))
                    {
                        return;
                    }

                    // Bail out early if we have no parameter references in the method body. 
                    if (!operationBlockContext.OperationBlocks.HasAnyOperationDescendant(OperationKind.ParameterReference))
                    {
                        return;
                    }

                    // Perform analysis of all direct/indirect parameter usages in the method to get all non-validated usages that can cause a null dereference.
                    ImmutableDictionary<IParameterSymbol, SyntaxNode> hazardousParameterUsages = null;
                    foreach (var operationBlock in operationBlockContext.OperationBlocks)
                    {
                        if (operationBlock is IBlockOperation topmostBlock)
                        {
                            hazardousParameterUsages = ParameterValidationAnalysis.GetOrComputeHazardousParameterUsages(
                                topmostBlock, operationBlockContext.Compilation, containingMethod,
                                operationBlockContext.Options, Rule, operationBlockContext.CancellationToken);
                            break;
                        }
                    }

                    if (hazardousParameterUsages != null)
                    {
                        foreach (var kvp in hazardousParameterUsages)
                        {
                            IParameterSymbol parameter = kvp.Key;
                            SyntaxNode node = kvp.Value;

                            // In externally visible method '{0}', validate parameter '{1}' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.
                            var arg1 = containingMethod.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat);
                            var arg2 = parameter.Name;
                            var diagnostic = node.CreateDiagnostic(Rule, arg1, arg2);
                            operationBlockContext.ReportDiagnostic(diagnostic);
                        }
                    }
                });

            });
        }
    }
}
