// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Microsoft.NetCore.Analyzers.ImmutableCollections
{
    /// <summary>
    /// CA2009: Do not call ToImmutableCollection on an ImmutableCollection value
    /// </summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public sealed class DoNotCallToImmutableCollectionOnAnImmutableCollectionValueAnalyzer : DiagnosticAnalyzer
    {
        private const string ImmutableArrayMetadataName = "System.Collections.Immutable.ImmutableArray`1";
        internal const string RuleId = "CA2009";

        private static readonly LocalizableString s_localizableTitle = new LocalizableResourceString(nameof(SystemCollectionsImmutableAnalyzersResources.DoNotCallToImmutableCollectionOnAnImmutableCollectionValueTitle), SystemCollectionsImmutableAnalyzersResources.ResourceManager, typeof(SystemCollectionsImmutableAnalyzersResources));
        private static readonly LocalizableString s_localizableMessage = new LocalizableResourceString(nameof(SystemCollectionsImmutableAnalyzersResources.DoNotCallToImmutableCollectionOnAnImmutableCollectionValueMessage), SystemCollectionsImmutableAnalyzersResources.ResourceManager, typeof(SystemCollectionsImmutableAnalyzersResources));

        internal static DiagnosticDescriptor Rule = new DiagnosticDescriptor(RuleId,
                                                                             s_localizableTitle,
                                                                             s_localizableMessage,
                                                                             DiagnosticCategory.Reliability,
                                                                             DiagnosticHelpers.DefaultDiagnosticSeverity,
                                                                             isEnabledByDefault: DiagnosticHelpers.EnabledByDefaultIfNotBuildingVSIX,
                                                                             helpLinkUri: null,
                                                                             customTags: WellKnownDiagnosticTags.Telemetry);

        private static readonly ImmutableDictionary<string, string> ImmutableCollectionMetadataNames = new Dictionary<string, string>
        {
            ["ToImmutableArray"] = "System.Collections.Immutable.ImmutableArray`1",
            ["ToImmutableDictionary"] = "System.Collections.Immutable.ImmutableDictionary`2",
            ["ToImmutableHashSet"] = "System.Collections.Immutable.ImmutableHashSet`1",
            ["ToImmutableList"] = "System.Collections.Immutable.ImmutableList`1",
            ["ToImmutableSortedDictionary"] = "System.Collections.Immutable.ImmutableSortedDictionary`2",
            ["ToImmutableSortedSet"] = "System.Collections.Immutable.ImmutableSortedSet`1",
        }.ToImmutableDictionary();

        public static ImmutableArray<string> ToImmutableMethodNames => ImmutableCollectionMetadataNames.Keys.ToImmutableArray();

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            context.RegisterCompilationStartAction(compilationStartContext =>
            {
                var compilation = compilationStartContext.Compilation;
                var immutableArraySymbol = compilation.GetTypeByMetadataName(ImmutableArrayMetadataName);
                if (immutableArraySymbol is null)
                {
                    var systemNamespace = compilation.GlobalNamespace.GetMembers(nameof(System)).OfType<INamespaceSymbol>().SingleOrDefault();
                    var systemCollectionsNamespace = systemNamespace?.GetMembers(nameof(System.Collections)).OfType<INamespaceSymbol>().SingleOrDefault();
                    var systemCollectionsImmutableNamespace = systemCollectionsNamespace?.GetMembers(nameof(System.Collections.Immutable)).OfType<INamespaceSymbol>().SingleOrDefault();
                    if (systemCollectionsImmutableNamespace is null)
                    {
                        return;
                    }

                    var immutableArrayTypes = systemCollectionsImmutableNamespace.GetMembers(nameof(ImmutableArray)).OfType<INamedTypeSymbol>().Where(type => type.MetadataName == typeof(ImmutableArray<>).Name).ToArray();
                    var localSymbol = immutableArrayTypes.FirstOrDefault(type => type.ContainingAssembly.Equals(compilation.Assembly));
                    var publicSymbol = immutableArrayTypes.FirstOrDefault(type => type.DeclaredAccessibility == Accessibility.Public);
                    var fallbackSymbol = immutableArrayTypes.FirstOrDefault();
                    immutableArraySymbol = localSymbol ?? publicSymbol ?? fallbackSymbol;
                }

                if (immutableArraySymbol is null)
                {
                    return;
                }

                var immutableCollectionsAssembly = immutableArraySymbol.ContainingAssembly;

                compilationStartContext.RegisterOperationAction(operationContext =>
                {
                    var invocation = (IInvocationOperation)operationContext.Operation;
                    var targetMethod = invocation.TargetMethod;
                    if (targetMethod == null || !ImmutableCollectionMetadataNames.TryGetValue(targetMethod.Name, out string metadataName))
                    {
                        return;
                    }

                    Debug.Assert(!string.IsNullOrEmpty(metadataName));

                    // Do not flag invocations that take any explicit argument (comparer, converter, etc.)
                    // as they can potentially modify the contents of the resulting collection.
                    var argumentsToSkip = invocation.IsExtensionMethodAndHasNoInstance() ? 1 : 0;
                    if (invocation.Arguments.Skip(argumentsToSkip).Any(arg => arg.ArgumentKind == ArgumentKind.Explicit))
                    {
                        return;
                    }

                    var immutableCollectionType = immutableCollectionsAssembly.GetTypeByMetadataName(metadataName);
                    if (immutableCollectionType == null)
                    {
                        // The user might be running against a custom system assembly that defines ImmutableArray,
                        // but not other immutable collection types.
                        return;
                    }

                    var receiverType = invocation.GetReceiverType(operationContext.Compilation, beforeConversion: true, cancellationToken: operationContext.CancellationToken);
                    if (receiverType != null &&
                        receiverType.DerivesFromOrImplementsAnyConstructionOf(immutableCollectionType))
                    {
                        operationContext.ReportDiagnostic(Diagnostic.Create(
                            Rule,
                            invocation.Syntax.GetLocation(),
                            targetMethod.Name,
                            immutableCollectionType.Name));
                    }
                }, OperationKind.Invocation);
            });
        }
    }
}
