// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System.Collections.Immutable;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Microsoft.NetFramework.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public partial class MarkVerbHandlersWithValidateAntiforgeryTokenAnalyzer : DiagnosticAnalyzer
    {
        internal const string RuleId = "CA3147";
        private const string HelpLinkUri = "https://aka.ms/ca3147";

        private static readonly LocalizableString Title = new LocalizableResourceString(
            nameof(MicrosoftSecurityAnalyzersResources.MarkVerbHandlersWithValidateAntiforgeryTokenTitle),
            MicrosoftSecurityAnalyzersResources.ResourceManager,
            typeof(MicrosoftSecurityAnalyzersResources));

        private static readonly LocalizableString NoVerbsMessage = new LocalizableResourceString(
            nameof(MicrosoftSecurityAnalyzersResources.MarkVerbHandlersWithValidateAntiforgeryTokenNoVerbsMessage),
            MicrosoftSecurityAnalyzersResources.ResourceManager,
            typeof(MicrosoftSecurityAnalyzersResources));

        private static readonly LocalizableString NoVerbsNoTokenMessage = new LocalizableResourceString(
            nameof(MicrosoftSecurityAnalyzersResources.MarkVerbHandlersWithValidateAntiforgeryTokenNoVerbsNoTokenMessage),
            MicrosoftSecurityAnalyzersResources.ResourceManager,
            typeof(MicrosoftSecurityAnalyzersResources));

        private static readonly LocalizableString GetAndTokenMessage = new LocalizableResourceString(
            nameof(MicrosoftSecurityAnalyzersResources.MarkVerbHandlersWithValidateAntiforgeryTokenGetAndTokenMessage),
            MicrosoftSecurityAnalyzersResources.ResourceManager,
            typeof(MicrosoftSecurityAnalyzersResources));

        private static readonly LocalizableString GetAndOtherAndTokenMessage = new LocalizableResourceString(
            nameof(MicrosoftSecurityAnalyzersResources.MarkVerbHandlersWithValidateAntiforgeryTokenGetAndOtherAndTokenMessage),
            MicrosoftSecurityAnalyzersResources.ResourceManager,
            typeof(MicrosoftSecurityAnalyzersResources));

        private static readonly LocalizableString VerbsAndNoTokenMessage = new LocalizableResourceString(
            nameof(MicrosoftSecurityAnalyzersResources.MarkVerbHandlersWithValidateAntiforgeryTokenVerbsAndNoTokenMessage),
            MicrosoftSecurityAnalyzersResources.ResourceManager,
            typeof(MicrosoftSecurityAnalyzersResources));

        internal static readonly DiagnosticDescriptor NoVerbsRule = new DiagnosticDescriptor(
            RuleId,
            Title,
            NoVerbsMessage,
            DiagnosticCategory.Security,
            DiagnosticHelpers.DefaultDiagnosticSeverity,
            isEnabledByDefault: true,
            helpLinkUri: HelpLinkUri);

        internal static readonly DiagnosticDescriptor NoVerbsNoTokenRule = new DiagnosticDescriptor(
            RuleId,
            Title,
            NoVerbsNoTokenMessage,
            DiagnosticCategory.Security,
            DiagnosticHelpers.DefaultDiagnosticSeverity,
            isEnabledByDefault: true,
            helpLinkUri: HelpLinkUri);

        internal static readonly DiagnosticDescriptor GetAndTokenRule = new DiagnosticDescriptor(
            RuleId,
            Title,
            GetAndTokenMessage,
            DiagnosticCategory.Security,
            DiagnosticHelpers.DefaultDiagnosticSeverity,
            isEnabledByDefault: true,
            helpLinkUri: HelpLinkUri);

        internal static readonly DiagnosticDescriptor GetAndOtherAndTokenRule = new DiagnosticDescriptor(
            RuleId,
            Title,
            GetAndOtherAndTokenMessage,
            DiagnosticCategory.Security,
            DiagnosticHelpers.DefaultDiagnosticSeverity,
            isEnabledByDefault: true,
            helpLinkUri: HelpLinkUri);

        internal static readonly DiagnosticDescriptor VerbsAndNoTokenRule = new DiagnosticDescriptor(
            RuleId,
            Title,
            VerbsAndNoTokenMessage,
            DiagnosticCategory.Security,
            DiagnosticHelpers.DefaultDiagnosticSeverity,
            isEnabledByDefault: true,
            helpLinkUri: HelpLinkUri);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(NoVerbsRule, NoVerbsNoTokenRule, GetAndTokenRule, GetAndOtherAndTokenRule, VerbsAndNoTokenRule);

        public override void Initialize(AnalysisContext analysisContext)
        {
            analysisContext.EnableConcurrentExecution();
            analysisContext.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            analysisContext.RegisterCompilationStartAction(
                (CompilationStartAnalysisContext compilationStartContext) =>
                {
                    INamedTypeSymbol mvcControllerSymbol = WellKnownTypes.MvcController(compilationStartContext.Compilation);
                    INamedTypeSymbol mvcControllerBaseSymbol = WellKnownTypes.MvcControllerBase(compilationStartContext.Compilation);
                    INamedTypeSymbol actionResultSymbol = WellKnownTypes.ActionResult(compilationStartContext.Compilation);

                    if ((mvcControllerSymbol == null && mvcControllerBaseSymbol == null) || actionResultSymbol == null)
                    {
                        // No MVC controllers that return an ActionResult here.
                        return;
                    }

                    MvcAttributeSymbols mvcAttributeSymbols = new MvcAttributeSymbols(compilationStartContext.Compilation);

                    compilationStartContext.RegisterSymbolAction(
                        (SymbolAnalysisContext symbolContext) =>
                        {
                            // TODO enhancements: Consider looking at non-ActionResult-derived return types as well.
                            if (!(symbolContext.Symbol is IMethodSymbol methodSymbol)
                                || methodSymbol.MethodKind != MethodKind.Ordinary
                                || methodSymbol.IsStatic
                                || !methodSymbol.IsPublic()
                                || !methodSymbol.ReturnType.Inherits(actionResultSymbol)  // FxCop implementation only looks at ActionResult-derived return types.
                                || (!methodSymbol.ContainingType.Inherits(mvcControllerSymbol)
                                    && !methodSymbol.ContainingType.Inherits(mvcControllerBaseSymbol)))
                            {
                                return;
                            }

                            ImmutableArray<AttributeData> methodAttributes = methodSymbol.GetAttributes();
                            mvcAttributeSymbols.ComputeAttributeInfo(methodAttributes, out var verbs, out var isAntiforgeryTokenDefined, out var isAction);

                            if (!isAction)
                            {
                                return;
                            }

                            if (verbs == MvcHttpVerbs.None)
                            {
                                // no verbs specified
                                if (isAntiforgeryTokenDefined)
                                {
                                    // antiforgery token attribute is set, but verbs are not specified
                                    symbolContext.ReportDiagnostic(Diagnostic.Create(NoVerbsRule, methodSymbol.Locations[0], methodSymbol.MetadataName));
                                }
                                else
                                {
                                    // no verbs, no antiforgery token attribute
                                    symbolContext.ReportDiagnostic(Diagnostic.Create(NoVerbsNoTokenRule, methodSymbol.Locations[0], methodSymbol.MetadataName));
                                }
                            }
                            else
                            {
                                // verbs are defined 
                                if (isAntiforgeryTokenDefined)
                                {
                                    if (verbs.HasFlag(MvcHttpVerbs.Get))
                                    {
                                        symbolContext.ReportDiagnostic(Diagnostic.Create(GetAndTokenRule, methodSymbol.Locations[0], methodSymbol.MetadataName));

                                        if ((verbs & (MvcHttpVerbs.Post | MvcHttpVerbs.Put | MvcHttpVerbs.Delete | MvcHttpVerbs.Patch)) != MvcHttpVerbs.None)
                                        {
                                            // both verbs, antiforgery token attribute
                                            symbolContext.ReportDiagnostic(Diagnostic.Create(GetAndOtherAndTokenRule, methodSymbol.Locations[0], methodSymbol.MetadataName));
                                        }
                                    }
                                }
                                else
                                {
                                    if ((verbs & (MvcHttpVerbs.Post | MvcHttpVerbs.Put | MvcHttpVerbs.Delete | MvcHttpVerbs.Patch)) != MvcHttpVerbs.None)
                                    {
                                        // HttpPost, no antiforgery token attribute
                                        symbolContext.ReportDiagnostic(Diagnostic.Create(VerbsAndNoTokenRule, methodSymbol.Locations[0], methodSymbol.MetadataName));
                                    }
                                }
                            }
                        },
                        SymbolKind.Method);
                }
            );
        }
    }
}
