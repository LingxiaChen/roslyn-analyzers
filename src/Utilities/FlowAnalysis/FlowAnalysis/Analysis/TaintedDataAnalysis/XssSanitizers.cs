﻿// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System.Collections.Immutable;
using Analyzer.Utilities.Extensions;
using Microsoft.CodeAnalysis;

namespace Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis
{
    internal static class XssSanitizers
    {
        /// <summary>
        /// <see cref="SanitizerInfo"/>s for primitive type conversion tainted data sanitizers.
        /// </summary>
        public static ImmutableHashSet<SanitizerInfo> SanitizerInfos { get; }

        static XssSanitizers()
        {
            var builder = PooledHashSet<SanitizerInfo>.GetInstance();

            builder.AddSanitizerInfo(
                WellKnownTypeNames.MicrosoftSecurityApplicationAntiXss,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "HtmlAttributeEncode",
                    "HtmlEncode",
                    "XmlAttributeEncode",
                });
            builder.AddSanitizerInfo(
                WellKnownTypeNames.MicrosoftSecurityApplicationAntiXssEncoder,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "HtmlAttributeEncode",
                    "HtmlEncode",
                });
            builder.AddSanitizerInfo(
                WellKnownTypeNames.MicrosoftSecurityApplicationEncoder,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "HtmlAttributeEncode",
                    "HtmlEncode",
                    "XmlAttributeEncode",
                });
            builder.AddSanitizerInfo(
                WellKnownTypeNames.MicrosoftSecurityApplicationUnicodeCharacterEncoder,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "HtmlAttributeEncode",
                    "HtmlEncode",
                    "XmlAttributeEncode",
                });
            builder.AddSanitizerInfo(
                WellKnownTypeNames.SystemIDisposable,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "Dispose",
                });
            builder.AddSanitizerInfo(
                WellKnownTypeNames.SystemWebHttpServerUtility,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "HtmlEncode",
                });
            builder.AddSanitizerInfo(
                WellKnownTypeNames.SystemWebHttpServerUtilityBase,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "HtmlEncode",
                });
            builder.AddSanitizerInfo(
                WellKnownTypeNames.SystemWebHttpServerUtilityWrapper,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "HtmlEncode",
                });
            builder.AddSanitizerInfo(
                WellKnownTypeNames.SystemWebHttpUtility,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "HtmlAttributeEncode",
                    "HtmlEncode",
                });
            builder.AddSanitizerInfo(
                WellKnownTypeNames.SystemWebSecurityAntiXssAntiXssEncoder,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "HtmlAttributeEncode",
                    "HtmlEncode",
                    "XmlAttributeEncode",
                });
            builder.AddSanitizerInfo(
                WellKnownTypeNames.SystemWebSecurityAntiXssUnicodeCharacterEncoder,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "HtmlAttributeEncode",
                    "HtmlEncode",
                    "XmlAttributeEncode",
                });
            builder.AddSanitizerInfo(
                WellKnownTypeNames.SystemWebUIHtmlTextWriter,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "WriteHtmlAttributeEncode",
                });
            builder.AddSanitizerInfo(
                WellKnownTypeNames.SystemWebUtilHttpEncoder,
                isInterface: false,
                isConstructorSanitizing: false,
                sanitizingMethods: new[] {
                    "HtmlAttributeEncode",
                    "HtmlEncode",
                });

            builder.AddRange(PrimitiveTypeConverterSanitizers.SanitizerInfos);

            SanitizerInfos = builder.ToImmutableAndFree();
        }
    }
}
