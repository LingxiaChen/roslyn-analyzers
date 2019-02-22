﻿// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using Microsoft.CodeAnalysis;

namespace Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis
{
    internal static class TaintedDataSymbolMapExtensions
    {
        /// <summary>
        /// Determines if the given method is a tainted data source.
        /// </summary>
        /// <param name="sourceSymbolMap"></param>
        /// <param name="method"></param>
        /// <returns></returns>
        public static bool IsSourceMethod(this TaintedDataSymbolMap<SourceInfo> sourceSymbolMap, IMethodSymbol method)
        {
            foreach (SourceInfo sourceInfo in sourceSymbolMap.GetInfosForType(method.ContainingType))
            {
                if (sourceInfo.TaintedMethods.Contains(method.MetadataName))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Determines if the given property is a tainted data source.
        /// </summary>
        /// <param name="sourceSymbolMap"></param>
        /// <param name="propertySymbol"></param>
        /// <returns></returns>
        public static bool IsSourceProperty(this TaintedDataSymbolMap<SourceInfo> sourceSymbolMap, IPropertySymbol propertySymbol)
        {
            foreach (SourceInfo sourceInfo in sourceSymbolMap.GetInfosForType(propertySymbol.ContainingType))
            {
                if (sourceInfo.TaintedProperties.Contains(propertySymbol.MetadataName))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
