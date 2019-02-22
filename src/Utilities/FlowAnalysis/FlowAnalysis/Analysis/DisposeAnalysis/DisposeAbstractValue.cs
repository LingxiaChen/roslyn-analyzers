﻿// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System;
using System.Collections.Immutable;
using System.Diagnostics;
using Analyzer.Utilities;

#pragma warning disable CA1067 // Override Object.Equals(object) when implementing IEquatable<T> - CacheBasedEquatable handles equality

namespace Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.DisposeAnalysis
{
    /// <summary>
    /// Abstract dispose data tracked by <see cref="DisposeAnalysis"/>.
    /// It contains the set of <see cref="IOperation"/>s that dispose an associated disposable <see cref="AbstractLocation"/> and
    /// the dispose <see cref="Kind"/>.
    /// </summary>
    public class DisposeAbstractValue : CacheBasedEquatable<DisposeAbstractValue>
    {
        public static readonly DisposeAbstractValue NotDisposable = new DisposeAbstractValue(DisposeAbstractValueKind.NotDisposable);
        public static readonly DisposeAbstractValue NotDisposed = new DisposeAbstractValue(DisposeAbstractValueKind.NotDisposed);
        public static readonly DisposeAbstractValue Unknown = new DisposeAbstractValue(DisposeAbstractValueKind.MaybeDisposed);

        private DisposeAbstractValue(DisposeAbstractValueKind kind)
            : this(ImmutableHashSet<IOperation>.Empty, kind)
        {
            Debug.Assert(kind != DisposeAbstractValueKind.Disposed);
        }

        internal DisposeAbstractValue(ImmutableHashSet<IOperation> disposingOrEscapingOperations, DisposeAbstractValueKind kind)
        {
            VerifyArguments(disposingOrEscapingOperations, kind);
            DisposingOrEscapingOperations = disposingOrEscapingOperations;
            Kind = kind;
        }

        internal DisposeAbstractValue WithNewDisposingOperation(IOperation disposingOperation)
        {
            Debug.Assert(Kind != DisposeAbstractValueKind.NotDisposable);

            return new DisposeAbstractValue(DisposingOrEscapingOperations.Add(disposingOperation), DisposeAbstractValueKind.Disposed);
        }

        internal DisposeAbstractValue WithNewEscapingOperation(IOperation escapingOperation)
        {
            Debug.Assert(Kind != DisposeAbstractValueKind.NotDisposable);

            return new DisposeAbstractValue(DisposingOrEscapingOperations.Add(escapingOperation), DisposeAbstractValueKind.MaybeDisposed);
        }

        [Conditional("DEBUG")]
        private static void VerifyArguments(ImmutableHashSet<IOperation> disposingOrEscapingOperations, DisposeAbstractValueKind kind)
        {
            Debug.Assert(disposingOrEscapingOperations != null);

            switch (kind)
            {
                case DisposeAbstractValueKind.NotDisposable:
                case DisposeAbstractValueKind.NotDisposed:
                    Debug.Assert(disposingOrEscapingOperations.Count == 0);
                    break;

                case DisposeAbstractValueKind.Disposed:
                    Debug.Assert(disposingOrEscapingOperations.Count > 0);
                    break;
            }
        }

        public ImmutableHashSet<IOperation> DisposingOrEscapingOperations { get; }
        public DisposeAbstractValueKind Kind { get; }

        protected override void ComputeHashCodeParts(ArrayBuilder<int> builder)
        {
            builder.Add(HashUtilities.Combine(DisposingOrEscapingOperations));
            builder.Add(Kind.GetHashCode());
        }
    }
}
