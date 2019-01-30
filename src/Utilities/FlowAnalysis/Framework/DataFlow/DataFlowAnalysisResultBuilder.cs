﻿// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System;
using System.Collections.Immutable;
using Analyzer.Utilities.Extensions;

namespace Microsoft.CodeAnalysis.FlowAnalysis.DataFlow
{
    /// <summary>
    /// Used by <see cref="DataFlowAnalysis"/> to store intermediate dataflow results while executing data flow analysis
    /// and also to compute the final <see cref="DataFlowAnalysisResult{TAnalysisResult, TAbstractAnalysisValue}"/> exposed as the result.
    /// </summary>
    internal sealed class DataFlowAnalysisResultBuilder<TAnalysisData> : IDisposable
        where TAnalysisData : AbstractAnalysisData
    {
        private readonly PooledDictionary<BasicBlock, TAnalysisData> _info;

        public DataFlowAnalysisResultBuilder()
        {
            _info = PooledDictionary<BasicBlock, TAnalysisData>.GetInstance();
        }

        public TAnalysisData this[BasicBlock block] => _info[block];
        public TAnalysisData EntryBlockOutputData { get; set; }
        public TAnalysisData ExitBlockOutputData { get; set; }

        internal void Add(BasicBlock block)
        {
            _info.Add(block, null);
        }

        internal void Update(BasicBlock block, TAnalysisData newData)
        {
            _info[block] = newData;
        }

        public DataFlowAnalysisResult<TBlockAnalysisResult, TAbstractAnalysisValue> ToResult<TBlockAnalysisResult, TAbstractAnalysisValue>(
            Func<BasicBlock, TAnalysisData, TBlockAnalysisResult> getBlockResult,
            ImmutableDictionary<IOperation, TAbstractAnalysisValue> stateMap,
            ImmutableDictionary<IOperation, PredicateValueKind> predicateValueKindMap,
            (TAbstractAnalysisValue, PredicateValueKind)? returnValueAndPredicateKindOpt,
            ImmutableDictionary<IOperation, IDataFlowAnalysisResult<TAbstractAnalysisValue>> interproceduralResultsMap,
            TAnalysisData entryBlockOutputData,
            TAnalysisData exitBlockOutputData,
            TAnalysisData mergedDataForUnhandledThrowOperationsOpt,
            ControlFlowGraph cfg,
            TAbstractAnalysisValue defaultUnknownValue)
            where TBlockAnalysisResult: AbstractBlockAnalysisResult
        {
            var resultBuilder = PooledDictionary<BasicBlock, TBlockAnalysisResult>.GetInstance();
            foreach (var kvp in _info)
            {
                var block = kvp.Key;
                var blockAnalysisData = kvp.Value;
                var result = getBlockResult(block, blockAnalysisData);
                resultBuilder.Add(block, result);
            }

            TBlockAnalysisResult mergedStateForUnhandledThrowOperationsOpt = null;
            if (mergedDataForUnhandledThrowOperationsOpt != null)
            {
                mergedStateForUnhandledThrowOperationsOpt = getBlockResult(cfg.GetExit(), mergedDataForUnhandledThrowOperationsOpt);
            }

            var entryBlockOutputResult = getBlockResult(cfg.GetEntry(), entryBlockOutputData);
            var exitBlockOutputResult = getBlockResult(cfg.GetExit(), exitBlockOutputData);

            return new DataFlowAnalysisResult<TBlockAnalysisResult, TAbstractAnalysisValue>(resultBuilder.ToImmutableDictionaryAndFree(), stateMap,
                predicateValueKindMap, returnValueAndPredicateKindOpt, interproceduralResultsMap,
                entryBlockOutputResult, exitBlockOutputResult, mergedStateForUnhandledThrowOperationsOpt, cfg, defaultUnknownValue);
        }

        public void Dispose()
        {
            _info.Values.Dispose();
            _info.Free();
        }
    }
}
