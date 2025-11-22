#!/usr/bin/env python3
"""
analyze_patterns.py - Signature Database 패턴 분석 도구

tracer list 명령으로 생성된 abstract pattern을 분석합니다.
"""

import json
import os
from collections import Counter, defaultdict
from pathlib import Path
import sys


def load_signature_info(json_path):
    """Load signature info from JSON file"""
    with open(json_path, 'r') as f:
        return json.load(f)


def analyze_directory(sig_db_info_dir):
    """Analyze all signatures in the directory"""
    
    stats = {
        'total_programs': 0,
        'total_signatures': 0,
        'bug_types': Counter(),
        'qualifiers': Counter(),
        'severities': Counter(),
        'pattern_lengths': [],
        'common_patterns': Counter(),
        'sink_types': Counter(),
    }
    
    all_traces = []
    
    # Walk through all subdirectories
    for program_dir in Path(sig_db_info_dir).iterdir():
        if not program_dir.is_dir():
            continue
            
        stats['total_programs'] += 1
        
        # Process each JSON file
        for json_file in program_dir.glob('*.json'):
            try:
                sig_info = load_signature_info(json_file)
                stats['total_signatures'] += 1
                
                # Count metadata
                stats['bug_types'][sig_info['bug_type']] += 1
                stats['qualifiers'][sig_info['qualifier']] += 1
                stats['severities'][sig_info['severity']] += 1
                
                # Analyze traces
                for trace in sig_info['abstract_traces']:
                    stats['pattern_lengths'].append(len(trace))
                    all_traces.append(trace)
                    
                    # Count pattern as tuple for hashability
                    pattern_tuple = tuple(trace)
                    stats['common_patterns'][pattern_tuple] += 1
                    
                    # Identify sink type (last element usually)
                    if trace:
                        sink_types = [
                            'CMD_INJECTION', 'BUFFER_OVERFLOW', 
                            'FORMAT_STRING', 'INT_OVERFLOW', 'INT_UNDERFLOW'
                        ]
                        for elem in trace:
                            if elem in sink_types:
                                stats['sink_types'][elem] += 1
                                
            except Exception as e:
                print(f"Error processing {json_file}: {e}", file=sys.stderr)
    
    return stats, all_traces


def print_statistics(stats):
    """Print analysis statistics"""
    print("=" * 60)
    print("Signature Database 패턴 분석 결과")
    print("=" * 60)
    print()
    
    # Basic stats
    print(f"총 프로그램 수: {stats['total_programs']}")
    print(f"총 시그니처 수: {stats['total_signatures']}")
    print()
    
    # Bug types
    print("Bug Types:")
    for bug_type, count in stats['bug_types'].most_common():
        pct = count / stats['total_signatures'] * 100
        print(f"  {bug_type:30s}: {count:4d} ({pct:5.1f}%)")
    print()
    
    # Severities
    print("Severities:")
    for severity, count in stats['severities'].most_common():
        pct = count / stats['total_signatures'] * 100
        print(f"  {severity:15s}: {count:4d} ({pct:5.1f}%)")
    print()
    
    # Sink types
    print("Sink Types (취약점 종류):")
    for sink, count in stats['sink_types'].most_common():
        pct = count / sum(stats['sink_types'].values()) * 100
        print(f"  {sink:20s}: {count:4d} ({pct:5.1f}%)")
    print()
    
    # Pattern length distribution
    if stats['pattern_lengths']:
        avg_len = sum(stats['pattern_lengths']) / len(stats['pattern_lengths'])
        min_len = min(stats['pattern_lengths'])
        max_len = max(stats['pattern_lengths'])
        print("Trace 길이 통계:")
        print(f"  평균: {avg_len:.1f}")
        print(f"  최소: {min_len}")
        print(f"  최대: {max_len}")
        print()
    
    # Most common patterns
    print("가장 흔한 패턴 (Top 10):")
    for i, (pattern, count) in enumerate(stats['common_patterns'].most_common(10), 1):
        pattern_str = " → ".join(pattern)
        pct = count / stats['total_signatures'] * 100
        print(f"  {i:2d}. [{count:3d}회, {pct:4.1f}%] {pattern_str}")
    print()


def analyze_pattern_similarity(traces, sample_size=5):
    """Analyze pattern similarity"""
    from itertools import combinations
    
    print("=" * 60)
    print("패턴 유사도 분석 (샘플)")
    print("=" * 60)
    print()
    
    # Take sample
    sample_traces = traces[:min(sample_size, len(traces))]
    
    def edit_distance(s1, s2):
        """Calculate Levenshtein distance"""
        if len(s1) < len(s2):
            return edit_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                # Cost of insertion, deletion, substitution
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    print(f"샘플 trace {len(sample_traces)}개의 쌍별 유사도:")
    print()
    
    for (i, trace1), (j, trace2) in combinations(enumerate(sample_traces), 2):
        dist = edit_distance(trace1, trace2)
        max_len = max(len(trace1), len(trace2))
        similarity = 1 - (dist / max_len) if max_len > 0 else 1.0
        
        print(f"Trace {i+1} vs Trace {j+1}:")
        print(f"  Trace {i+1}: {' → '.join(trace1)}")
        print(f"  Trace {j+1}: {' → '.join(trace2)}")
        print(f"  Edit Distance: {dist}")
        print(f"  Similarity: {similarity:.2%}")
        print()


def find_patterns(traces, pattern):
    """Find traces matching a specific pattern"""
    matching_traces = []
    pattern_tuple = tuple(pattern)
    
    for trace in traces:
        # Exact match
        if tuple(trace) == pattern_tuple:
            matching_traces.append(('exact', trace))
            continue
        
        # Subsequence match
        trace_str = ','.join(trace)
        pattern_str = ','.join(pattern)
        if pattern_str in trace_str:
            matching_traces.append(('subsequence', trace))
    
    return matching_traces


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <signature-db-info-dir>")
        print()
        print("Example:")
        print(f"  {sys.argv[0]} ../../tracer/tracer/rank/signature-db-info")
        sys.exit(1)
    
    sig_db_info_dir = sys.argv[1]
    
    if not os.path.isdir(sig_db_info_dir):
        print(f"Error: Directory not found: {sig_db_info_dir}", file=sys.stderr)
        sys.exit(1)
    
    print(f"Analyzing: {sig_db_info_dir}")
    print()
    
    # Analyze
    stats, all_traces = analyze_directory(sig_db_info_dir)
    
    # Print results
    print_statistics(stats)
    
    # Similarity analysis (sample)
    if all_traces:
        analyze_pattern_similarity(all_traces, sample_size=5)
    
    # Pattern search examples
    print("=" * 60)
    print("특정 패턴 검색 예시")
    print("=" * 60)
    print()
    
    # Example: Find command injection patterns
    cmd_injection_pattern = ['INPUT', 'CMD_INJECTION']
    matches = find_patterns(all_traces, cmd_injection_pattern)
    print(f"패턴 [{' → '.join(cmd_injection_pattern)}]와 일치하는 trace:")
    print(f"  정확히 일치: {sum(1 for t, _ in matches if t == 'exact')}개")
    print(f"  부분 일치: {sum(1 for t, _ in matches if t == 'subsequence')}개")
    print()
    
    # Example: Find buffer overflow with allocation
    overflow_pattern = ['ALLOCATE', 'BUFFER_OVERFLOW']
    matches = find_patterns(all_traces, overflow_pattern)
    print(f"패턴 [{' → '.join(overflow_pattern)}]와 일치하는 trace:")
    print(f"  정확히 일치: {sum(1 for t, _ in matches if t == 'exact')}개")
    print(f"  부분 일치: {sum(1 for t, _ in matches if t == 'subsequence')}개")
    print()


if __name__ == '__main__':
    main()
