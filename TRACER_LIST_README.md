# Tracer List - Signature Pattern Extraction Tool

This tool extracts abstract trace patterns from signature database JSON files for easier comparison and analysis.

## Overview

The `tracer list` command reads signature JSON files from `signature-db/` and generates abstract trace patterns saved to `signature-db-info/`.

## Features

- **Abstract Pattern Extraction**: Converts detailed trace elements to abstract patterns
- **Batch Processing**: Processes entire signature database directory tree
- **Structured Output**: Maintains directory structure in output

## Abstract Pattern Types

Trace elements are abstracted to the following types:

- `INPUT`: Input sources (e.g., user input, file read)
- `STORE`: Memory store operations
- `CONVERT`: Type conversions, binary/unary operations (BinOp, UnOp, Cast)
- `MULTIPLY`: Multiplication operations (potential for integer overflow)
- `PRUNE`: Conditional pruning
- `CALL`: Function calls
- `LIBRARY_CALL`: Library function calls
- `INT_OVERFLOW`: Integer overflow points
- `INT_UNDERFLOW`: Integer underflow points
- `FORMAT_STRING`: Format string operations
- `CMD_INJECTION`: Command injection sinks
- `BUFFER_OVERFLOW`: Buffer overflow sinks
- `ALLOCATE`: Memory allocation
- `FREE`: Memory deallocation
- `UNKNOWN`: Unknown or unsupported operations

## Building

```bash
# Using dune
dune build

# The executable will be at: _build/default/tracer_list.exe
```

## Usage

```bash
# Run the tool
./tracer_list.exe --db path/to/signature-db

# Example (from tracer project):
./tracer_list.exe --db ../tracer/signature-db
```

## Input Format

The tool expects signature database with the following structure:

```
signature-db/
├── program1/
│   ├── 0.json
│   ├── 1.json
│   └── ...
├── program2/
│   └── ...
└── ...
```

Each JSON file should contain:
- `bug_type`: Type of vulnerability
- `qualifier`: Additional classification
- `severity`: Severity level (ERROR, WARNING, etc.)
- `bug_trace`: Array of trace arrays, where each trace is a sequence of steps

Example JSON structure:
```json
{
  "bug_type": "API_MISUSE",
  "qualifier": "CmdInjection.",
  "severity": "ERROR",
  "bug_trace": [
    [
      {
        "feature": "[\"Input\",\"main\"]",
        ...
      },
      {
        "feature": "[\"CmdInjection\",\"execve\",[\"Var\"]]",
        ...
      }
    ]
  ]
}
```

## Output Format

The tool generates abstract patterns in `signature-db-info/` with the same directory structure:

```
signature-db-info/
├── program1/
│   ├── 0.json
│   ├── 1.json
│   └── ...
├── program2/
│   └── ...
└── ...
```

Each output JSON file contains:
```json
{
  "bug_type": "API_MISUSE",
  "qualifier": "CmdInjection.",
  "severity": "ERROR",
  "abstract_traces": [
    ["INPUT", "CMD_INJECTION"],
    ["INPUT", "LIBRARY_CALL", "CMD_INJECTION"]
  ]
}
```

## Example

Given a signature file `signature-db/amanda-3.3.1/0.json` with traces showing:
1. Input → CmdInjection
2. Input → LibraryCall → CmdInjection
3. Input → LibraryCall → LibraryCall → CmdInjection

The tool generates `signature-db-info/amanda-3.3.1/0.json`:
```json
{
  "bug_type": "API_MISUSE",
  "qualifier": "CmdInjection.",
  "severity": "ERROR",
  "abstract_traces": [
    ["INPUT", "CMD_INJECTION"],
    ["INPUT", "LIBRARY_CALL", "CMD_INJECTION"],
    ["INPUT", "LIBRARY_CALL", "LIBRARY_CALL", "CMD_INJECTION"]
  ]
}
```

## Implementation Details

### Pattern Abstraction

The tool applies the following abstractions:

1. **INPUT**: All input sources (Input feature)
2. **CONVERT**: All computation operations
   - BinOp (except multiplication)
   - UnOp
   - Cast
3. **MULTIPLY**: Multiplication operations (BinOp with "*")
4. **Vulnerability Types**: Preserved as-is
   - INT_OVERFLOW
   - INT_UNDERFLOW
   - CMD_INJECTION
   - FORMAT_STRING
   - BUFFER_OVERFLOW

### Why Abstract Patterns?

Abstract patterns enable:
- **Faster similarity comparison**: Fewer unique elements to compare
- **Better generalization**: Focus on semantic flow rather than implementation details
- **Easier pattern matching**: Identify common vulnerability patterns
- **Reduced noise**: Filter out irrelevant operations

### Trace Similarity Calculation

After extracting abstract patterns, you can use them for similarity calculation using:
- **Edit Distance**: Levenshtein distance between abstract trace sequences
- **LCS**: Longest Common Subsequence for partial matching
- **Weighted Similarity**: Cosine similarity with feature vectors

## Dependencies

- OCaml >= 4.08
- dune >= 2.9
- yojson
- unix (standard library)

## Related Documentation

See `tracer-infer-analysis.md` for detailed information about:
- Infer/Quandary architecture
- Taint analysis implementation
- Trace similarity algorithms
- Signature database structure
