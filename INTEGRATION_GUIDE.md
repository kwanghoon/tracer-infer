# Tracer List 명령 통합 가이드

## 개요

`./tracer list --db signature-db/` 명령을 tracer 프로젝트에 통합하는 방법을 설명합니다.

## 구현된 파일들

1. **list_signatures.ml**: 핵심 로직 모듈
   - signature-db JSON 파일 읽기
   - abstract trace pattern 추출
   - signature-db-info에 저장

2. **tracer_list.ml**: 독립 실행형 진입점
   - 명령행 인자 파싱
   - list_signatures 모듈 호출

## tracer 프로젝트 통합 방법

### 방법 1: 독립 실행형 도구로 추가

#### 1.1. 파일 복사

```bash
# tracer-infer에서 tracer 프로젝트로 파일 복사
cp list_signatures.ml ../../tracer/tracer/rank/src/
```

#### 1.2. dune 파일 수정

`tracer/rank/src/dune` 파일에 새 실행 파일 추가:

```lisp
;; 기존 실행 파일
(executable
 (name main)
 (modules main rank feature infer location options viz)
 (libraries yojson unix str))

;; 새로운 list 명령 실행 파일
(executable
 (name list_signatures)
 (modules list_signatures)
 (libraries yojson unix))
```

#### 1.3. 빌드 및 실행

```bash
cd tracer/rank
dune build
./_build/default/list_signatures.exe --db ../signature-db
```

### 방법 2: 기존 main.ml에 서브커맨드로 통합

#### 2.1. list_signatures.ml을 모듈로 추가

```bash
cp list_signatures.ml ../../tracer/tracer/rank/src/
```

#### 2.2. options.ml 수정

```ocaml
(* options.ml에 추가 *)

(* ... 기존 코드 ... *)

(* 새로운 옵션: 명령 타입 *)
type command_type = Rank | List

let command = ref Rank

let opts =
  [
    (* 기존 옵션들 ... *)
    ( "-out_dir",
      Arg.Set_string out_dir,
      "Output directory (default: " ^ !out_dir ^ ")" );
    ( "-sig_dir",
      Arg.Set_string sig_dir,
      "Signature directory (default: " ^ !sig_dir ^ ")" );
    (* ... *)
  ]

(* 서브커맨드 파싱을 위한 함수 *)
let parse_command () =
  let args = Array.to_list Sys.argv in
  match args with
  | _ :: "list" :: rest ->
      command := List;
      (* list 명령의 나머지 인자 처리 *)
      Array.of_list ("program" :: rest)
  | _ :: "rank" :: rest ->
      command := Rank;
      Array.of_list ("program" :: rest)
  | _ ->
      (* 기본값: rank 명령 *)
      Sys.argv
```

#### 2.3. main.ml 수정

```ocaml
(* main.ml 수정 *)

module F = Format

(* ... 기존 함수들 ... *)

let main () =
  (* 서브커맨드 파싱 *)
  let argv = Options.parse_command () in
  
  match !Options.command with
  | Options.List ->
      (* list 명령 실행 *)
      Arg.parse_argv argv Options.opts (fun _ -> ()) Options.usage;
      
      F.printf "Reading signatures from: %s\n" !Options.sig_dir;
      List_signatures.run !Options.sig_dir
      
  | Options.Rank ->
      (* 기존 rank 명령 실행 *)
      Arg.parse_argv argv Options.opts
        (fun x -> Options.analysis_results_dir := x)
        Options.usage;
      
      F.printf "sig_dir: %s\n" !Options.sig_dir;
      init_out_dir ();
      
      match !Options.feat with
      | "manual1" -> run (module Feature.Manual1)
      | "manual2" -> run (module Feature.Manual2)
      (* ... *)
      | _ -> failwith "Unknown feature encoding"

let _ = main ()
```

#### 2.4. dune 파일 수정

```lisp
(executable
 (name main)
 (modules main rank feature infer location options viz list_signatures)
 (libraries yojson unix str))
```

#### 2.5. 빌드 및 실행

```bash
cd tracer/rank
dune build

# list 명령 실행
./tracer list --sig_dir ../signature-db

# 또는 기본 rank 명령 (기존 동작)
./tracer rank analysis-results-dir
```

## 사용 예시

### 예제 1: 전체 signature-db 처리

```bash
./tracer list --sig_dir ../signature-db
```

출력:
```
Reading signatures from: ../signature-db
Writing abstract patterns to: signature-db-info

Processing amanda-3.3.1...
Saved: signature-db-info/amanda-3.3.1/0.json
Saved: signature-db-info/amanda-3.3.1/1.json
...

Processing buffer-overflow1...
Saved: signature-db-info/buffer-overflow1/0.json
...

Done!
```

### 예제 2: 특정 디렉토리만 처리

```bash
./tracer list --sig_dir ../signature-db/amanda-3.3.1
```

## 생성되는 출력

### 입력 (signature-db/amanda-3.3.1/0.json)

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

### 출력 (signature-db-info/amanda-3.3.1/0.json)

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

## 추상화 패턴 설명

| 원본 Feature | Abstract Pattern | 설명 |
|-------------|------------------|------|
| Input | INPUT | 입력 소스 |
| Store | STORE | 메모리 저장 |
| BinOp (*, +, -, /) | MULTIPLY / CONVERT | 이항 연산 |
| UnOp | CONVERT | 단항 연산 |
| Cast | CONVERT | 타입 변환 |
| Call | CALL | 함수 호출 |
| LibraryCall | LIBRARY_CALL | 라이브러리 함수 호출 |
| IntOverflow | INT_OVERFLOW | 정수 오버플로우 |
| CmdInjection | CMD_INJECTION | 명령어 인젝션 |
| BufferOverflow | BUFFER_OVERFLOW | 버퍼 오버플로우 |
| FormatString | FORMAT_STRING | 포맷 스트링 |
| Allocate | ALLOCATE | 메모리 할당 |
| Free | FREE | 메모리 해제 |

## Abstract Pattern의 활용

### 1. 빠른 유사도 계산

```ocaml
(* 예: Edit Distance 계산 *)
let trace1 = [INPUT; CONVERT; MULTIPLY; ALLOCATE]
let trace2 = [INPUT; LIBRARY_CALL; MULTIPLY; ALLOCATE]

(* 상세 trace보다 빠르게 유사도 계산 가능 *)
let distance = edit_distance trace1 trace2  (* = 1 *)
```

### 2. 패턴 매칭

```ocaml
(* CmdInjection 패턴 검색 *)
let is_cmd_injection_pattern trace =
  List.exists (fun elem -> elem = CMD_INJECTION) trace
  && List.exists (fun elem -> elem = INPUT) trace

(* IntOverflow with multiplication 패턴 *)
let is_mult_overflow_pattern trace =
  has_subsequence [INPUT; MULTIPLY; INT_OVERFLOW] trace
```

### 3. 취약점 분류

```ocaml
(* signature-db-info를 읽어서 취약점 타입별로 분류 *)
let classify_by_sink traces =
  let sinks = [CMD_INJECTION; BUFFER_OVERFLOW; FORMAT_STRING] in
  List.filter (fun trace ->
    List.exists (fun sink -> List.mem sink trace) sinks
  ) traces
```

## 디버깅 및 문제 해결

### 컴파일 에러

```bash
# yojson 라이브러리 누락
opam install yojson

# ppx_deriving 누락 (deriving 사용 시)
opam install ppx_deriving ppx_deriving_yojson
```

### 실행 시 에러

```bash
# 디렉토리 권한 문제
chmod 755 signature-db
chmod 755 signature-db/*

# JSON 파싱 에러: 파일 형식 확인
cat signature-db/program-name/0.json | python -m json.tool
```

## 성능 최적화

현재 구현은 순차적으로 파일을 처리합니다. 대용량 데이터베이스의 경우 병렬 처리를 추가할 수 있습니다:

```ocaml
(* 병렬 처리 버전 - Parmap 라이브러리 사용 *)
let process_directory_parallel sig_db_dir output_dir =
  let subdirs = get_all_subdirs sig_db_dir in
  
  (* 병렬로 각 서브디렉토리 처리 *)
  Parmap.pariter ~ncores:4
    (fun subdir -> process_subdir subdir output_dir)
    (Parmap.L subdirs)
```

## 추가 기능 제안

### 1. 통계 정보 출력

```ocaml
(* 처리 후 통계 출력 *)
let print_statistics () =
  F.printf "\nStatistics:\n";
  F.printf "  Total programs: %d\n" !total_programs;
  F.printf "  Total signatures: %d\n" !total_signatures;
  F.printf "  By bug type:\n";
  List.iter (fun (bug_type, count) ->
    F.printf "    %s: %d\n" bug_type count
  ) !bug_type_counts
```

### 2. 필터링 옵션

```ocaml
(* 특정 bug_type만 처리 *)
let filter_by_bug_type = ref None

let opts = [
  (* ... *)
  ("-bug_type", Arg.String (fun s -> filter_by_bug_type := Some s),
   "Filter by bug type (e.g., API_MISUSE)");
]
```

### 3. 상세 출력 모드

```ocaml
let verbose = ref false

let opts = [
  (* ... *)
  ("-v", Arg.Set verbose, "Verbose output");
]

(* 상세 모드일 때만 출력 *)
if !verbose then
  F.printf "Processing file: %s\n" json_file
```

## 참고 자료

- `tracer-infer-analysis.md`: Infer/Quandary 아키텍처 상세 설명
- `TRACER_LIST_README.md`: tracer_list 도구 사용법
- `rank/src/infer.ml`: Signature 파싱 구현 참고
- `rank/src/feature.ml`: Feature 추상화 구현 참고
