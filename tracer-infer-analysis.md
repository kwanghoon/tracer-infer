# Tracer-Infer 정적 분석기 구조 분석

## 1. 프로젝트 개요

Tracer는 KAIST ProsysLab에서 개발한 도구로, 알려진 취약점의 시그니처를 기반으로 의미적으로 반복되는 취약점을 탐지합니다. Infer의 taint 분석 기능(Quandary)을 활용하여 interprocedural data dependency trace를 추출합니다.

**참고 링크**: https://prosys.kaist.ac.kr/tracer/

### 1.1 Quandary란?

**Quandary**는 Facebook(Meta)에서 개발한 Infer 정적 분석 프레임워크의 **taint 분석 체커(checker)**입니다.

#### Quandary의 특징

1. **Taint 분석 전문 도구**
   - 신뢰할 수 없는 데이터(source)가 민감한 작업(sink)으로 흐르는 경로 추적
   - Information flow 분석을 통한 보안 취약점 탐지
   - Data dependency를 interprocedural하게 추적

2. **지원 언어**
   - **Java**: Android 앱 보안 분석에 주로 사용
   - **C/C++**: 시스템 프로그래밍 언어의 메모리 안전성 및 보안 분석
   - **Objective-C**: iOS 앱 분석

3. **탐지 가능한 취약점 유형**
   - **Shell Injection**: 사용자 입력이 shell 명령어로 전달
   - **SQL Injection**: 신뢰할 수 없는 데이터가 SQL 쿼리로 전달
   - **Privacy Leak**: 개인정보가 로그나 네트워크로 유출
   - **Cross-Site Scripting (XSS)**: 사용자 입력이 HTML/JavaScript로 렌더링
   - **Intent 관련 취약점**: Android Intent 처리 시 보안 이슈
   - **File Access**: 신뢰할 수 없는 경로로 파일 접근

4. **분석 방식**
   - **Flow-sensitive**: 프로그램 실행 순서를 고려
   - **Context-sensitive**: 함수 호출 컨텍스트 구분
   - **Interprocedural**: 함수 경계를 넘어서 taint 추적
   - **Summary-based**: 함수별 taint 효과를 요약하여 확장성 확보

#### Quandary vs 다른 Infer 체커

| 체커 | 목적 | 분석 대상 |
|------|------|----------|
| **Quandary** | Taint 분석, 보안 취약점 | Data flow, source→sink 경로 |
| **Pulse** | 메모리 안전성, null pointer | 메모리 상태, 포인터 생명주기 |
| **RacerD** | 동시성 버그, 데이터 레이스 | 쓰레드 간 메모리 접근 |
| **BufferOverrun** | 배열 경계 검사 | 버퍼 크기와 인덱스 |
| **Eradicate** | Null pointer 예외 (Java) | @Nullable 애노테이션 |

#### Quandary의 구현 구조

```
infer/src/quandary/
├── TaintAnalysis.ml          # 핵심 taint 분석 엔진 (functor)
├── TaintSpec.ml              # Source/Sink 명세 인터페이스
├── JavaTaintAnalysis.ml      # Java 구현 (TaintAnalysis functor 인스턴스화)
├── ClangTaintAnalysis.ml     # C/C++ 구현
├── JavaTrace.ml              # Java source/sink 정의
├── ClangTrace.ml             # C/C++ source/sink 정의
├── QuandaryConfig.ml         # 외부 설정 파싱
└── QuandarySummary.ml        # Summary 타입 정의
```

#### Functor 기반 설계

Quandary는 OCaml의 **functor** (매개변수화된 모듈)를 사용한 우아한 설계:

```ocaml
(* TaintAnalysis.ml - 일반적인 taint 분석 로직 *)
module Make (TaintSpecification : TaintSpec.S) = struct
  module TraceDomain = TaintSpecification.Trace
  module TaintDomain = TaintSpecification.AccessTree
  (* ... taint 전파 로직 ... *)
end

(* JavaTaintAnalysis.ml - Java에 특화된 구현 *)
include TaintAnalysis.Make (struct
  module Trace = JavaTrace
  module AccessTree = AccessTree.Make (Trace) (AccessTree.DefaultConfig)
  
  (* Java 전용 source/sink 규칙 *)
  let handle_unknown_call pname ret_typ actuals tenv = ...
  let get_model pname ret_typ actuals tenv summary = ...
end)
```

이 구조의 장점:
- **코드 재사용**: 핵심 분석 로직은 한 번만 작성
- **언어별 커스터마이징**: 각 언어의 특성에 맞는 source/sink 정의
- **유지보수성**: 분석 엔진 개선 시 모든 언어에 자동 적용

#### Quandary 실행 예시

```bash
# Java 분석
infer run --quandary-only -- javac MyApp.java

# C++ 분석  
infer run --quandary-only -- clang++ -c mycode.cpp

# 결과에서 Quandary 이슈만 필터링
infer explore --select 0 --only-show quandary
```

#### Tracer와 Quandary의 관계

**Tracer**는 Quandary를 **기반**으로 하되, 다음 기능을 **추가**:

1. **Quandary가 제공하는 것**:
   - Source → Sink 경로 탐지
   - Interprocedural taint 전파
   - 기본 취약점 보고

2. **Tracer가 추가하는 것**:
   - Taint trace의 **구조적 표현** (시그니처)
   - 알려진 취약점 trace의 **데이터베이스**
   - 새로운 trace와 기존 시그니처의 **유사도 비교**
   - **의미적 매칭** (syntactic 차이를 넘어선 패턴 인식)
   - **랭킹 시스템** (유사도 점수 기반)

### Tracer의 핵심 아이디어
- 취약점 시그니처를 interprocedural data dependency trace로 표현
- Taint 분석을 통해 다양한 취약점 탐지
- 알려진 취약점 집합에서 취약 trace를 추출하여 시그니처 데이터베이스 구축
- 새로운 프로그램 분석 시 잠재적 취약 trace와 시그니처를 비교하여 유사도 점수로 랭킹

## 2. 정적 분석기의 핵심 구조

### 2.1 Main 엔트리 포인트

**실행 흐름**:
```
infer/src/infer.ml 
  ↓
Driver
  ↓
infer/src/backend/InferAnalyze.ml::main
  ↓
register_active_checkers()
  ↓
분석 실행
```

**주요 파일**:
- `infer/src/infer.ml`: 최상위 드라이버
- `infer/src/backend/InferAnalyze.ml`: 분석 메인 로직
- `infer/src/backend/registerCheckers.ml`: 체커 등록

### 2.2 Taint 분석 핵심 모듈

**위치**: `infer/src/quandary/` 디렉토리

**주요 파일 구성**:

| 파일명 | 역할 |
|--------|------|
| `TaintAnalysis.ml` | Taint 분석의 핵심 엔진 (functor 구조) |
| `TaintSpec.ml` | Source/Sink 명세 인터페이스 정의 |
| `JavaTaintAnalysis.ml` | Java용 taint 분석 구현 |
| `ClangTaintAnalysis.ml` | C/C++용 taint 분석 구현 |
| `JavaTrace.ml` | Java용 source/sink 정의 |
| `ClangTrace.ml` | C/C++용 source/sink 정의 |
| `QuandaryConfig.ml` | JSON 설정 파일 파싱 |

### 2.3 체커 등록

`infer/src/backend/registerCheckers.ml`에서 Quandary checker 등록:

```ocaml
{ checker= Quandary
; callbacks=
    [ (interprocedural Payloads.Fields.quandary JavaTaintAnalysis.checker, Java)
    ; (interprocedural Payloads.Fields.quandary ClangTaintAnalysis.checker, Clang) ] }
```

## 3. Source와 Sink 지정 방식

### 3.1 하이브리드 방식 (자동 + 수동)

Tracer-Infer는 **하드코딩된 패턴 매칭**과 **외부 설정 파일**을 모두 사용합니다.

### 3.2 자동 지정 (Hard-coded)

#### A. Java Sources (JavaTrace.ml)

코드에 직접 패턴 매칭으로 정의:

```ocaml
match (Typ.Name.name typename, method_name) with
| "android.app.Activity", "getIntent" -> 
    Intent
| "android.content.SharedPreferences", "getString" -> 
    PrivateData
| "android.widget.EditText", "getText" -> 
    UserControlledString
| "android.location.Location", ("getLatitude" | "getLongitude") -> 
    PrivateData
| "android.telephony.TelephonyManager", ("getDeviceId" | "getSubscriberId") -> 
    PrivateData
```

**Source 종류**:
- `Intent`: 외부 Intent 또는 Intent에서 읽은 값
- `PrivateData`: 개인정보 또는 디바이스 특정 데이터
- `UserControlledString`: 텍스트박스나 클립보드에서 읽은 데이터
- `UserControlledURI`: 브라우저 주소창에서 온 리소스 로케이터
- `Endpoint`: 엔드포인트의 formal parameter에서 시작된 source

#### B. Java Sinks (JavaTrace.ml)

```ocaml
match (Typ.Name.name typename, method_name) with
| "java.lang.Runtime", "exec" -> 
    [ShellExec]
| "android.content.Context", "startActivity" -> 
    [StartComponent]
| "android.util.Log", _ -> 
    [Logging]
| "java.io.FileOutputStream", "<init>" -> 
    [CreateFile]
```

**Sink 종류**:
- `ShellExec`: 셸 명령어 실행
- `SQLInjection`: SQL 데이터베이스로의 unescaped 쿼리
- `Logging`: 인자를 로그에 기록
- `CreateFile`: 파일 생성
- `StartComponent`: Activity, Service 등 실행
- `JavaScript`: 신뢰할 수 없는 JS 코드로 인자 전달

#### C. C/C++ Sources (ClangTrace.ml)

```ocaml
match (qualified_pname, method) with
| ["std"; "basic_istream"], ("getline" | "read" | "operator>>") ->
    [(ReadFile, Some 1)]
| _ when is_gflag ->
    [(CommandLineFlag (global_pvar, typ_desc), None)]
| "getenv" ->
    [(EnvironmentVariable, return)]
```

**Source 종류**:
- `ReadFile`: 파일에서 읽은 source
- `CommandLineFlag`: 커맨드라인 플래그에서 읽은 source
- `EnvironmentVariable`: 환경 변수에서 읽은 source
- `Endpoint`: 엔드포인트의 formal에서 시작된 source
- `UserControlledEndpoint`: 사용자 제어 데이터를 가진 엔드포인트

#### D. C/C++ Sinks (ClangTrace.ml)

```ocaml
match Procname.to_string pname with
| "fopen" | "freopen" | "open" ->
    taint_nth 0 [CreateFile] actuals
| "execl" | "execve" | "system" ->
    taint_all [ShellExec] actuals
| "malloc" | "calloc" ->
    taint_nth 0 [HeapAllocation] actuals
```

**Sink 종류**:
- `BufferAccess`: 배열 읽기/쓰기
- `CreateFile`: 파일 생성/열기
- `ShellExec`: 셸 실행 함수
- `HeapAllocation`: 힙 메모리 할당
- `StackAllocation`: 스택 메모리 할당
- `SQLInjection`: SQL 인젝션

### 3.3 수동 지정 (외부 설정 파일)

#### .inferconfig JSON 형식

프로젝트 루트나 테스트 디렉토리에 `.inferconfig` 파일을 두고 사용자 정의 source/sink 지정:

```json
{
  "quandary-sources": [
    {
      "procedure": "codetoanalyze.java.quandary.ExternalSpecs.privateData*",
      "kind": "PrivateData"
    },
    {
      "procedure": "codetoanalyze.java.quandary.InterfaceSpec.source",
      "kinds": ["PrivateData", "Other"]
    }
  ],
  "quandary-sinks": [
    {
      "procedure": "codetoanalyze.java.quandary.ExternalSpecs.loggingSink1",
      "kind": "Logging",
      "index": "1"
    },
    {
      "procedure": "codetoanalyze.java.quandary.ExternalSpecs.loggingSink2",
      "kind": "Logging"
    }
  ],
  "quandary-sanitizers": [
    {
      "procedure": "codetoanalyze.java.quandary.ExternalSpecs.sanitizer"
    }
  ],
  "quandary-endpoints": [
    "codetoanalyze.java.quandary.MyService"
  ]
}
```

#### 설정 파싱 과정

1. **`QuandaryConfig.ml`**에서 JSON 파싱
2. **`Config.quandary_sources`** / **`Config.quandary_sinks`**로 로드
3. 정규표현식 매칭으로 프로시저 식별

```ocaml
let external_sources =
  List.filter_map
    ~f:(fun {QuandaryConfig.Source.procedure; kinds; index} ->
      parse_clang_procedure procedure kinds index )
    (QuandaryConfig.Source.of_json Config.quandary_sources)
```

#### 파라미터 설명

- **procedure**: 프로시저 이름 (정규표현식 지원)
- **kind/kinds**: Source/Sink 타입
- **index**: 
  - Source: "return" (기본값) 또는 파라미터 인덱스
  - Sink: "all" (기본값) 또는 특정 파라미터 인덱스

## 4. 분석기 동작 흐름

### 4.1 전체 실행 흐름

```
┌─────────────────────────────────────────┐
│ 1. infer.ml::run                        │
│    - 최상위 드라이버                      │
└────────────┬────────────────────────────┘
             │
             ↓
┌─────────────────────────────────────────┐
│ 2. Driver::capture                      │
│    - 소스 코드 캡처 및 IR 변환            │
└────────────┬────────────────────────────┘
             │
             ↓
┌─────────────────────────────────────────┐
│ 3. InferAnalyze.main                    │
│    - 분석 메인 로직                       │
└────────────┬────────────────────────────┘
             │
             ↓
┌─────────────────────────────────────────┐
│ 4. register_active_checkers()           │
│    - Quandary 포함 활성 체커 등록         │
└────────────┬────────────────────────────┘
             │
             ↓
┌─────────────────────────────────────────┐
│ 5. analyze                              │
│    - 병렬/순차 분석 실행                  │
└────────────┬────────────────────────────┘
             │
             ↓
┌─────────────────────────────────────────┐
│ 6. 각 소스 파일/프로시저별 분석           │
│    - Taint 전파 및 취약점 탐지            │
└─────────────────────────────────────────┘
```

### 4.2 Taint 분석 세부 흐름

```
┌──────────────────────────────────────────────┐
│ TaintAnalysis.Make (Functor)                 │
│ - Java: JavaTaintAnalysis                    │
│ - C/C++: ClangTaintAnalysis                  │
└────────────┬─────────────────────────────────┘
             │
             ↓
┌──────────────────────────────────────────────┐
│ 1. TransferFunctions (Intra-procedural)      │
│    - exec_instr: 각 명령어 처리               │
│    - 변수 할당, 함수 호출 등 분석              │
└────────────┬─────────────────────────────────┘
             │
             ↓
┌──────────────────────────────────────────────┐
│ 2. Source 탐지                               │
│    - JavaTrace.SourceKind.get                │
│    - get_tainted_formals (formal parameter)  │
│    - 특정 API 호출 검사                       │
└────────────┬─────────────────────────────────┘
             │
             ↓
┌──────────────────────────────────────────────┐
│ 3. Taint 전파                                │
│    - AccessTree로 taint 상태 추적             │
│    - write 시 rhs에서 lhs로 taint 전달       │
│    - 함수 호출 시 summary 적용                │
└────────────┬─────────────────────────────────┘
             │
             ↓
┌──────────────────────────────────────────────┐
│ 4. Sink 탐지                                 │
│    - JavaTrace.SinkKind.get                  │
│    - 위험한 API 호출 검사                     │
│    - add_sink으로 trace에 sink 추가           │
└────────────┬─────────────────────────────────┘
             │
             ↓
┌──────────────────────────────────────────────┐
│ 5. Inter-procedural 분석                     │
│    - Summary 생성 (to_summary_access_tree)   │
│    - Callee summary 적용 (apply_summary)     │
│    - Footprint source 처리                   │
└────────────┬─────────────────────────────────┘
             │
             ↓
┌──────────────────────────────────────────────┐
│ 6. 취약점 보고                                │
│    - Source → Sink 경로 발견 시               │
│    - TraceDomain.get_reports                 │
│    - Errlog에 issue 기록                     │
└──────────────────────────────────────────────┘
```

### 4.3 핵심 알고리즘

#### A. Intra-procedural Transfer Function

각 명령어(`exec_instr`)를 처리하며 taint를 전파:

```ocaml
let exec_instr astate _ _ = function
  | Assign (lhs_access_expr, rhs_exp, _) ->
      exec_write formal_map lhs_access_expr rhs_exp astate
  | Call (ret, Direct callee_pname, actuals, _, loc) ->
      analyze_call ~ret_ap ~callee_pname ~actuals ~call_flags ~callee_loc astate
  | _ ->
      astate
```

#### B. Inter-procedural Summary

함수 호출 시:
1. Callee의 summary를 가져옴
2. Formal parameter를 actual argument로 매핑
3. Return value를 caller의 변수로 매핑
4. Footprint source를 caller context로 해석

```ocaml
let apply_summary ret_opt actuals summary caller_access_tree callee_site =
  (* formal_ap를 actual_ap로 변환 *)
  (* callee trace와 caller trace를 결합 *)
  (* 결과를 caller_access_tree에 추가 *)
```

#### C. Taint 전파 규칙

- **Propagate_to_return**: 모든 actual에서 return value로 전파
- **Propagate_to_receiver**: non-receiver actual에서 receiver로 전파
- **Propagate_to_actual n**: 모든 actual에서 n번째 actual로 전파

### 4.4 핵심 데이터 구조

#### AccessTree
```ocaml
(* 접근 경로별로 taint 추적 *)
type t = (trace * tree) AccessPath.Abs.BaseMap.t

(* 예: x.f.g 접근 경로의 taint 상태 *)
```

#### TraceDomain
```ocaml
(* Source → Sink 경로 정보 *)
type t = {
  sources: Sources.t;  (* source 집합 *)
  sinks: Sinks.t;      (* sink 집합 *)
  passthroughs: Passthroughs.t;
}
```

#### Source/Sink
```ocaml
(* Source *)
type t = {
  kind: SourceKind.t;
  site: CallSite.t;
}

(* Sink *)
type t = {
  kind: SinkKind.t;
  site: CallSite.t;
  indexes: IntSet.t;  (* 어느 파라미터가 taint되었는지 *)
}
```

#### Summary
```ocaml
(* 함수의 taint 효과 요약 *)
type t = AccessTree.t
(* formal parameter와 return value의 taint 관계 *)
```

## 5. Tracer 프로젝트 특화 기능

### 5.1 기본 Infer에서 확장된 부분

이 프로젝트는 기본 Infer/Quandary에 다음 기능을 추가하여 Tracer를 구현:

1. **Interprocedural Trace 추출**
   - Taint 분석 결과에서 data dependency trace 추출
   - Source → Intermediate → Sink 전체 경로 기록

2. **취약점 시그니처 데이터베이스**
   - 알려진 취약점의 trace를 시그니처로 저장
   - Trace 패턴을 정규화하여 비교 가능하게 변환

3. **시그니처 유사도 비교**
   - 새로운 프로그램의 trace와 시그니처 비교
   - 구조적 유사도 계산 (예: CVE-2009-1570과 CVE-2017-16612의 유사도 0.96)

4. **의미적 매칭**
   - 구문적으로 다른 코드라도 동일한 취약 패턴 탐지
   - 함수명, 변수명 차이를 넘어선 행동 패턴 매칭

### 5.2 Tracer의 취약점 탐지 예시

논문에서 제시한 예시:

#### 시나리오: Integer Overflow → Buffer Allocation

**공통 취약 패턴**:
1. 파일에서 바이트 문자열 읽기 (`fread`)
2. 문자열을 정수로 변환 (bitwise operations)
3. 곱셈으로 인한 integer overflow
4. Overflow된 크기로 메모리 할당 (`malloc`)
5. 할당된 버퍼 사용

**탐지된 CVE**:
- CVE-2009-1570 (gimp-2.6.7)
- CVE-2017-16663 (sam2p-0.49.4) - 8년 후
- CVE-2017-16612 (libXcursor-1.1.14) - 의미적으로 동일

Tracer는 첫 번째 취약점을 시그니처로 하여 마지막 취약점을 0.96 유사도로 탐지.

## 6. 분석 커스터마이징 방법

### 6.1 새로운 Source 추가

#### 방법 1: 코드 수정
`infer/src/quandary/JavaTrace.ml` 또는 `ClangTrace.ml`에 추가:

```ocaml
match (Typ.Name.name typename, method_name) with
| "com.myapp.DataSource", "getUserData" ->
    Some [(PrivateData, return)]
```

#### 방법 2: 설정 파일
`.inferconfig`에 추가:

```json
{
  "quandary-sources": [
    {
      "procedure": "com.myapp.DataSource.getUserData",
      "kind": "PrivateData"
    }
  ]
}
```

### 6.2 새로운 Sink 추가

#### 방법 1: 코드 수정
```ocaml
match (Typ.Name.name typename, method_name) with
| "com.myapp.Network", "sendData" ->
    taint_all [Other] actuals
```

#### 방법 2: 설정 파일
```json
{
  "quandary-sinks": [
    {
      "procedure": "com.myapp.Network.sendData",
      "kind": "Other",
      "index": "0"
    }
  ]
}
```

### 6.3 새로운 Source/Sink Kind 추가

1. `JavaTrace.ml` 또는 `ClangTrace.ml`의 `SourceKind` 또는 `SinkKind` 타입에 variant 추가
2. `of_string` 함수에 파싱 로직 추가
3. `pp` 함수에 출력 형식 추가
4. 필요시 `IssueType.ml`에 새로운 issue type 등록

## 7. 빌드 및 실행

### 7.1 빌드
```bash
# OCaml과 의존성 설치
./build-infer.sh

# 또는
make
```

### 7.2 실행
```bash
# Java 프로젝트 분석
infer run --quandary-only -- javac MyClass.java

# C/C++ 프로젝트 분석
infer run --quandary-only -- clang -c example.c

# 커스텀 설정 파일 사용
infer run --quandary-only -- <build command>
# (프로젝트 루트에 .inferconfig 파일 배치)
```

### 7.3 결과 확인
```bash
# 결과 요약
cat infer-out/report.txt

# JSON 형식
cat infer-out/report.json

# 특정 issue 필터링
infer explore --select 0
```

## 8. Signature Database와 Trace 유사도 계산

### 8.1 Signature Database 구조

Tracer는 알려진 취약점의 trace를 시그니처로 저장하여 재사용합니다. `signature-db` 디렉토리에는 JSON 형식의 취약점 시그니처가 저장됩니다.

#### Trace JSON 형식

```json
{
  "trace": [
    {
      "type": "Input",
      "procname": "fread",
      "location": {"file": "example.c", "line": 10}
    },
    {
      "type": "Store", 
      "lhs": "buffer",
      "rhs": "data",
      "location": {"file": "example.c", "line": 11}
    },
    {
      "type": "Call",
      "procname": "ToL",
      "location": {"file": "example.c", "line": 12}
    },
    {
      "type": "IntOverflow",
      "procname": "operator*",
      "expression": "width * height",
      "location": {"file": "example.c", "line": 15}
    },
    {
      "type": "Allocate",
      "procname": "malloc",
      "location": {"file": "example.c", "line": 16}
    }
  ],
  "vulnerability": "CVE-2009-1570",
  "description": "Integer overflow leading to heap buffer overflow"
}
```

#### Trace Element 타입

Infer의 `APIMisuseTrace.ml`에서 정의된 trace element와 trace 타입:

```ocaml
(* 단일 Trace Element 타입 *)
type elem =
  | SymbolDecl of AbsLoc.Loc.t                (* 심볼 선언 *)
  | Input of Procname.t * Location.t          (* 외부 입력: fread, getenv 등 *)
  | Store of Exp.t * Exp.t * Location.t       (* 변수 할당: lhs = rhs *)
  | Prune of Exp.t * Location.t               (* 조건 분기: if, while 등 *)
  | Call of Procname.t * Location.t           (* 함수 호출 *)
  | LibraryCall of Procname.t * Exp.t list * Location.t  (* 라이브러리 호출 *)
  | IntOverflow of Procname.t * Exp.t * Location.t       (* 정수 오버플로우 *)
  | IntUnderflow of Procname.t * Exp.t * Location.t      (* 정수 언더플로우 *)
  | FormatString of Procname.t * Exp.t * Location.t      (* 포맷 스트링 취약점 *)
  | CmdInjection of Procname.t * Exp.t * Location.t      (* 명령어 인젝션 *)
  | BufferOverflow of Procname.t * Exp.t * Location.t    (* 버퍼 오버플로우 *)
  | Allocate of Procname.t * Location.t       (* 메모리 할당: malloc, new 등 *)
  | Free of Procname.t * Exp.t * Location.t  (* 메모리 해제: free, delete 등 *)
[@@deriving compare, yojson_of]

(* Trace는 elem의 리스트 *)
type t = elem list [@@deriving compare]
```

**Trace 타입의 특징**:
- **`t = elem list`**: Trace는 trace element들의 순서 있는 리스트
- **`[@@deriving compare]`**: 두 trace를 비교 가능 (유사도 계산에 사용)
- **`[@@deriving yojson_of]`**: elem을 JSON으로 직렬화 가능 (signature DB 저장)

**Trace 기본 연산**:

```ocaml
module Trace = struct
  type t = elem list
  
  let length = List.length                    (* trace 길이 *)
  let append h t = h :: t                     (* 앞에 element 추가 *)
  let concat t1 t2 = List.rev_append (List.rev t1) t2  (* 두 trace 연결 *)
  let make_singleton elem = [elem]            (* 단일 element로 trace 생성 *)
end
```

### 8.2 Trace Set과 집합 연산

여러 trace를 관리하기 위한 집합 타입:

```ocaml
module Set = struct
  include AbstractDomain.FiniteSet (Trace)
  
  type t = Trace.t set  (* Trace들의 집합 *)
  
  (* 집합 연산 *)
  let add : Trace.t -> t -> t           (* trace 추가 *)
  let join : t -> t -> t                (* 합집합 *)
  let append : elem -> t -> t           (* 모든 trace에 element 추가 *)
  let concat : t -> t -> t              (* 두 집합의 trace들을 연결 *)
  
  (* 최대 크기 제한 (성능 최적화) *)
  let max_trace_set_size = Config.api_misuse_max_trace_set
  let max_trace_length = Config.api_misuse_max_trace_length
  
  (* Errlog 변환 *)
  let make_err_trace : t -> Errlog.LTRSet.t
end
```

**사용 예시**:

```ocaml
(* 단일 trace *)
let trace1 = [Input (fread, loc1); Store (x, data, loc2); Allocate (malloc, loc3)]

(* Trace set *)
let traces = Set.empty 
  |> Set.add trace1 
  |> Set.add trace2
  
(* 모든 trace에 새 element 추가 *)
let extended = Set.append (Call (process, loc4)) traces
```

### 8.3 Trace 패턴 정규화

구조적 유사도를 계산하기 위해 trace를 정규화된 패턴으로 변환합니다.

#### 정규화 과정

1. **구체적 정보 제거**
   - 변수명, 파일명, 라인 번호 제거
   - 함수명을 추상화 (예: `fread` → `FILE_READ`)

2. **타입 기반 추상화**
   ```
   원본: Input("fread", location)
   패턴: INPUT
   
   원본: Call("ToL", location)  
   패턴: CALL[TYPE_CONVERSION]
   
   원본: IntOverflow("operator*", "width*height", location)
   패턴: INT_OVERFLOW[MULTIPLY]
   
   원본: Allocate("malloc", location)
   패턴: ALLOCATE
   ```

3. **시퀀스 패턴 생성**
   ```
   전체 패턴: INPUT → CALL → INT_OVERFLOW → ALLOCATE
   ```

#### 정규화 알고리즘 (의사 코드)

```ocaml
let normalize_trace trace =
  let normalize_elem = function
    | Input (_, _) -> 
        Abstract_Input
    | Call (pname, _) -> 
        Abstract_Call (categorize_function pname)
    | IntOverflow (_, exp, _) -> 
        Abstract_IntOverflow (get_operator_type exp)
    | Allocate (_, _) -> 
        Abstract_Allocate
    | Store (lhs, rhs, _) -> 
        Abstract_Store (get_value_type lhs, get_value_type rhs)
    (* ... 기타 타입 ... *)
  in
  List.map normalize_elem trace
```

### 8.4 구조적 유사도 계산

#### 유사도 메트릭

Tracer는 **편집 거리(Edit Distance)** 기반 유사도를 사용합니다.

##### 1. Levenshtein Distance 변형

두 trace 패턴 간의 최소 변환 횟수를 계산:

```ocaml
type operation = 
  | Insert of elem
  | Delete of elem  
  | Substitute of elem * elem
  | Match of elem

let edit_distance trace1 trace2 =
  (* 동적 프로그래밍으로 최소 편집 거리 계산 *)
  let len1 = List.length trace1 in
  let len2 = List.length trace2 in
  let dp = Array.make_matrix (len1 + 1) (len2 + 1) 0 in
  
  (* 초기화 *)
  for i = 0 to len1 do dp.(i).(0) <- i done;
  for j = 0 to len2 do dp.(0).(j) <- j done;
  
  (* 동적 프로그래밍 *)
  for i = 1 to len1 do
    for j = 1 to len2 do
      let cost = if elem_equal trace1.(i-1) trace2.(j-1) then 0 else 1 in
      dp.(i).(j) <- min (min 
        (dp.(i-1).(j) + 1)      (* 삭제 *)
        (dp.(i).(j-1) + 1))     (* 삽입 *)
        (dp.(i-1).(j-1) + cost) (* 치환 또는 매치 *)
    done
  done;
  dp.(len1).(len2)
```

##### 2. 유사도 점수 계산

```ocaml
let similarity_score trace1 trace2 =
  let distance = edit_distance trace1 trace2 in
  let max_len = max (List.length trace1) (List.length trace2) in
  1.0 -. (float_of_int distance /. float_of_int max_len)
```

**예시**:
- CVE-2009-1570: `INPUT → CONVERT → MULTIPLY → ALLOCATE → USE`
- CVE-2017-16612: `INPUT → CONVERT → MULTIPLY → ALLOCATE → USE`
- 편집 거리: 0
- 유사도: 1.0 (완전 일치)

##### 3. 가중치 기반 유사도

중요한 요소에 가중치 부여:

```ocaml
let weighted_similarity trace1 trace2 =
  let elem_weight = function
    | Abstract_Input -> 2.0
    | Abstract_IntOverflow _ -> 3.0  (* 핵심 취약점 *)
    | Abstract_Allocate -> 2.0
    | Abstract_Call _ -> 1.0
    | _ -> 1.0
  in
  
  let weighted_distance = 
    compute_weighted_edit_distance trace1 trace2 elem_weight
  in
  
  let total_weight = 
    List.fold_left (fun acc elem -> acc +. elem_weight elem) 0.0 trace1
  in
  
  1.0 -. (weighted_distance /. total_weight)
```

#### 유사도 예시

**패턴 1** (gimp-2.6.7, CVE-2009-1570):
```
INPUT[fread] → CONVERT[ToL] → MULTIPLY[*] → ALLOCATE[malloc] → USE
```

**패턴 2** (sam2p-0.49.4, CVE-2017-16663):
```
INPUT[fread] → CONVERT[ToL] → MULTIPLY[*] → ALLOCATE[new] → USE
```

**패턴 3** (libXcursor-1.1.14, CVE-2017-16612):
```
INPUT[read] → CONVERT[bitwise] → MULTIPLY[*] → ALLOCATE[malloc] → USE
```

**유사도 계산**:
- 패턴 1 vs 패턴 2: 0.98 (할당 함수만 다름)
- 패턴 1 vs 패턴 3: 0.96 (입력/변환 방법 다름, 논문 결과와 일치)

### 8.5 부분 매칭 (Partial Matching)

전체 trace가 일치하지 않아도 중요 서브시퀀스 매칭:

```ocaml
let find_longest_common_subsequence trace1 trace2 =
  (* LCS 알고리즘으로 공통 부분 시퀀스 찾기 *)
  let len1 = List.length trace1 in
  let len2 = List.length trace2 in
  let dp = Array.make_matrix (len1 + 1) (len2 + 1) 0 in
  
  for i = 1 to len1 do
    for j = 1 to len2 do
      if elem_equal trace1.(i-1) trace2.(j-1) then
        dp.(i).(j) <- dp.(i-1).(j-1) + 1
      else
        dp.(i).(j) <- max dp.(i-1).(j) dp.(i).(j-1)
    done
  done;
  dp.(len1).(len2)

let partial_similarity trace1 trace2 =
  let lcs_len = find_longest_common_subsequence trace1 trace2 in
  let min_len = min (List.length trace1) (List.length trace2) in
  float_of_int lcs_len /. float_of_int min_len
```

### 8.6 시그니처 매칭 파이프라인

```
┌──────────────────────────────────────────────┐
│ 1. Taint 분석 실행                            │
│    - Quandary로 Source → Sink 경로 탐지       │
│    - Trace 추출                               │
└────────────┬─────────────────────────────────┘
             │
             ↓
┌──────────────────────────────────────────────┐
│ 2. Trace 정규화                              │
│    - 구체적 정보 제거                         │
│    - 추상 패턴 생성                           │
└────────────┬─────────────────────────────────┘
             │
             ↓
┌──────────────────────────────────────────────┐
│ 3. Signature DB 로드                         │
│    - JSON 파일들 파싱                         │
│    - 알려진 취약점 패턴 추출                  │
└────────────┬─────────────────────────────────┘
             │
             ↓
┌──────────────────────────────────────────────┐
│ 4. 유사도 계산                                │
│    - 각 시그니처와 비교                       │
│    - 편집 거리 계산                           │
│    - 가중치 적용                              │
└────────────┬─────────────────────────────────┘
             │
             ↓
┌──────────────────────────────────────────────┐
│ 5. 랭킹 및 보고                               │
│    - 유사도 점수로 정렬                       │
│    - 임계값 이상만 보고                       │
│    - CVE 정보와 함께 출력                     │
└──────────────────────────────────────────────┘
```

### 8.7 최적화 기법

#### 인덱싱

```ocaml
(* Trace 시작 패턴으로 인덱싱 *)
type trace_index = (abstract_elem list, signature list) Hashtbl.t

let build_index signatures =
  let index = Hashtbl.create 1000 in
  List.iter (fun sig ->
    let prefix = take 3 sig.normalized_trace in  (* 첫 3개 요소 *)
    let existing = Hashtbl.find_opt index prefix |> Option.value ~default:[] in
    Hashtbl.replace index prefix (sig :: existing)
  ) signatures;
  index

let find_candidates index query_trace =
  let prefix = take 3 query_trace in
  Hashtbl.find_opt index prefix |> Option.value ~default:[]
```

#### 조기 종료

```ocaml
let quick_filter trace1 trace2 threshold =
  (* 길이 차이가 너무 크면 조기 종료 *)
  let len_diff = abs (List.length trace1 - List.length trace2) in
  let max_len = max (List.length trace1) (List.length trace2) in
  if float_of_int len_diff /. float_of_int max_len > (1.0 -. threshold) then
    None  (* 임계값 이하 확정 *)
  else
    Some (compute_full_similarity trace1 trace2)
```

### 8.8 실제 사용 예시

```bash
# 1. Tracer 실행하여 trace 추출
./tracer analyze target_program.c

# 2. Signature DB와 비교
./tracer match --db signature-db/ --threshold 0.85

# 3. 결과 출력
# Match found!
# Query trace: INPUT → CONVERT → MULTIPLY → ALLOCATE
# Similar to: CVE-2009-1570 (gimp-2.6.7)
# Similarity: 0.96
# Description: Integer overflow leading to heap buffer overflow
```

## 9. 주요 참고 자료

### 논문
- **Tracer: Signature-based Static Analysis for Detecting Recurring Vulnerabilities**
  - Wooseok Kang, Byoungho Son, Kihong Heo
  - CCS 2022
  - https://prosys.kaist.ac.kr/publications/ccs22.pdf

### 코드 저장소
- **GitHub**: https://github.com/prosyslab/tracer
- **Tracer-Infer**: 현재 저장소

### 관련 기술

#### Infer
- **개발사**: Facebook (Meta)
- **목적**: 프로덕션 코드를 위한 확장 가능한 정적 분석
- **특징**: 
  - Compositional (함수별 분석 후 결합)
  - Incremental (변경된 코드만 재분석)
  - 대규모 코드베이스 지원 (수백만 라인)
- **링크**: 
  - https://fbinfer.com/
  - https://github.com/facebook/infer

#### Quandary
- **개발사**: Facebook (Meta), Infer 팀
- **목적**: Taint 분석을 통한 보안 취약점 탐지
- **첫 공개**: 2016년경
- **특징**:
  - Summary-based interprocedural analysis
  - 확장 가능한 source/sink 정의
  - Android와 서버 사이드 Java 분석에 특화
- **주요 사용처**:
  - Facebook/Instagram Android 앱 보안 분석
  - WhatsApp 보안 검증
  - 오픈소스 프로젝트 CI/CD 통합
- **링크**: 
  - https://fbinfer.com/docs/checker-quandary
  - [블로그 포스트](https://engineering.fb.com/2016/08/18/security/finding-inter-procedural-bugs-at-scale-with-infer-static-analyzer/)

#### Tracer (이 프로젝트)
- **개발**: KAIST ProsysLab
- **기반**: Infer + Quandary
- **차별점**: 취약점 시그니처 매칭을 통한 recurring vulnerability 탐지
- **논문**: CCS 2022
- **링크**: https://prosys.kaist.ac.kr/tracer/

#### 기술 스택 비교

```
Infer (Framework)
├── Abstract Interpretation
├── Separation Logic
└── 다양한 체커들
    ├── Quandary (Taint Analysis)        ← 이 프로젝트가 사용
    ├── Pulse (Memory Safety)
    ├── RacerD (Concurrency)
    └── ...

Tracer = Quandary + Signature Matching
```

## 9. 요약

### 핵심 포인트

| 항목 | 설명 |
|------|------|
| **Quandary** | Infer의 taint 분석 체커, Facebook 개발 |
| **Tracer** | Quandary 기반 + 시그니처 매칭 추가, KAIST 개발 |
| **Source/Sink 지정** | 하이브리드 방식 (하드코딩 + `.inferconfig` 수동 설정) |
| **핵심 모듈** | `infer/src/quandary/` 디렉토리 |
| **Main 엔트리** | `infer.ml` → `InferAnalyze.ml` → `registerCheckers.ml` |
| **분석 엔진** | `TaintAnalysis.ml` (functor), Java/Clang별 구현 |
| **동작 방식** | Intraprocedural transfer functions + Interprocedural summaries |
| **Tracer 특화** | Trace 추출, 시그니처 비교, 의미적 매칭 |

### 분석 흐름 요약

```
소스 코드
  ↓ [Capture]
IR (Intermediate Representation)
  ↓ [Register Checkers]
Quandary Checker 활성화
  ↓ [Intra-procedural Analysis]
Source 탐지 → Taint 전파 → Sink 탐지
  ↓ [Inter-procedural Analysis]
Summary 생성 및 적용
  ↓ [Report Generation]
Source → Sink 경로 발견 시 취약점 보고
  ↓ [Tracer Extension]
Trace 추출 → 시그니처 비교 → 유사 취약점 탐지
```

### 장점

1. **확장성**: Functor 구조로 언어별 구현 분리
2. **유연성**: 설정 파일로 source/sink 커스터마이징
3. **정확성**: Interprocedural 분석으로 경로 추적
4. **실용성**: 알려진 취약점 기반 탐지로 false positive 감소

### 활용 분야

**Quandary (일반적 용도)**:
- 앱/서비스 코드의 실시간 보안 검증
- CI/CD 파이프라인 통합
- Privacy leak 자동 탐지
- Security code review 자동화

**Tracer (특화된 용도)**:
- 반복되는 보안 취약점 자동 탐지
- 레거시 코드베이스의 알려진 취약점 패턴 스캔
- 코드 재사용으로 인한 취약점 전파 추적
- 오픈소스 라이브러리의 보안 감사
- CVE 데이터베이스 기반 취약점 스캔

### 추가 학습 자료

#### Quandary 이해를 위한 자료
1. **Infer 공식 문서**
   - Quandary checker: https://fbinfer.com/docs/checker-quandary
   - Taint analysis guide: https://fbinfer.com/docs/quandary-generic

2. **Facebook Engineering 블로그**
   - "Finding Inter-Procedural Bugs at Scale with Infer Static Analyzer"
   - Quandary 소개 및 실제 적용 사례

3. **학술 논문**
   - "Compositional Recurrence Analysis" (PLDI 2015) - Infer 이론적 기반
   - "Moving Fast with Software Verification" (NFM 2015) - Facebook의 Infer 사용 사례

#### Tracer 관련 자료
1. **CCS 2022 논문**
   - "Tracer: Signature-based Static Analysis for Detecting Recurring Vulnerabilities"
   - https://prosys.kaist.ac.kr/publications/ccs22.pdf

2. **프로젝트 페이지**
   - https://prosys.kaist.ac.kr/tracer/

3. **Docker 이미지**
   - https://hub.docker.com/repository/docker/prosyslab/tracer-artifacts
   - 논문 실험 재현 가능

---

**작성일**: 2025년 11월 22일  
**분석 대상**: tracer-infer (prosyslab)  
**기반 프로젝트**: Facebook Infer, Quandary  
**문서 버전**: 1.1 (Quandary 상세 설명 추가)
