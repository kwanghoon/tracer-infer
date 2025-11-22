#!/bin/bash
# demo_tracer_list.sh - Tracer List 기능 데모 스크립트

set -e

echo "================================"
echo "Tracer List 기능 데모"
echo "================================"
echo ""

# 1. 빌드
echo "[1/4] 프로젝트 빌드..."
cd "$(dirname "$0")"
if [ -d "../../tracer/tracer/rank" ]; then
    TRACER_DIR="../../tracer/tracer"
else
    echo "Error: tracer 프로젝트를 찾을 수 없습니다."
    exit 1
fi

# list_signatures.ml 복사
echo "  - list_signatures.ml 복사..."
cp list_signatures.ml "$TRACER_DIR/rank/src/"

# dune 파일 백업 및 수정
echo "  - dune 파일 수정..."
cd "$TRACER_DIR/rank/src"
if [ ! -f "dune.backup" ]; then
    cp dune dune.backup
fi

# dune 파일에 list_signatures 실행 파일 추가
cat > dune << 'EOF'
(executable
 (name main)
 (modules main rank feature infer location options viz)
 (libraries yojson unix str))

(executable
 (name list_signatures)
 (modules list_signatures)
 (libraries yojson unix))
EOF

# 빌드
echo "  - dune 빌드..."
cd ..
dune build

echo ""
echo "[2/4] Signature Database 확인..."
SIG_DB="../signature-db"
if [ ! -d "$SIG_DB" ]; then
    echo "Error: signature-db 디렉토리를 찾을 수 없습니다: $SIG_DB"
    exit 1
fi

NUM_SUBDIRS=$(find "$SIG_DB" -mindepth 1 -maxdepth 1 -type d | wc -l)
echo "  - 발견된 프로그램: $NUM_SUBDIRS개"

# 첫 번째 서브디렉토리의 JSON 파일 하나 표시
FIRST_SUBDIR=$(find "$SIG_DB" -mindepth 1 -maxdepth 1 -type d | head -n 1)
if [ -n "$FIRST_SUBDIR" ]; then
    PROGRAM_NAME=$(basename "$FIRST_SUBDIR")
    FIRST_JSON=$(find "$FIRST_SUBDIR" -name "*.json" | head -n 1)
    if [ -n "$FIRST_JSON" ]; then
        echo "  - 예제 파일: $PROGRAM_NAME/$(basename "$FIRST_JSON")"
        echo ""
        echo "    입력 JSON 구조 (처음 20줄):"
        head -n 20 "$FIRST_JSON" | sed 's/^/      /'
    fi
fi

echo ""
echo "[3/4] List 명령 실행..."
cd "$TRACER_DIR/rank"
if [ -f "_build/default/src/list_signatures.exe" ]; then
    LIST_CMD="_build/default/src/list_signatures.exe"
elif [ -f "_build/default/list_signatures.exe" ]; then
    LIST_CMD="_build/default/list_signatures.exe"
else
    echo "Error: list_signatures 실행 파일을 찾을 수 없습니다."
    exit 1
fi

# 작은 샘플만 처리 (데모용)
echo "  - 샘플 처리 시작..."
$LIST_CMD --db "$SIG_DB"

echo ""
echo "[4/4] 결과 확인..."
OUTPUT_DIR="signature-db-info"
if [ -d "$OUTPUT_DIR" ]; then
    NUM_OUTPUT=$(find "$OUTPUT_DIR" -name "*.json" | wc -l)
    echo "  - 생성된 파일: $NUM_OUTPUT개"
    
    # 첫 번째 출력 파일 표시
    FIRST_OUTPUT=$(find "$OUTPUT_DIR" -name "*.json" | head -n 1)
    if [ -n "$FIRST_OUTPUT" ]; then
        echo "  - 예제 출력: $FIRST_OUTPUT"
        echo ""
        echo "    출력 JSON:"
        cat "$FIRST_OUTPUT" | python -m json.tool | head -n 30 | sed 's/^/      /'
    fi
else
    echo "  - Warning: 출력 디렉토리가 생성되지 않았습니다."
fi

echo ""
echo "================================"
echo "데모 완료!"
echo "================================"
echo ""
echo "생성된 파일 위치: $TRACER_DIR/rank/signature-db-info/"
echo ""
echo "다음 단계:"
echo "  1. signature-db-info 디렉토리의 JSON 파일 확인"
echo "  2. abstract trace 패턴을 사용한 유사도 계산 구현"
echo "  3. 취약점 패턴 분류 및 분석"
