# Ethereum Smart Contract Security Analyzer

이더리움 스마트 컨트랙트의 악성 패턴과 보안 취약점을 탐지하는 Python 도구

## 주요 기능

### 탐지 가능한 악성 패턴들

#### 1. 허니팟 (Honeypot) 패턴
- **블랙리스트 시스템**: 특정 주소의 토큰 전송 차단
- **화이트리스트 전용**: 화이트리스트에 없는 주소는 거래 불가
- **판매 함수 비활성화**: transfer 함수가 항상 실패
- **조건부 제한 로직**: owner만 판매 가능한 구조
- **시간 기반 잠금**: 특정 시간/블록까지 거래 제한
- **비현실적 최소 판매량**: 달성 불가능한 최소 판매 요구량

#### 2. 민팅 관련 악성 패턴
- **무제한 민팅**: 양 제한 없는 토큰 발행
- **숨겨진 민팅**: 일반 함수 내부에 숨겨진 민팅 로직
- **조건부 대량 민팅**: 특정 조건에서 대량 토큰 발행
- **totalSupply 조작**: 총 공급량 직접 수정
- **최대 공급량 무시**: maxSupply 체크 우회
- **잔액 직접 할당**: balanceOf 직접 수정

#### 3. 수수료 및 세금 조작
- **극단적 수수료**: 90-100% 수수료율
- **동적 수수료 조작**: 제한 없는 수수료 변경
- **비대칭 수수료**: 매수/매도 수수료 현저한 차이
- **수수료 상한선 없음**: 수수료 설정에 제한 없음
- **예상외 수수료 수신자**: 선언과 다른 수수료 흐름
- **수수료 계산 오류**: 백분율 변환 누락
- **다중 수수료**: 여러 수수료 중첩 적용

#### 4. 접근 제어 권한 남용
- **과도한 Owner 권한**: 토큰 압수, 계정 동결 등
- **잔액 조작**: Owner의 임의 잔액 변경
- **긴급 인출**: 컨트랙트 자금 전체 인출
- **컨트랙트 일시정지**: 모든 거래 차단 기능
- **소유권 포기 무력화**: renounceOwnership 미작동

#### 5. 메타모픽/업그레이드 패턴
- **무제한 업그레이드**: 제한 없는 컨트랙트 업그레이드
- **프록시 구현체 교체**: implementation 주소 임의 변경
- **SELFDESTRUCT 패턴**: 컨트랙트 자폭 기능
- **CREATE2 사용**: 결정적 주소 생성
- **거버넌스 우회**: 투표 없는 중요 변경

#### 6. Low-level 조작
- **Inline Assembly**: Assembly 블록 악용
- **스토리지 직접 조작**: sstore/sload를 통한 조작
- **메모리 조작**: mstore/mload 등 메모리 직접 접근
- **Storage 포인터**: 직접적인 스토리지 접근

#### 7. 함수 로직 조작
- **불가능한 조건**: 항상 거짓인 require 조건
- **시간 기반 트랩**: 특정 시간에만 작동
- **주소 기반 분기**: 특정 주소에서만 다른 동작
- **오해를 유발하는 함수명**: 안전해 보이지만 악성인 함수
- **더미 보안 함수**: 실제로는 아무것도 하지 않는 함수
- **악성 fallback**: fallback/receive 함수 내 악성 로직

#### 8. 경제적 로직 조작
- **하드코딩된 가격**: 시장과 무관한 고정 가격
- **조작 가능한 오라클**: Owner의 임의 가격 변경
- **유동성 철수**: Owner의 임의 유동성 제거
- **스테이킹 잠금**: 스테이킹 토큰 출금 불가

#### 9. 이벤트 및 로깅 조작
- **거짓 이벤트**: 실제 상태 변경 없는 이벤트
- **누락된 이벤트**: 중요한 상태 변경 시 이벤트 없음
- **가짜 성공 이벤트**: 실패한 거래의 성공 이벤트

#### 10. 표준 위반 패턴
- **ERC-20 필수 함수 누락**: 표준 함수 미구현
- **transfer 함수 조작**: 표준과 다른 동작
- **approve 함수 무력화**: 실제 승인하지 않음
- **잔액 불일치**: balanceOf 거짓 값 반환

#### 11. 가스 및 실행 조작
- **무한 루프**: 탈출 조건 없는 루프
- **가스 폭탄**: 의도적 높은 가스 소모
- **재진입 취약점**: 외부 호출 후 상태 변경
- **실행 순서 의존성**: 블록체인 환경 의존 로직

## 설치 및 사용법

### 설치
```bash
git clone https://github.com/your-username/contractCodeAnalyzer.git
cd contractCodeAnalyzer
```

### 기본 사용법
```bash
# 컨트랙트 파일 분석
python contract_analyzer.py contract.sol

# JSON 형태로 결과 저장
python contract_analyzer.py contract.sol -o report.json

# 상세 출력
python contract_analyzer.py contract.sol -v
```

### Python 코드에서 사용
```python
from contract_analyzer import ContractAnalyzer
from report_generator import ReportGenerator

# 분석기 초기화
analyzer = ContractAnalyzer()

# 파일에서 분석
result = analyzer.analyze_from_file("contract.sol")

# 문자열에서 직접 분석
contract_code = "pragma solidity ^0.8.0; ..."
result = analyzer.analyze_contract(contract_code)

# 리포트 생성
report_gen = ReportGenerator()
report_gen.set_data(result)

# 콘솔 리포트
print(report_gen.generate_console_report())

# JSON 리포트 저장
report_gen.save_report("report.json", "json")

# HTML 리포트 저장
report_gen.save_report("report.html", "html")
```

## 출력 예시

### 콘솔 출력
```
================================================================================
ETHEREUM SMART CONTRACT SECURITY ANALYSIS REPORT
================================================================================
Analysis Date: 2025-01-20 15:30:45

SUMMARY
----------------------------------------
Total Issues Found: 26
🔴 Critical: 9
🟠 High: 14
🟡 Medium: 3
🟢 Low: 0

🔴 CRITICAL SEVERITY ISSUES (9)
------------------------------------------------------------
1. Unlimited Minting
   Description: 민팅 함수에 양 제한이 없어 무제한으로 토큰을 발행할 수 있습니다.
   Line: 45
   Code: function mint(address to, uint256 amount) public onlyOwner {
   Recommendation: 민팅 양에 대한 적절한 제한을 설정하세요.
```

### JSON 출력
```json
{
  "metadata": {
    "analysis_date": "2025-01-20T15:30:45",
    "analyzer_version": "1.0.0",
    "total_patterns_checked": 11
  },
  "summary": {
    "total_issues": 26,
    "critical": 9,
    "high": 14,
    "medium": 3,
    "low": 0
  },
  "findings": {
    "Critical": [
      {
        "pattern_name": "Unlimited Minting",
        "description": "민팅 함수에 양 제한이 없어 무제한으로 토큰을 발행할 수 있습니다.",
        "code_snippet": "function mint(address to, uint256 amount) public onlyOwner {",
        "line_number": 45,
        "recommendation": "민팅 양에 대한 적절한 제한을 설정하세요."
      }
    ]
  },
  "risk_assessment": {
    "overall_risk_level": "CRITICAL",
    "risk_score": 10,
    "deployment_recommendation": "DO NOT DEPLOY - Critical security vulnerabilities must be fixed first"
  }
}
```

## 테스트

테스트 실행:
```bash
python tests/test_analyzer.py
```

### 검증 항목
- 악성 패턴들의 탐지
- 깨끗한 컨트랙트에서의 오탐 최소화
- 리포트 생성 기능
- 다양한 출력 형식

## 프로젝트 구조

```
contractCodeAnalyzer/
├── contract_analyzer.py          # 메인 분석기
├── report_generator.py           # 리포트 생성기
├── analyzers/                    # 분석 모듈들
│   ├── __init__.py
│   ├── honeypot_patterns.py      # 허니팟 패턴
│   ├── minting_patterns.py       # 민팅 패턴
│   ├── fee_patterns.py           # 수수료 패턴
│   ├── access_control_patterns.py # 접근 제어 패턴
│   ├── metamorphic_patterns.py   # 메타모픽 패턴
│   ├── lowlevel_patterns.py      # Low-level 패턴
│   ├── function_logic_patterns.py # 함수 로직 패턴
│   ├── economic_patterns.py      # 경제적 패턴
│   ├── event_patterns.py         # 이벤트 패턴
│   ├── standard_patterns.py      # 표준 위반 패턴
│   └── gas_patterns.py           # 가스 패턴
└── README.md                     # 이 파일
```

## 확장성

새로운 패턴 추가 방법:

1. `analyzers/` 디렉토리에 새로운 모듈 생성
2. `AnalysisPattern` 클래스를 상속받아 `analyze` 메서드 구현
3. `contract_analyzer.py`의 `_register_patterns` 메서드에 추가


## 제한사항

일부 패턴들은 정적 코드 분석으로는 탐지하기 어려울 수 있음:

### 탐지 어려운 패턴들:
- **동적 컨트랙트 교체**: 런타임에 결정되는 로직
- **복잡한 수학적 조작**: 고도의 암호화나 수학 로직
- **타임스탬프 기반 정밀 조작**: 매우 구체적인 시간 조건
- **크로스 컨트랙트 의존성**: 다른 컨트랙트와의 상호작용
- **오프체인 의존성**: 외부 데이터에 의존하는 로직

## 면책 조항

이 도구는 교육 및 연구 목적으로 제공됩니다. 사용자는 이 도구의 결과를 기반으로 한 투자나 계약 결정에 대해 전적인 책임을 집니다. 개발자는 이 도구의 사용으로 인한 어떠한 손실이나 피해에 대해서도 책임지지 않습니다.
