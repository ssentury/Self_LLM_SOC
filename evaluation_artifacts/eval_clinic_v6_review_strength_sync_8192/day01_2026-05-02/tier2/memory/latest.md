# Attack Surface Memory - 20260519T120233+0900

## Derived Attack Surface Changes
- [recent] **외부 노출 접점 집중**: 환자 포털(203.0.113.10)과 VPN 게이트웨이(203.0.113.20)가 핵심 공격 표면으로 식별됨. 특히 PHP-CGI(CVE-2024-4577) 및 Citrix(CVE-2023-3519) 취약점 관련 외부 노출 위험이 높음.
- [recent] **내부 횡적 이동 경로**: 클리닉 워크스테이션에서 백업 NAS(10.42.40.12)로의 SMB 접근 및 클라우드 메타데이터(IMDS) 접근이 랜섬웨어 및 권한 탈취의 주요 경로로 정의됨.

## Top Attack Hypotheses
- [recent] **VPN 기반 초기 침투 및 랜섬웨어 스테이징**
  - evidence: 위협 피드 내 VPN 무차별 대입 IP(198.51.100.77) 및 섹터 경고.
  - observable_conditions: 외부 IP의 VPN 게이트웨이 반복 접속 실패 또는 알려진 위협 IP의 접근.
  - negative_conditions: 승인된 사용자의 정상적인 업무 시간 내 VPN 접속.
  - confidence: high
  - review_condition: 동일 외부 IP에서 짧은 시간 내 다수의 세션 시도 시 검토.

- [recent] **웹 취약점(PHP-CGI) 기반 RCE 시도**
  - evidence: CVE-2024-4577 및 관련 스캐너 IP(198.51.100.88).
  - observable_conditions: 환자 포털 대상 비정상적인 HTTP 인자 전달 또는 알려진 스캐너의 접근.
  - negative_conditions: 정상적인 환자 예약 및 포털 이용 트래픽.
  - confidence: medium
  - review_condition: URI 내 특수문자나 PHP 실행 관련 키워드 포함 시 검토.

## Repeated Patterns
- [recent] 아직 관찰된 반복 패턴 없음 (초기 사이클). 위협 피드 기반의 스캐닝 시나리오를 우선 감시.

## Watchlist Feedback
- [recent] 피드백 데이터 없음. 초기 왓치리스트 설정 후 다음 사이클에서 탐지 효율성 평가 예정.

## Next-Cycle Guidance
- maintain: 외부 노출 자산(포털, VPN)에 대한 고강도 모니터링 유지.
- strengthen: 백업 NAS 및 IMDS 접근에 대한 정책 위반 탐지 강화.
- soften: 업무 시간 내 정상적인 VPN 및 API 통신에 대한 오탐 주의.