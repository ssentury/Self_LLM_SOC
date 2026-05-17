# Attack Surface Memory - 20260516T153905+0900

## Derived Attack Surface Changes
- [recent] **공개 웹 및 VPN 노출 위협 증가**: CVE-2024-4577(PHP-CGI) 및 CVE-2023-3519(VPN) 취약점이 보고됨에 따라 환자 포털(203.0.113.10)과 VPN 게이트웨이(203.0.113.20)가 최우선 보호 대상으로 부상함.
- [recent] **백업 스토리지 타겟팅 징후**: 내부 워크스테이션에서 백업 NAS(10.60.40.12)로의 비정상적인 SMB 접근이 확인되어 랜섬웨어 전조 현상으로 판단됨.
- [medium-term] **데이터베이스 직접 노출**: 외부 IP(198.51.100.90)가 내부 EHR DB(10.60.30.20)로 직접 접근을 시도하는 패턴이 반복됨.

## Top Attack Hypotheses
- [recent] **환자 포털 RCE 공격**: CVE-2024-4577 취약점을 이용한 PHP-CGI 인젝션 시도가 발생할 가능성이 높음.
  - evidence: 위협 피드 내 198.51.100.88의 스캐닝 이력 및 Tier 1 DB 내 다수 탐지 이력.
  - observable_conditions: 외부 IP의 80/443 포트 반복 접근 및 이상 HTTP 페이로드.
  - negative_conditions: 관리자 점프박스에서의 정상적인 점검 트래픽.
  - confidence: High
  - review_condition: 해당 자산으로의 외부 접근 시 ML 점수가 0.1 이상일 경우.

- [recent] **내부 랜섬웨어 확산 시도**: 감염된 워크스테이션을 통한 백업 데이터 변조/삭제 시도.
  - evidence: 10.60.100.72 등 워크스테이션에서 백업 NAS로의 SMB(445) 접근 알람 발생.
  - observable_conditions: 백업 윈도우(02:00-04:00) 외 시간대의 워크스테이션발 SMB 트래픽.
  - negative_conditions: IT 운영팀(10.60.50.8)의 유지보수 활동.
  - confidence: Medium
  - review_condition: 비인가 대역의 445 포트 접근 시.

## Repeated Patterns
- [recent] **VPN 무차별 대입**: 198.51.100.77 IP가 VPN 게이트웨이(443)에 대해 반복적인 인증 실패를 유발함.
- [medium-term] **관리자 평면 스캐닝**: 192.0.2.77 IP가 점프박스(10.60.50.8) SSH(22) 포트를 지속적으로 탐색함.

## Watchlist Feedback
- [recent] 198.51.100.88과 198.51.100.77에 대한 왓치리스트 항목이 실제 알람으로 이어져 유효성이 검증됨. 백업 서버 접근 정책 강화 필요.

## Next-Cycle Guidance
- maintain: 외부 공개 서비스(Portal, VPN)에 대한 집중 모니터링.
- strengthen: 워크스테이션 대역에서 백업 및 관리 평면으로의 접근 통제 감시 강화.
- soften: 정상적인 업무 시간 내 의사 워크스테이션의 PACS 접근은 과탐 방지를 위해 완화.