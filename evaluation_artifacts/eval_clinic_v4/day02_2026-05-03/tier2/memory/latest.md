# Attack Surface Memory - 20260511T144411+0900

## Derived Attack Surface Changes
- [recent] 환자 포털(203.0.113.10) 및 VPN 게이트웨이(203.0.113.20)에 대한 외부 스캐닝 및 취약점 공격 시도가 급증함. 특히 PHP-CGI(CVE-2024-4577) 및 Citrix(CVE-2023-3519) 관련 위협이 실질적인 위험 요소로 부상.
- [medium-term] 내부 워크스테이션에서 백업 NAS(10.42.40.12)로의 비정상 시간대 접근이 확인됨(10.42.100.45). 이는 랜섬웨어 준비 단계의 전형적인 징후로 판단되어 모니터링 강화 필요.

## Top Attack Hypotheses
- [recent] PHP-CGI 취약점 악용을 통한 환자 포털 침투
  - evidence: 알려진 스캐너(198.51.100.88)의 포털 접근 이력.
  - observable_conditions: 203.0.113.10 대상 HTTP/HTTPS 요청 중 PHP 인자 주입 패턴.
  - negative_conditions: 단순 정적 리소스 요청 또는 정상적인 환자 로그인.
  - confidence: high
  - review_condition: 외부 IP의 반복적인 4xx/5xx 에러 유발 시 검토.

- [medium-term] 백업 변조 및 암호화를 위한 내부 확산
  - evidence: 10.42.100.45의 백업 NAS SMB 접근 기록.
  - observable_conditions: 유지보수 시간(02-04시) 외의 워크스테이션 -> NAS SMB 접근.
  - negative_conditions: 관리자 점프박스(10.42.50.8)를 통한 정기 점검.
  - confidence: medium
  - review_condition: 대량의 파일 수정/삭제 활동 감지 시 즉시 검토.

## Repeated Patterns
- [recent] 외부 대역(198.51.100.0/24)에서의 조직적인 스캐닝: 포털, VPN, DB(5432)를 대상으로 한 순차적 탐색 패턴 확인.

## Watchlist Feedback
- [recent] 이전 사이클에서 설정한 외부 IP 차단 및 백업 접근 감시 항목이 실제 Tier 1 경보(7건)와 일치함. 특히 198.51.100.77(VPN) 및 198.51.100.90(DB) 탐지가 유효했음.

## Next-Cycle Guidance
- maintain: 외부 스캐너 IP 및 비정상 시간대 백업 접근 감시.
- strengthen: 클라우드 메타데이터(169.254.169.254) 접근 시도에 대한 즉각적인 에스컬레이션 규칙 강화.