# Attack Surface Memory - 20260516T152904+0900

## Derived Attack Surface Changes
- [recent] 외부 노출 자산(Patient Portal, VPN Gateway)에 대한 공격 시도가 실시간으로 확인됨. 특히 PHP-CGI 및 Citrix 관련 RCE 취약점(CVE-2024-4577, CVE-2023-3519)을 노린 스캐닝 활동이 관찰됨.
- [medium-term] 내부 자산 중 Billing DB 및 Backup NAS에 대한 비정상 접근 시도가 탐지됨. 이는 단순 스캐닝을 넘어선 내부 침투 또는 랜섬웨어 준비 단계의 가능성을 시사함.

## Top Attack Hypotheses
- [recent] **외부 접점 취약점 악용을 통한 초기 침투**
  - evidence: 198.51.100.88(PHP-CGI prober), 198.51.100.77(VPN brute-force)의 반복적 접근 기록.
  - observable_conditions: 특정 외부 IP의 반복적 로그인 실패 또는 웹 취약점 패턴(PHP-CGI injection) 요청.
  - negative_conditions: 정상적인 환자 포털 이용 및 승인된 VPN 사용자의 성공적인 로그인.
  - confidence: High
  - review_condition: 동일 소스 IP에서 5회 이상의 접근 시도 발생 시.

- [medium-term] **랜섬웨어 배포를 위한 백업 데이터 변조/탈취**
  - evidence: 10.42.100.45(클리닉 워크스테이션)에서 백업 윈도우 외 시간에 Backup NAS로 SMB 접근 시도 발생.
  - observable_conditions: 02:00-04:00 외 시간대의 SMB(445) 트래픽.
  - negative_conditions: 관리자 점프박스(10.42.50.8)에서의 정기 점검 활동.
  - confidence: Medium
  - review_condition: 워크스테이션 구역에서 백업 서버로의 직접적인 SMB 연결.

## Repeated Patterns
- [recent] 외부 위협 IP(198.51.100.77, 198.51.100.88)가 각각 VPN과 Portal을 지속적으로 타격하는 패턴.
- [medium-term] 내부 워크스테이션 구역에서 백업 서버로의 비인가 접근 시도 반복.

## Watchlist Feedback
- [recent] 이전 주기에서 설정한 외부 위협 IP 기반 Watchlist가 실제 8건의 경보 중 대부분을 탐지하여 유효성이 입증됨.

## Next-Cycle Guidance
- maintain: 외부 위협 IP 리스트 및 취약점 기반 탐지 강화.
- strengthen: 백업 윈도우 외 시간대의 SMB 접근에 대한 모니터링 임계치 강화.
- soften: 정상적인 비즈니스 시간 내의 포털 HTTP 트래픽에 대한 민감도 유지.