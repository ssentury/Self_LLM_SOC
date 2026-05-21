# Attack Surface Memory - 20260521T110432+0900

## Derived Attack Surface Changes
- [recent] 외부 위협 IP(`198.51.100.77`, `198.51.100.90`, `192.0.2.210`)로부터의 실질적인 공격 시도가 Tier 1 Alert로 확인되었습니다. 특히 외부에서 내부 DB(`10.42.30.25`)로의 직접 접근 시도는 심각한 정책 위반이자 노출 상태를 시사합니다.
- [recent] EHR API(`10.42.20.15`)에서 클라우드 메타데이터(`169.254.169.254`)로의 접근이 감지되어 자격증명 탈취 위험이 증가했습니다.
- [recent] 백업 NAS(`10.42.40.12`)에서 외부 미확인 IP(`198.51.100.123`)로의 아웃바운드 연결 및 워크스테이션(`10.42.100.45`)에서의 비인가 SMB 접근이 감지되어 랜섬웨어 전조 증상 가능성이 매우 높습니다.

## Top Attack Hypotheses
- [recent] VPN 무차별 대입 및 자격 증명 탈취 시도
  - evidence: `198.51.100.77` 및 `192.0.2.44`로부터 `203.0.113.20:443`으로의 다수 연결 시도 탐지.
  - observable_conditions: 동일 외부 IP가 짧은 시간 내 다수의 HTTPS 요청을 전송하며 실패 응답 크기가 일정함.
  - negative_conditions: 정상적인 VPN 세션 수립 및 장시간 연결 유지.
  - confidence: high
  - review_condition: 외부 IP의 VPN 게이트웨이 접근 실패 횟수 누적 시 검토.
- [recent] 백업 데이터 변조 및 랜섬웨어 스테이징
  - evidence: 워크스테이션 `10.42.100.45`가 백업 NAS `10.42.40.12:445`로 비인가 시간대 접근, 백업 NAS의 비정상 외부 아웃바운드(`198.51.100.123:443`) 발생.
  - observable_conditions: 백업 윈도우(02:00-04:00) 외의 시간대에 워크스테이션 CIDR(`10.42.100.0/24`)에서 NAS로의 SMB(445) 연결 또는 NAS 자체의 외부 아웃바운드.
  - negative_conditions: 허용된 관리자 호스트(`10.42.50.8`) 또는 백업 서버(`10.42.40.10`)의 백업 시간 내 정상 통신.
  - confidence: high
  - review_condition: 백업 윈도우 외 시간대의 SMB 통신 혹은 NAS의 외부 세션 연결 시 즉시 검토.
- [recent] 클라우드 자격증명 탈취 및 API 서버 침해
  - evidence: EHR API(`10.42.20.15`)에서 IMDS IP(`169.254.169.254`)로의 접근 탐지.
  - observable_conditions: 내부 호스트가 `169.254.169.254:80`으로 HTTP 요청 전송.
  - negative_conditions: 없음 (정책상 전면 금지).
  - confidence: high
  - review_condition: IMDS 목적지 IP 탐지 시 즉시 검토.

## Repeated Patterns
- [recent] 외부 스캐너(`192.0.2.210`)에 의한 환자 포털(`203.0.113.10`) 디렉터리 열거 및 PHP-CGI 취약점(CVE-2024-4577) 탐색 시도 지속.
- [recent] 워크스테이션 영역(`10.42.100.46`)에서 외부 DNS(`8.8.8.8`)를 이용한 비정상 대용량 DNS 질의(터널링 의심) 발생.

## Watchlist Feedback
- [recent] 이전 주기에서 설정된 외부 위협 IP 차단 및 비인가 백업 접근 룰이 Tier 1 DB 상에서 다수의 경보(Alert 8건)를 유효하게 탐지함. 특히 외부 DB 직접 접근(`198.51.100.90`) 탐지가 유효했음.

## Next-Cycle Guidance
- maintain: 외부 악성 IP 목록 기반의 게이트웨이 및 웹 포털 모니터링 유지.
- soften: 없음.
- strengthen: 백업 NAS의 아웃바운드 통신 통제 및 워크스테이션발 외부 DNS 대용량 질의(P-DNS) 탐지 정교화.