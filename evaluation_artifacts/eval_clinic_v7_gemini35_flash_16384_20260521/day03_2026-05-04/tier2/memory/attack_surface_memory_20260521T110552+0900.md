# Attack Surface Memory - 20260521T110552+0900

## Derived Attack Surface Changes
- [recent] 외부 위협 IP(`198.51.100.90`)로부터 내부 빌링 데이터베이스(`10.42.30.25`)로의 직접적인 Postgres(5432) 연결 시도가 식별되어 심각한 경계선 노출 확인.
- [recent] 환자 포탈 웹 서버(`203.0.113.10`)가 내부 빌링 데이터베이스(`10.42.30.25`)로 직접 SQL 질의를 수행하는 비정상 흐름 감지. 포탈 웹 서버 침해 및 내부 횡적 이동 가능성 매우 높음.
- [recent] 백업 NAS(`10.42.40.12`)에서 외부 미확인 IP(`198.51.100.123`)로의 아웃바운드 HTTPS 연결 및 클리닉 워크스테이션(`10.42.100.45`)으로부터 비인가 SMB 접근이 확인되어 랜섬웨어 전조 증상 의심.

## Top Attack Hypotheses
- [recent] 환자 포탈 침해를 통한 내부 데이터베이스 탈취 가설
  - evidence: 환자 포탈(`203.0.113.10`)에서 빌링 DB(`10.42.30.25`)로의 직접적인 Postgres 연결 발생 이력.
  - observable_conditions: 포탈 서버 출발지 및 내부 DB 목적지의 5432 포트 연결 또는 기타 내부망 비인가 스캔.
  - negative_conditions: 허용된 관리자 점프박스(`10.42.50.8`)를 통한 정상 DB 점검 작업.
  - confidence: high
  - review_condition: 포탈 IP에서 내부망 대역으로의 신규 세션 수립 시 즉시 검토.
- [recent] 백업 시스템 표적 랜섬웨어 스테이징 및 데이터 유출 가설
  - evidence: 백업 NAS의 외부 아웃바운드 연결 이력 및 백업 윈도우 외 시간대의 워크스테이션 SMB 연결 경보.
  - observable_conditions: 백업 윈도우(02:00-04:00) 외 시간대에 워크스테이션 대역(`10.42.100.0/24`)에서 백업 NAS(`10.42.40.12`)로의 SMB(445) 트래픽 발생.
  - negative_conditions: 지정된 백업 소스(`10.42.40.10`, `10.42.50.8`)의 백업 시간 내 정상 동작.
  - confidence: high
  - review_condition: 백업 NAS 관련 비정상 포트 연결 또는 시간 외 SMB 접근 발생 시 검토.

## Repeated Patterns
- [medium-term] 외부 악성 IP 대역(`198.51.100.77`, `192.0.2.44`)으로부터 VPN 게이트웨이(`203.0.113.20`) 대상의 무차별 대입(Password Spraying) 공격 지속 관찰.
- [medium-term] 클리닉 워크스테이션 영역에서 외부 공용 DNS(`8.8.8.8`)를 경유하는 대용량 DNS 질의(터널링 의심) 반복 발생.

## Watchlist Feedback
- [recent] 이전 주기에서 설정한 VPN 브루트포스 및 외부 DB 직접 접근 탐지 룰이 실제 다수의 유효 경보를 성공적으로 분류함. 포탈-DB 직접 연결 패턴에 대한 탐지 정교화가 필요함.

## Next-Cycle Guidance
- maintain: 외부 IP의 DB 직접 접근 및 VPN 무차별 대입 탐지 상태 유지.
- soften: 없음.
- strengthen: 환자 포탈의 내부망 접근 통제 위반 감시 및 백업 NAS의 외부 아웃바운드 연결 통제 강화.