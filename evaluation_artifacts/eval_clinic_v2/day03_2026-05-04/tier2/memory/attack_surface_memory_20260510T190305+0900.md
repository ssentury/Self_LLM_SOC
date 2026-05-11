# Attack Surface Memory - 20260510T190305+0900

## Derived Attack Surface Changes
- [recent] VPN 게이트웨이(203.0.113.20)와 빌링 DB(10.42.30.25)에 대한 외부 위협 IP의 직접적인 스캐닝 및 브루트포스 시도가 실시간 탐지됨에 따라 위험도 상향 조정.
- [recent] EHR API(10.42.20.15)에서 클라우드 메타데이터 서비스(169.254.169.254)로의 접근이 확인되어, 애플리케이션 권한 탈취 시도 가능성 농후.
- [medium-term] 백업 NAS(10.42.40.12)에서 외부 미확인 IP로의 HTTPS 통신이 발생, 이는 데이터 유출 또는 C2 통신 전조일 수 있음.

## Top Attack Hypotheses
- [recent] VPN 초기 침투 및 랜섬웨어 전개
  - evidence: 198.51.100.77의 반복적인 VPN 로그인 실패 및 10.42.40.12의 외부 통신.
  - observable_conditions: VPN 포트(443)에 대한 동일 외부 IP의 반복 접속, 백업 NAS의 비정상 시간대 외부 통신.
  - negative_conditions: 승인된 유지보수 시간 내 관리자 IP의 접속.
  - confidence: high
  - review_condition: VPN 로그인 성공 후 내부 자원 스캐닝 발생 시 즉시 에스컬레이션.

- [recent] 클라우드 자격 증명 탈취 (IMDS Exfiltration)
  - evidence: EHR API 서버에서 169.254.169.254:80 접근 탐지.
  - observable_conditions: 내부 앱 서버의 IMDS 쿼리 발생.
  - negative_conditions: 인프라 팀의 명시적인 클라우드 설정 변경 작업.
  - confidence: high
  - review_condition: IMDS 접근 후 외부로의 대량 데이터 전송 발생 시.

## Repeated Patterns
- [recent] 외부 위협 IP(198.51.100.77, 198.51.100.90)가 DMZ와 내부 DB 영역을 교차하며 정찰하는 패턴 반복.
- [medium-term] 클리닉 워크스테이션 영역에서의 외부 DNS(8.8.8.8) 쿼리 반복 발생, DNS 터널링 의심.

## Watchlist Feedback
- [recent] VPN 브루트포스 및 DB 스캐닝 탐지 항목이 실제 위협 IP와 일치하여 유효함. IMDS 접근 차단 정책 강화 필요.

## Next-Cycle Guidance
- maintain: VPN 및 DB 직접 접근 모니터링 강화.
- strengthen: 백업 NAS의 외부 통신 및 워크스테이션의 비정상 DNS 쿼리 탐지 로직 정교화.
- soften: 유지보수 시간대(02-04시) 내 승인된 관리자 IP의 SMB 통신 알람 우선순위 하향.