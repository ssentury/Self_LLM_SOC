# Attack Surface Memory - 20260519T121033+0900

## Derived Attack Surface Changes
- [long-term] 환자 포털(203.0.113.10) 및 VPN 게이트웨이(203.0.113.20)는 조직의 가장 노출된 접점으로, CVE-2024-4577 및 CVE-2023-3519의 직접적인 영향을 받음.
- [medium-term] 내부 백업 NAS(10.60.40.12)에 대한 워크스테이션의 접근 시도가 확인되었으며, 이는 랜섬웨어 스테이징의 전조 증상으로 관리 필요.
- [recent] 관리 평면(FortiManager, Jumpbox) 및 클라우드 메타데이터(169.254.169.254)에 대한 비인가 접근 시도가 탐지 데이터에서 반복적으로 식별됨.

## Top Attack Hypotheses
- [recent] 외부 위협원에 의한 DMZ 서비스 RCE 시도
  - evidence: 198.51.100.88(Web Scanner) 및 198.51.100.77(VPN Spray)의 지속적인 접근 이력.
  - observable_conditions: 특정 외부 IP에서의 반복적인 80/443 접속 및 작은 응답 크기.
  - negative_conditions: 정상적인 환자 포털 이용자 및 승인된 VPN 세션.
  - confidence: high
  - review_condition: 알려진 악성 IP 또는 CVE 취약점 관련 패턴 매칭 시.

- [medium-term] 워크스테이션을 통한 내부 자산 횡적 이동 및 백업 변조
  - evidence: 10.60.100.72 등 워크스테이션에서 백업 NAS(SMB)로의 비정상 시간대 접근.
  - observable_conditions: 백업 윈도우(02:00-04:00) 외의 SMB(445) 트래픽.
  - negative_conditions: 관리용 점프박스(10.60.50.8)에서의 정기 점검.
  - confidence: medium
  - review_condition: 일반 워크스테이션이 백업 또는 DB 세그먼트로 직접 연결 시도 시.

## Repeated Patterns
- [recent] 외부 IP 198.51.100.88의 포털(203.0.113.10) 대상 HTTP 80 포트 스캐닝.
- [recent] 내부 워크스테이션 대역에서의 169.254.169.254(IMDS) 접근 시도 및 비인가 외부 DNS(8.8.8.8) 사용.

## Watchlist Feedback
- [recent] 외부 DB 스캐너(198.51.100.90)의 내부 DB 접근 시도가 정확히 탐지되어 Alert 처리됨. 해당 패턴 유지 필요.
- [recent] NTP(123) 및 DNS(53) 관련 Alert가 다수 발생했으나, 이는 인프라 구성에 따른 오탐 가능성이 높으므로 임계치 조정 검토 필요.

## Next-Cycle Guidance
- maintain: 외부 DMZ 자산에 대한 CVE 기반 모니터링 강화.
- soften: 내부 인프라 서비스(NTP, DNS)에 대한 단순 접근 Alert 임계치 상향.
- strengthen: 관리 평면(TCP/541, RDP/SSH)으로의 비인가 소스 접근 차단 정책 검토.