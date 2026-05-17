# Attack Surface Memory - 20260516T152954+0900

## Derived Attack Surface Changes
- [recent] **외부 노출 자산에 대한 집중적인 스캐닝 확인**: 환자 포털(203.0.113.10) 및 VPN 게이트웨이(203.0.113.20)를 대상으로 한 특정 위협 소스(198.51.100.x 대역)의 활동이 급증함.
- [recent] **내부 백업 자산 접근 이상**: 클리닉 워크스테이션(10.42.100.45)에서 백업 NAS(10.42.40.12)로의 비정상적인 SMB 접근이 탐지되어 랜섬웨어 준비 동작 가능성 제기.
- [medium-term] **DB 직접 노출 위험**: 외부 IP(198.51.100.90)가 내부 DB(10.42.30.25) 포트로 직접 접근을 시도하는 패턴이 지속됨.

## Top Attack Hypotheses
- [recent] **PHP-CGI 취약점(CVE-2024-4577) 악용 시도**
  - evidence: 위협 피드 내 198.51.100.88의 스캐닝 이력 및 Tier 1 DB의 다수 탐지 기록.
  - observable_conditions: 203.0.113.10 대상의 HTTP/HTTPS 요청 중 특정 인자 주입 패턴.
  - negative_conditions: 단순 정적 리소스 요청 또는 정상적인 환자 로그인 세션.
  - confidence: high
  - review_condition: 알려진 위협 IP로부터의 접근 시 즉시 리뷰.

- [recent] **VPN 게이트웨이 무단 접근 및 RCE 시도**
  - evidence: 198.51.100.77의 반복적인 VPN 접속 시도 및 CVE-2023-3519 관련 경고.
  - observable_conditions: 203.0.113.20:443 대상의 반복적 로그인 실패 또는 비정상적 페이로드.
  - negative_conditions: 정상적인 직원 계정을 통한 다요소 인증 성공.
  - confidence: high
  - review_condition: 동일 소스 IP의 반복적 실패 발생 시 리뷰.

- [medium-term] **내부 이동 및 랜섬웨어 스테이징**
  - evidence: 워크스테이션 대역에서 백업 윈도우 외 시간에 백업 NAS로 SMB 접근 발생.
  - observable_conditions: 10.42.100.0/24 -> 10.42.40.12 (Port 445) 접근.
  - negative_conditions: 허용된 관리자 IP(10.42.50.8) 또는 백업 윈도우(02:00-04:00) 내 작업.
  - confidence: medium
  - review_condition: 비인가 IP의 SMB 세션 생성 시 리뷰.

## Repeated Patterns
- [recent] **198.51.100.0/24 대역의 조직적 스캐닝**: 포털, VPN, DB 등 다양한 자산을 대상으로 한 분산 스캐닝 패턴 확인.
- [recent] **SSH 무차별 대입**: 192.0.2.70, 192.0.2.71 등 외부 소스로부터 점프박스(10.42.50.8) 대상 SSH 접근 시도 반복.

## Watchlist Feedback
- [recent] 198.51.100.88 및 198.51.100.77 관련 항목이 높은 정확도로 탐지됨. 해당 소스들에 대한 차단 우선순위 상향 필요.

## Next-Cycle Guidance
- maintain: 외부 노출 서비스(Portal, VPN)에 대한 엄격한 모니터링 유지.
- strengthen: 백업 NAS 및 DB에 대한 내부 접근 제어 정책 위반 감시 강화.
- soften: 정상적인 백업 윈도우 내의 관리자 활동에 대한 오탐 주의.