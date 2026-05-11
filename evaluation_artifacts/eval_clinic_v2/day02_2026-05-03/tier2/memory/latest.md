# Attack Surface Memory - 20260510T190217+0900

## Derived Attack Surface Changes
- [recent] **외부 노출 서비스 공격 시도 증가**: VPN 게이트웨이(203.0.113.20) 및 환자 포털(203.0.113.10)을 대상으로 한 외부 위협 IP의 구체적인 공격 시도가 확인됨.
- [recent] **내부 자산의 클라우드 메타데이터 접근**: EHR API 서버(10.42.20.15)에서 IMDS(169.254.169.254)로의 접근이 탐지되어 클라우드 권한 탈취 시도 가능성이 높아짐.
- [medium-term] **백업 데이터 무결성 위험**: 백업 NAS(10.42.40.12)에서 외부 미확인 IP로의 통신이 발생하여 데이터 유출 또는 랜섬웨어 스테이징 징후가 포착됨.

## Top Attack Hypotheses
- [recent] **VPN 무차별 대입을 통한 초기 침투**
  - evidence: 198.51.100.77의 VPN 게이트웨이 접속 시도 및 경보 발생.
  - observable_conditions: 동일 외부 IP의 반복적인 443 포트 접속 및 작은 패킷 사이즈.
  - negative_conditions: 승인된 사용자의 정상적인 VPN 로그인 성공.
  - confidence: high
  - review_condition: 동일 IP에서 5회 이상 실패 후 성공 시 즉시 리뷰.

- [recent] **웹 취약점(PHP-CGI)을 이용한 RCE 시도**
  - evidence: CVE-2024-4577 관련 위협 피드 및 알려진 스캐너(192.0.2.210)의 포털 접근.
  - observable_conditions: HTTP/HTTPS 요청 내 특정 아규먼트 주입 패턴.
  - negative_conditions: 정적 리소스 요청 및 정상적인 예약 프로세스.
  - confidence: medium
  - review_condition: 비정상적인 경로(/php-cgi/) 접근 시도 시 리뷰.

## Repeated Patterns
- [recent] 외부 위협 IP(198.51.100.x 대역)를 통한 체계적인 스캐닝 및 브루트포스 패턴이 반복됨.
- [medium-term] 업무 시간 외 백업 자산에 대한 접근 시도가 간헐적으로 발생함.

## Watchlist Feedback
- [recent] 위협 피드에 등록된 IP(198.51.100.77, 198.51.100.90 등) 기반 탐지가 매우 효과적이었으며, 실제 경보로 이어짐.
- [recent] IMDS 접근 정책(P-IMDS) 위반 탐지가 유효한 공격 징후를 포착함.

## Next-Cycle Guidance
- maintain: 외부 위협 IP 블랙리스트 기반 모니터링 유지.
- strengthen: 내부 자산 간의 비정상적인 SMB 통신 및 IMDS 쿼리에 대한 가시성 강화.
- soften: 정상적인 백업 윈도우(02:00-04:00) 내의 승인된 소스 통신은 우선순위 낮춤.