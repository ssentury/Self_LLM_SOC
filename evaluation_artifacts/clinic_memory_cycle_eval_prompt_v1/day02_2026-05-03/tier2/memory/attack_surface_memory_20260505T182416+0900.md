# Attack Surface Memory - 20260505T182416+0900

## Derived Attack Surface Changes
- [recent] **VPN 게이트웨이 및 환자 포털 집중 공격**: 외부 IP 대역(198.51.100.0/24, 192.0.2.0/24)에서 VPN(203.0.113.20) 및 포털(203.0.113.10)을 대상으로 한 무차별 대입 및 스캐닝 활동이 급증함.
- [recent] **클라우드 자격 증명 탈취 시도**: EHR API 서버(10.42.20.15)에서 IMDS(169.254.169.254)로의 비정상적인 접근이 탐지되어 클라우드 환경 내 권한 상승 위험이 식별됨.
- [medium-term] **내부 자산 노출 위험**: 빌링 DB(10.42.30.25)에 대한 외부 직접 접근 시도가 탐지됨. 이는 내부 망 분리 정책의 우회 가능성 또는 설정 오류를 시사함.

## Top Attack Hypotheses
- [recent] **VPN 초기 침투 및 랜섬웨어 준비**
  - evidence: 198.51.100.77 등 다수의 외부 IP에서 VPN 로그인 실패 및 비정상적 응답 크기 발생.
  - observable_conditions: dst_ip: 203.0.113.20, dst_port: 443, 다수의 실패 로그.
  - negative_conditions: 업무 시간 내 정상적인 VPN 세션 유지 및 성공적인 다요소 인증.
  - confidence: high
  - review_condition: 동일 외부 IP에서 5회 이상의 연결 시도 발생 시.

- [recent] **PHP-CGI 취약점(CVE-2024-4577) 기반 RCE**
  - evidence: 198.51.100.88 등 알려진 스캐너의 포털(203.0.113.10) 접근.
  - observable_conditions: HTTP 요청 내 특정 인자 주입 패턴(query string 등).
  - negative_conditions: 정적 리소스(이미지, CSS)에 대한 단순 GET 요청.
  - confidence: medium
  - review_condition: 알려진 악성 IP로부터의 포털 접근 시.

## Repeated Patterns
- [recent] 외부 미식별 대역에서 VPN 게이트웨이(443/tcp)로의 반복적인 연결 시도.
- [medium-term] 내부 워크스테이션(10.42.100.0/24)에서 외부 DNS(8.8.8.8)를 이용한 대량 쿼리 패턴(터널링 의심).

## Watchlist Feedback
- [recent] 198.51.100.77(VPN) 및 198.51.100.90(DB) 관련 탐지 항목이 실제 경보로 이어져 유효성이 입증됨.

## Next-Cycle Guidance
- maintain: VPN 및 포털 대상 외부 스캐닝 모니터링 강화.
- soften: 백업 윈도우(02:00-04:00) 내의 정상적인 SMB 트래픽에 대한 우선순위 하향.
- strengthen: EHR API 서버의 IMDS 접근 및 내부 DNS 외의 외부 DNS 쿼리 감시.