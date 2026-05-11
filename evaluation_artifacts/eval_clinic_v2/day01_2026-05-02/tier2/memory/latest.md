# Attack Surface Memory - 20260510T190120+0900

## Derived Attack Surface Changes
- [long-term] Hanbit Care Network의 주요 공격 표면은 외부 노출된 환자 포털(203.0.113.10)과 VPN 게이트웨이(203.0.113.20)로 식별됨. 소규모 조직 특성상 관리 인력이 적어 자동화된 스캔 및 브루트포스 공격에 취약할 가능성이 높음.
- [recent] CVE-2024-4577(PHP-CGI) 및 CVE-2023-3519(Citrix)와 같은 고위험 취약점이 외부 접점 자산에 할당되어 있어, 이를 타겟으로 한 초기 침투 시도가 예상됨.

## Top Attack Hypotheses
- [recent] VPN 자격 증명 탈취 및 초기 침투
  - evidence: 위협 피드 내 VPN 브루트포스 IP(198.51.100.77) 존재 및 VPN 게이트웨이(203.0.113.20)의 비정상 로그인 시도 정책.
  - observable_conditions: 동일 외부 IP에서의 반복적인 VPN 접속 실패 또는 알려진 위협 IP로부터의 접근.
  - negative_conditions: 승인된 관리자 IP 또는 정상 업무 시간 내의 성공적인 다요소 인증(MFA) 동반 접속.
  - confidence: high
  - review_condition: 외부 IP에서 VPN 게이트웨이로의 반복적인 443/TCP 연결 시도 발생 시.

- [recent] 환자 포털을 통한 RCE 및 데이터 유출
  - evidence: CVE-2024-4577 취약점 및 PHP-CGI 스캐너 IP(198.51.100.88) 정보.
  - observable_conditions: 웹 서버(203.0.113.10)를 대상으로 한 특수 인자 주입 형태의 HTTP 요청.
  - negative_conditions: 정상적인 환자 예약 및 포털 이용 트래픽.
  - confidence: medium
  - review_condition: 알려진 스캐너 IP의 접근이나 비정상적인 URI 패턴 탐지 시.

## Repeated Patterns
- [recent] 현재 첫 분석 주기로 반복 패턴은 식별되지 않았으나, 소규모 의료 기관을 타겟으로 한 랜섬웨어 전조 현상(백업 변조, VPN 압박)을 중점 감시할 필요가 있음.

## Watchlist Feedback
- [recent] 이전 데이터 없음. 이번 주기에서 설정한 위협 IP 및 취약점 기반 탐지 규칙의 유효성을 다음 주기에서 평가 예정.

## Next-Cycle Guidance
- maintain: 외부 접점 자산(Portal, VPN)에 대한 엄격한 모니터링 유지.
- strengthen: 내부망에서 백업 NAS(10.42.40.12)로의 비정상적인 SMB 접근 패턴 감시 강화.
- soften: 정상 업무 시간 내의 일반적인 환자 포털 접속에 대한 경보 우선순위 조정.