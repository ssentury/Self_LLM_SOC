# Attack Surface Memory - 20260519T120330+0900

## Derived Attack Surface Changes
- [recent] 외부 노출 자산(VPN, 환자 포털)에 대한 위협 인텔리전스 기반 탐지 중요도 상승. 특히 CVE-2024-4577(PHP-CGI) 및 CVE-2023-3519(Citrix) 관련 노출 가능성 확인.
- [medium-term] 내부망에서 빌링 DB(Postgres) 및 백업 NAS(SMB)로의 비정상적인 접근 패턴이 랜섬웨어 전조 증상으로 식별됨.
- [long-term] 클라우드 환경으로의 전환에 따라 IMDS(169.254.169.254) 접근 제어 정책의 엄격한 모니터링 유지 필요.

## Top Attack Hypotheses
- [recent] VPN 무차별 대입 및 초기 침투 시도
  - evidence: 198.51.100.77 등 알려진 위협 IP의 VPN 게이트웨이 접근 이력.
  - observable_conditions: 동일 외부 소스의 반복적 로그인 실패, 비정상적인 요청/응답 크기.
  - negative_conditions: 승인된 임직원의 정상적인 VPN 접속 성공.
  - confidence: high
  - review_condition: ml_prob >= 0.10 또는 알려진 위협 IP 매칭 시.

- [recent] 환자 포털 대상 PHP-CGI RCE 시도
  - evidence: CVE-2024-4577 취약점 정보 및 198.51.100.88의 스캐닝 활동.
  - observable_conditions: HTTP/HTTPS 요청 내 특정 인자 주입 패턴.
  - negative_conditions: 정상적인 환자 포털 서비스 이용 트래픽.
  - confidence: medium
  - review_condition: 알려진 스캐너 IP의 포털 접근 시.

## Repeated Patterns
- [recent] 외부 위협 IP(198.51.100.90)의 빌링 DB 직접 접근 시도 반복.
- [medium-term] 클리닉 워크스테이션에서 백업 윈도우(02-04) 외 시간에 백업 NAS로의 SMB 접근 시도.

## Watchlist Feedback
- [recent] VPN 및 DB 접근 관련 Watchlist 항목이 실제 공격 시도를 성공적으로 탐지함(Tier 1 DB 확인).
- [recent] DNS 터널링 의심 징후(8.8.8.8 대상 대량 쿼리)가 탐지되어 감시 강화 필요.

## Next-Cycle Guidance
- maintain: 외부 노출 자산(VPN, Portal)에 대한 취약점 기반 모니터링.
- strengthen: 백업 NAS 및 빌링 DB에 대한 내부망 접근 통제 감시.
- soften: 정상 업무 시간 내의 관리자 점프박스(10.42.50.8) 접근에 대한 경보 임계치 유지.