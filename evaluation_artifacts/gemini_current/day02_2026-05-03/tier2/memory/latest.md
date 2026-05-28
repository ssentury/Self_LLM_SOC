# Attack Surface Memory - 20260527T151036+0900

## Derived Attack Surface Changes
- [recent] 외부 DMZ 노출 자산(환자 포털, VPN 게이트웨이)에 대한 취약점 공격 시도 및 무차별 대입 공격이 지속적으로 탐지되고 있어 모니터링 강화가 필요합니다.
- [recent] 내부 백업 자산(10.60.40.12)에서 외부 인터넷 대역(198.51.100.123)으로의 비정상 아웃바운드 연결 및 일반 워크스테이션 대역에서의 오프 윈도우 백업 접근이 확인되어 랜섬웨어 전조 행위 가능성이 매우 높습니다.
- [medium-term] 클라우드 메타데이터 서비스(169.254.169.254)에 대한 워크스테이션 대역의 비인가 접근 시도가 누적되고 있어 정책 위반 탐지 정밀도를 유지해야 합니다.

## Top Attack Hypotheses
- [recent] 랜섬웨어 공격을 위한 내부 백업 데이터 무력화 및 탈취 시나리오
  - evidence: 일반 워크스테이션(10.60.100.65 등)에서의 백업 NAS SMB 접근(오프 윈도우) 및 백업 NAS의 외부 미인가 IP(198.51.100.123) 아웃바운드 연결 탐지
  - observable_conditions: 백업 NAS(10.60.40.12)로의 비인가 대역 SMB 연결, 백업 NAS의 외부 HTTPS/443 아웃바운드 세션 생성
  - negative_conditions: 공식 백업 윈도우(02:00-04:00) 내 허용된 관리자 단말(10.60.50.8) 또는 백업 소스에서의 정상 작동
  - confidence: high
  - review_condition: 정해진 백업 윈도우 외의 접근이거나 외부 연결 시 즉각 검토
- [recent] VPN 게이트웨이 무차별 대입 공격을 통한 초기 침투 시나리오
  - evidence: 알려진 위협 소스 IP(198.51.100.77)로부터의 지속적인 VPN(203.0.113.20:443) 접속 실패 및 패턴 발생
  - observable_conditions: 동일 외부 소스 IP에서의 다수 로그인 실패 또는 짧은 세션 주기 반복
  - negative_conditions: 임직원의 정상 근무 시간대 로그인 및 다요소 인증 성공
  - confidence: high
  - review_condition: 외부 위협 IP 목록 매칭 시 즉시 검토

## Repeated Patterns
- [recent] 외부 위협 IP 198.51.100.88에 의한 환자 포털 웹서버(203.0.113.10) 대상 PHP-CGI 취약점(CVE-2024-4577) 탐색성 스캔 행위 반복
- [medium-term] 내부 데이터베이스(10.60.30.20)에 대한 외부 비인가 소스(198.51.100.90)의 포트 스캔 및 직접 연결 시도

## Watchlist Feedback
- [recent] 이전 주기에서 설정된 외부 공격자 IP 기반 룰이 유효하게 매칭되어 VPN 브루트포스 및 DB 스캔을 정확하게 탐지함. 백업 NAS 비정상 아웃바운드 행위는 신규 위협 경로로 식별되어 이번 주기 룰 강화가 필요함.

## Next-Cycle Guidance
- maintain: 외부 악성 IP(198.51.100.0/24 대역 등)에 대한 차단 및 모니터링 상태 유지
- soften: 파트너 전용 SFTP 게이트웨이에 대한 정상 파트너 IP(198.51.100.180)의 허용 시간대 접속은 탐지 우회 적용
- strengthen: Day 3 예정된 Tomcat CVE 취약점(예약 API 및 테스트 랩 결과 API 대상)에 대비하여 해당 포트(HTTPS-alt, tomcat-http) 모니터링 준비