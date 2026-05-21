# Attack Surface Memory - 20260521T110311+0900

## Derived Attack Surface Changes
- [recent] 원격 의료 플랫폼인 한빛 케어 네트워크는 외부 노출 자산(환자 포털, VPN 게이트웨이)과 내부 자산(EHR API, 백업 NAS, 빌링 DB) 간의 경계 보호가 최우선 과제임.
- [recent] 최근 위협 인텔리전스에 따르면 의료 부문을 겨냥한 VPN 패스워드 스프레이 및 랜섬웨어 사전 단계인 백업 변조 행위가 증가하고 있어 이에 대한 집중 모니터링이 필요함.
- [medium-term] 내부 워크스테이션 영역(`10.42.100.0/24`)에서 백업 NAS(`10.42.40.12`)로의 비인가 SMB 접근 및 클라우드 메타데이터 서비스(`169.254.169.254`) 호출 시도가 주요 탐지 지표로 부각됨.

## Top Attack Hypotheses
- [recent] VPN 게이트웨이 무단 침투 및 초기 침투 시도
  - evidence: 외부 위협 IP(`198.51.100.77`)의 VPN 무차별 대입 공격 이력 및 Citrix RCE(CVE-2023-3519) 취약점 존재 가능성.
  - observable_conditions: 동일 외부 IP에서 `203.0.113.20:443`으로의 반복적인 연결 실패 또는 소량의 패킷 교환.
  - negative_conditions: 정상적인 비즈니스 시간대 내의 성공적인 VPN 로그인 및 다요소 인증 완료.
  - confidence: high
  - review_condition: 외부 미식별 대역에서 다수의 로그인 실패 발생 시 즉시 검토.
- [recent] PHP-CGI 취약점을 악용한 환자 포털 RCE 시도
  - evidence: CVE-2024-4577 취약점 정보 및 알려진 웹 스캐너 IP(`198.51.100.88`, `192.0.2.210`)의 활동.
  - observable_conditions: `203.0.113.10` 포털을 대상으로 한 비정상적인 HTTP 파라미터 전송 및 스캐닝 패턴.
  - negative_conditions: 정상적인 환자 예약 및 포털 조회 트래픽.
  - confidence: medium
  - review_condition: 알려진 스캐너 IP가 포털 웹 서버에 접근할 경우.
- [medium-term] 랜섬웨어 배포 전 단계의 백업 NAS 변조 및 무단 접근
  - evidence: 클리닉 워크스테이션 대역에서 백업 시간대 외에 백업 NAS로의 SMB 접근 정책 위반 우려.
  - observable_conditions: `10.42.100.0/24` 대역에서 백업 NAS(`10.42.40.12:445`)로 백업 윈도우(02:00-04:00) 외의 시간대에 대량의 파일 접근 시도.
  - negative_conditions: 지정된 관리자 호스트(`10.42.50.8`) 또는 백업 서버(`10.42.40.10`)의 정상 백업 수행.
  - confidence: high
  - review_condition: 백업 시간 외의 워크스테이션발 SMB 연결 발생 시.

## Repeated Patterns
- [recent] 외부 위협 소스(`198.51.100.90`)에 의한 내부 빌링 데이터베이스(`10.42.30.25`) 직접 스캐닝 시도 가능성 경고.

## Watchlist Feedback
- [recent] 이번 사이클에서 최초 수립된 감시 목록으로, 향후 탐지 이벤트를 기반으로 임계치 및 오탐 요소를 튜닝 예정.

## Next-Cycle Guidance
- maintain: 외부 노출 자산(Portal, VPN)에 대한 알려진 위협 IP 차단 상태 및 스캔 패턴 모니터링 유지.
- strengthen: 백업 NAS 및 클라우드 메타데이터 접근 통제 정책 위반 흐름에 대한 탐지 룰 강화.