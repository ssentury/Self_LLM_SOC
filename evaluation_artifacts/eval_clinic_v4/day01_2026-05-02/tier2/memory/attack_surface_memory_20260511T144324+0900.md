# Attack Surface Memory - 20260511T144324+0900

## Derived Attack Surface Changes
- [long-term] 한빛 케어 네트워크는 소규모 텔레헬스 서비스 제공자로, 환자 포털(203.0.113.10)과 VPN 게이트웨이(203.0.113.20)가 주요 외부 노출 접점임.
- [long-term] 내부 자산 중 빌링 DB(10.42.30.25)와 백업 NAS(10.42.40.12)는 랜섬웨어 및 데이터 유출의 핵심 타겟으로 분류됨.
- [recent] CVE-2024-4577(PHP-CGI) 및 CVE-2023-3519(VPN RCE) 취약점이 외부 노출 서비스에 직접적인 위협이 됨.

## Top Attack Hypotheses
- [recent] VPN 초기 침투 및 자격 증명 탈취
  - evidence: 위협 피드 내 VPN 브루트포스 IP(198.51.100.77) 존재 및 관련 정책(P-VPN-FAIL).
  - observable_conditions: 동일 외부 소스의 반복적 VPN 접속 시도, 비정상적 소스 IP.
  - negative_conditions: 승인된 사용자의 정상적인 업무 시간 내 접속.
  - confidence: high
  - review_condition: 동일 소스 IP에서 5회 이상의 접속 실패 발생 시.

- [recent] 환자 포털을 통한 RCE 및 초기 거점 확보
  - evidence: CVE-2024-4577 취약점 및 PHP-CGI 스캐너 IP(198.51.100.88).
  - observable_conditions: HTTP/HTTPS 요청 내 특수 인자 주입 시도, 알려진 스캐너 IP의 접근.
  - negative_conditions: 일반적인 환자 예약 및 포털 이용 트래픽.
  - confidence: medium
  - review_condition: 알려진 악성 IP의 접근 또는 비정상적인 URI 패턴 탐지 시.

- [medium-term] 백업 데이터 변조를 통한 랜섬웨어 준비
  - evidence: 정책상 백업 윈도우(02:00-04:00) 외 접근 금지 및 NAS 자산 중요도.
  - observable_conditions: 워크스테이션(10.42.100.0/24)에서 NAS(10.42.40.12)로의 SMB 접근.
  - negative_conditions: 지정된 백업 서버 또는 관리자 호스트의 정기 백업 활동.
  - confidence: high
  - review_condition: 백업 윈도우 외의 시간대에 워크스테이션에서 발생하는 SMB 트래픽.

## Repeated Patterns
- [recent] 현재 첫 번째 분석 사이클로, 이전 반복 패턴 데이터 없음. 위협 피드 기반의 스캐닝 활동 주시 필요.

## Watchlist Feedback
- [recent] 신규 생성된 Watchlist 항목들에 대한 매칭 결과 모니터링 예정.

## Next-Cycle Guidance
- maintain: 외부 노출 자산(포털, VPN)에 대한 엄격한 모니터링 유지.
- strengthen: 빌링 DB 및 백업 NAS에 대한 내부 횡적 이동 탐지 강화.
- soften: 정상적인 백업 윈도우 내의 관리자 활동에 대한 오탐 주의.