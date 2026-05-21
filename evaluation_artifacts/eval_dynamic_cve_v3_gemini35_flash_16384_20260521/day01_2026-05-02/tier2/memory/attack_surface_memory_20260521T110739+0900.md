# Attack Surface Memory - 20260521T110739+0900

## Derived Attack Surface Changes
- [recent] Day 1 초기 분석 결과, 외부 노출 자산의 주요 취약점 노출 상태가 식별되었습니다. 특히 환자 포털(203.0.113.10)의 PHP-CGI 취약점(CVE-2024-4577) 및 VPN 게이트웨이(203.0.113.20)의 Citrix 취약점(CVE-2023-3519)이 주요 외부 공격 표면입니다.
- [recent] 내부망에서는 백업 NAS(10.60.40.12) 및 PACS 이미지 아카이브(10.60.35.10)가 랜섬웨어 및 비인가 접근의 표적이 될 가능성이 큽니다.

## Top Attack Hypotheses
- [recent] PHP-CGI 인자 주입을 통한 환자 포털 원격 코드 실행(RCE) 시도
  - evidence: CVE-2024-4577 취약점 정보 및 알려진 스캐너 IP(198.51.100.88)
  - observable_conditions: 외부 IP가 203.0.113.10의 80/443 포트로 비정상적인 HTTP 요청 전송
  - negative_conditions: 정상적인 포털 웹 브라우징 트래픽
  - confidence: high
  - review_condition: 알려진 악성 IP 매칭 혹은 웹 스캔 패턴 발생 시
- [recent] VPN 게이트웨이 무차별 대입 및 RCE 시도
  - evidence: CVE-2023-3519 및 위협 피드의 VPN 무차별 대입 IP(198.51.100.77)
  - observable_conditions: 동일 외부 IP에서 203.0.113.20:443으로의 잦은 실패 연결
  - negative_conditions: 정상적인 원격 사용자의 1회성 로그인 성공
  - confidence: high
  - review_condition: 198.51.100.77의 접근 또는 비정상적인 세션 크기 반복
- [recent] 백업 시스템 변조를 통한 랜섬웨어 사전 준비
  - evidence: 위협 피드 내 랜섬웨어 선행 행위 정의 및 P-MGMT 정책
  - observable_conditions: 일반 워크스테이션 대역에서 백업 NAS(10.60.40.12)로의 야간 백업 시간 외 SMB(445) 연결
  - negative_conditions: 지정된 백업 소스(10.60.40.10, 10.60.50.8)의 백업 시간대(02:00-04:00) 내 접근
  - confidence: medium
  - review_condition: 비인가 시간대/비인가 IP의 백업 NAS 접근 시

## Repeated Patterns
- [recent] Day 1 기준 수집된 반복 탐지 이력은 아직 없으나, 위협 피드에 등재된 스캐너 IP(198.51.100.77, 198.51.100.88, 198.51.100.90, 192.0.2.210)의 접근 가능성을 상시 예의주시해야 합니다.

## Watchlist Feedback
- [recent] Day 1 초기 수립 단계로 이전 피드백 데이터가 존재하지 않습니다. 본 룰셋의 탐지 효율성은 다음 사이클에서 검증 예정입니다.

## Next-Cycle Guidance
- maintain: 외부 노출 자산(포털, VPN) 대상의 취약점 프로빙 모니터링을 유지합니다.
- strengthen: 비인가 내부 자산 간의 횡적 이동(특히 DB 직접 접근 및 백업망 접근) 통제를 강화합니다.