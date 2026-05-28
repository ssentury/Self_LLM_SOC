# Attack Surface Memory - 20260527T150856+0900

## Derived Attack Surface Changes
- [long-term] 외부 노출된 환자 포털(203.0.113.10) 및 VPN 게이트웨이(203.0.113.20)는 지속적인 침투 표적이며, 내부 자산으로 진입하기 위한 1차 관문임.
- [recent] Day 1 시점 기준, PHP-CGI 취약점(CVE-2024-4577) 및 Citrix Gateway 취약점(CVE-2023-3519)의 영향을 받는 공개 자산들이 식별되어 공격 노출도가 상승함.
- [long-term] 내부의 핵심 임상 데이터(EHR, PACS) 및 백업 자산(10.60.40.12)은 랜섬웨어 타깃 경로에 해당하므로, 비인가 경로 및 비영업시간 접근 통제 정책의 중요성이 매우 높음.

## Top Attack Hypotheses
- [recent] 외부 위협 소스의 VPN 무차별 대입 및 원격 코드 실행(RCE) 시도
  - evidence: 위협 피드 내 외부 악성 IP(198.51.100.77, vpn-bruteforce) 및 Citrix ADC/Gateway 취약점(CVE-2023-3519) 연계 정황.
  - observable_conditions: dst_ip가 203.0.113.20이고 외부 소스로부터 세션 수립 실패가 누적되거나 악성 IP가 유입되는 정황.
  - negative_conditions: 정상 원격 근무자의 비즈니스 시간 내 단발성 로그인 성공.
  - confidence: high
  - review_condition: 동일 외부 소스 IP에서 반복적인 로그인 시도 또는 취약점 스캔 패턴 발견 시.
- [recent] 환자 포털 대상 PHP-CGI 인수 주입 취약점(CVE-2024-4577) RCE 공격
  - evidence: 포털 자산(203.0.113.10)의 PHP-CGI 취약점 영향 가능성 및 피드 내 웹 취약점 스캐너 IP(198.51.100.88, 192.0.2.210) 식별.
  - observable_conditions: 스캐너 IP에서 포털 웹 서비스(80/443)로 유입되는 비정상 파라미터나 스캔 요청.
  - negative_conditions: 일반 사용자의 정상적인 환자 포털 웹 서핑 및 예약 API 요청.
  - confidence: medium
  - review_condition: 스캐너 IP 매칭 혹은 웹 로그 상의 특이 인젝션 패턴 탐지 시.

## Repeated Patterns
- [long-term] 랜섬웨어 공격자가 초기 침투 후 내부 정찰을 통해 백업 자산(10.60.40.12)을 파괴하거나, 클라우드 자격증명 탈취를 위해 IMDS(169.254.169.254) 조회를 시도하는 행위 주의.

## Watchlist Feedback
- [recent] Day 1 최초 분석 주기로 이전 피드백 이력 없음.

## Next-Cycle Guidance
- maintain: 외부 노출 자산(포털, VPN)에 대한 취약점 악용 시도 집중 모니터링 유지.
- soften: 정상적인 임상 목적의 PACS/DICOM 조회 트래픽에 대한 과도한 경보 생성 방지.
- strengthen: 위협 피드에 등재된 고위험 IP 목록 기반의 탐지 룰 적용 강화.