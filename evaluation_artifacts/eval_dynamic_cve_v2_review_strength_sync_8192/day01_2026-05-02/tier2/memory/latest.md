# Attack Surface Memory - 20260519T120534+0900

## Derived Attack Surface Changes
- [long-term] **DMZ 노출 자산**: 환자 포털(203.0.113.10)과 VPN 게이트웨이(203.0.113.20)가 외부 공격의 1차 접점임. 특히 PHP-CGI 및 Citrix 관련 CVE 영향권에 있어 지속적인 모니터링 필요.
- [long-term] **내부 핵심 데이터**: EHR(10.60.20.15) 및 PACS(10.60.35.10) 시스템은 민감한 환자 정보를 포함하고 있어 내부 횡적 이동의 주요 목표가 될 가능성이 높음.
- [long-term] **관리 평면 분리**: 방화벽 관리자(10.60.50.30) 및 EDR 관리 콘솔은 일반 워크스테이션 구역과 엄격히 분리되어야 함.

## Top Attack Hypotheses
- [recent] **VPN 게이트웨이 초기 침투 (CVE-2023-3519)**
  - evidence: 위협 피드 내 VPN 무차별 대입 IP(198.51.100.77) 존재 및 관련 CVE 취약 자산 식별.
  - observable_conditions: 외부 IP로부터 203.0.113.20:443으로의 반복적 연결 실패 또는 비정상적인 요청 크기.
  - negative_conditions: 인가된 직원의 정상적인 VPN 로그인 및 세션 유지.
  - confidence: medium
  - review_condition: 동일 외부 IP에서 5회 이상의 로그인 실패 발생 시.

- [recent] **환자 포털 RCE 및 데이터 유출 (CVE-2024-4577)**
  - evidence: PHP-CGI 인젝션 취약점(CVE-2024-4577) 및 관련 스캐너 IP(198.51.100.88) 존재.
  - observable_conditions: 203.0.113.10에 대한 exploit 형태의 HTTP 파라미터 포함 요청.
  - negative_conditions: 정상적인 환자 예약 및 결과 조회 트래픽.
  - confidence: medium
  - review_condition: 알려진 악성 IP의 접근 또는 HTTP 4xx/5xx 에러 급증 시.

- [recent] **랜섬웨어 전조: 백업 시스템 변조**
  - evidence: 의료 네트워크 타겟 랜섬웨어 시나리오 및 백업 NAS(10.60.40.12) 노출.
  - observable_conditions: 백업 윈도우(02:00-04:00) 외 시간에 일반 워크스테이션에서 백업 NAS로의 SMB 접근.
  - negative_conditions: 관리자 점프박스(10.60.50.8)를 통한 정기 점검.
  - confidence: low
  - review_condition: 비인가 소스에서의 SMB Write 시도 발생 시.

## Repeated Patterns
- [recent] 현재 cycle 1(Day 1)로 반복 패턴은 아직 관찰되지 않음.

## Watchlist Feedback
- [recent] 초기 베이스라인 설정 단계로 피드백 없음.

## Next-Cycle Guidance
- maintain: DMZ 자산에 대한 외부 스캔 및 취약점 공격 모니터링 유지.
- strengthen: Day 3 예정된 Tomcat CVE(lab-results-api 관련)에 대비한 내부 API 트래픽 감시 강화 준비.