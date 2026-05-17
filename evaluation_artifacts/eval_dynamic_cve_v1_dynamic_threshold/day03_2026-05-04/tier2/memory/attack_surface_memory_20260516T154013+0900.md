# Attack Surface Memory - 20260516T154013+0900

## Derived Attack Surface Changes
- [recent] **Apache Tomcat 취약점 노출 (CVE-2025-24813)**: Day 3 신규 자산 정보에 따라 Lab-Results API(10.60.20.30) 및 Appointment API(203.0.113.30)의 위험도가 급증함. 특히 포트 8080, 8443을 통한 비정상 접근 주의 필요.
- [medium-term] **DMZ 자산 표적 공격 지속**: Patient Portal(203.0.113.10) 및 VPN Gateway(203.0.113.20)에 대해 알려진 위협 IP(198.51.100.88, 198.51.100.77)의 스캐닝 및 브루트포스 활동이 Tier 1 이력에서 확인됨.
- [long-term] **내부 자산 가시성 및 보호**: 의료 데이터(EHR, PACS) 및 백업(NAS) 시스템은 랜섬웨어의 주요 타겟임. 특히 비업무 시간대나 허용되지 않은 워크스테이션에서의 접근은 고위험으로 간주.

## Top Attack Hypotheses
- [recent] **Tomcat 취약점 기반 초기 침투 및 명령 실행**
  - evidence: CVE-2025-24813 영향 자산 확인 및 외부 위협 IP의 웹 스캐닝 이력.
  - observable_conditions: 외부 IP가 203.0.113.30:8443에 반복 접속하거나, 내부 10.60.20.30에서 외부로의 비정상 HTTPS 아웃바운드 발생.
  - negative_conditions: 클리닉 워크스테이션(10.60.100.x)의 정상적인 Lab 결과 조회 트래픽.
  - confidence: High
  - review_condition: 외부 소스로부터의 8080/8443 접근 시 즉시 검토.

- [medium-term] **백업 데이터 탈취 및 변조 (랜섬웨어 전조)**
  - evidence: Tier 1 DB에서 워크스테이션(10.60.100.72 등)이 백업 NAS(10.60.40.12)에 SMB 접근한 이력 탐지.
  - observable_conditions: 백업 윈도우(02:00-04:00) 외 시간대에 일반 워크스테이션의 SMB(445) 접속.
  - confidence: Medium

## Repeated Patterns
- [recent] **198.51.100.88**: Patient Portal 대상 PHP-CGI 취약점(CVE-2024-4577) 스캐닝 반복.
- [recent] **198.51.100.77**: VPN Gateway 대상 반복적 로그인 실패 유발.
- [recent] **198.51.100.90**: 내부 DB 및 API 자산 대상 직접적인 포트 스캐닝.

## Watchlist Feedback
- [recent] 이전 주기에서 198.51.100.88 및 .90에 대한 탐지가 성공적으로 Alert 처리됨을 확인. 해당 IP들에 대한 우선순위 유지.

## Next-Cycle Guidance
- maintain: 외부 접점 자산(DMZ)에 대한 취약점 스캐닝 감시 강화.
- strengthen: Tomcat CVE 영향을 받는 내부 API(10.60.20.30)에 대한 횡적 이동 감시 강화.