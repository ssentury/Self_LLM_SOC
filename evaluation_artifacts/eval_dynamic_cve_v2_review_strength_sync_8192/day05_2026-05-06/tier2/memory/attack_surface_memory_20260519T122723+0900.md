# Attack Surface Memory - 20260519T122723+0900

## Derived Attack Surface Changes
- [recent] **FortiManager 취약점 노출**: CVE-2024-47575가 추가됨에 따라 `firewall-manager`(10.60.50.30)의 TCP/541(FGFMD) 포트가 새로운 핵심 공격 표면으로 부상함.
- [medium-term] **Tomcat API 지속 위협**: CVE-2025-24813과 관련하여 `lab-results-api`(10.60.20.30) 및 `appointment-api`(203.0.113.30)에 대한 스캔 시도가 지속적으로 관찰됨.
- [medium-term] **자산 상태 변경**: `reporting-warehouse`(10.60.30.40)가 Day 4부로 퇴역(Retired) 처리됨. 이 자산으로 향하는 잔류 트래픽은 스캔 또는 설정 오류 가능성이 높음.
- [long-term] **백업 인프라 보호**: `backup-nas`(10.60.40.12)에 대한 비인가 SMB 접근 및 외부 통신은 랜섬웨어 전조 현상으로 간주하여 고강도 모니터링 유지.

## Top Attack Hypotheses
- [recent] **Firewall Management Plane 탈취**: 공격자가 인증되지 않은 상태로 TCP/541을 통해 방화벽 설정에 접근하거나 데이터를 탈취하려 함.
  - evidence: CVE-2024-47575 공지 및 관련 포트(541) 정책 정의.
  - observable_conditions: 관리자 점프박스 이외의 소스에서 10.60.50.30:541 접근 시도.
  - confidence: high
  - review_condition: 비인가 IP의 포트 541 접속 성공 또는 시도.
- [medium-term] **Tomcat Path Equivalence 공격**: 외부 스캐너가 특수 제작된 경로를 통해 API 서버의 파일에 접근하거나 PUT 명령을 시도함.
  - evidence: 198.51.100.91 등 알려진 Tomcat 스캐너 활동.
  - observable_conditions: 8080/8443 포트에 대한 반복적 접근 및 이후 해당 서버의 이상 외부 통신.
  - confidence: medium

## Repeated Patterns
- [recent] **알려진 위협 소스 반복 활동**: 198.51.100.88(PHP-CGI 스캐너)과 198.51.100.77(VPN 브루트포스)이 지속적으로 탐지 및 차단되고 있음.
- [medium-term] **DNS 터널링 의심**: 다수의 워크스테이션에서 외부 DNS(8.8.8.8 등)로 향하는 비정상적 볼륨의 쿼리가 반복됨.

## Watchlist Feedback
- [recent] 198.51.100.88 및 198.51.100.77 매칭률이 매우 높음. 해당 소스들에 대한 자동 차단 수준의 우선순위 유지 필요.
- [medium-term] 클라우드 메타데이터(169.254.169.254) 접근 시도가 실제 워크스테이션에서 발생하여 경보가 유효함을 확인.

## Next-Cycle Guidance
- maintain: 외부 접점 서비스(Portal, VPN, API)에 대한 알려진 위협 소스 차단.
- soften: 의료진 워크스테이션의 정상 PACS 접근에 대한 오탐 주의.
- strengthen: 퇴역 자산(10.60.30.40) 및 방화벽 관리 평면(TCP/541)에 대한 감시 강화.