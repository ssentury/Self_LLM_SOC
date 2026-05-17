# Attack Surface Memory - 20260516T154330+0900

## Derived Attack Surface Changes
- [recent] **관리 평면 위험 급증**: 5일차에 FortiManager 취약점(CVE-2024-47575)이 추가됨에 따라 `10.60.50.30`(firewall-manager)의 TCP/541 및 HTTPS 노출이 가장 크리티컬한 공격 표면으로 부상함.
- [medium-term] **API 서비스 노출 지속**: Tomcat 기반 API(`203.0.113.30`, `10.60.20.30`)에 대한 경로 탐색 및 취약점(CVE-2025-24813) 공격 시도가 지속적으로 관찰됨.
- [medium-term] **퇴역 자산 잔류 트래픽**: `10.60.30.40`(reporting-warehouse)이 4일차에 퇴역했으나, 여전히 외부 및 내부 워크스테이션에서 접근 시도가 발생할 가능성이 있어 모니터링 필요.

## Top Attack Hypotheses
- [recent] **관리 평면 장악 및 C2 통신**: 외부 미승인 IP가 `10.60.50.30:541`로 접근하여 방화벽 설정을 탈취하거나, 해당 서버에서 외부로 HTTPS(C2) 통신을 시도할 수 있음.
  - evidence: CVE-2024-47575 취약점 권고 및 관리 평면 정책(P-MGMT).
  - observable_conditions: 미승인 소스의 TCP/541 접근, firewall-manager의 비정상적 외부 아웃바운드.
  - confidence: high
- [medium-term] **Tomcat API 악용 및 내부 침투**: CVE-2025-24813을 이용해 API 서버 권한을 획득한 후 내부 DB(`10.60.30.30`)로 횡적 이동 시도.
  - evidence: 192.0.2.210 등 알려진 스캐너의 API 포트(8443, 8080) 접근 이력.
  - confidence: high
- [medium-term] **랜섬웨어 준비 단계 (백업 변조)**: 워크스테이션에서 백업 윈도우 외 시간에 `10.60.40.12`(SMB)로 접근하여 백업 데이터를 삭제하거나 암호화 시도.
  - evidence: Tier 1 DB에서 관찰된 10.60.100.x 대역의 SMB 접근 알럿 이력.
  - confidence: medium

## Repeated Patterns
- [medium-term] **지속적 스캐닝**: `198.51.100.88`(Portal), `198.51.100.77`(VPN), `192.0.2.210`(API) 소스들이 특정 자산을 대상으로 반복적인 정찰 수행.
- [recent] **내부 오탐 패턴**: 의료진(doctor-workstations)의 정상적인 PACS/DICOM 접근이 업무 시간 내 빈번하게 발생함.

## Watchlist Feedback
- [recent] 이전 주기에서 `198.51.100.88` 및 `198.51.100.90`에 대한 탐지가 유효했으므로, 해당 소스들에 대한 우선순위 유지.

## Next-Cycle Guidance
- maintain: 관리 평면(TCP/541) 및 API(8080/8443) 감시 강화.
- soften: 업무 시간 내 인가된 의료진의 PACS 접근에 대한 경계 완화.
- strengthen: 퇴역 자산(`10.60.30.40`)으로의 모든 접근에 대한 검토 강도 상향.