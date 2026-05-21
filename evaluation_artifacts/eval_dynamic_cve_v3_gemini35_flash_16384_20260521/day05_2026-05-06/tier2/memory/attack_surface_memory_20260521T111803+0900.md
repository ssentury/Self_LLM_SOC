# Attack Surface Memory - 20260521T111803+0900

## Derived Attack Surface Changes
- [recent] Day 5에 신규 추가된 FortiManager 취약점(CVE-2024-47575)으로 인해 방화벽 관리자(10.60.50.30)의 관리 평면(TCP/541) 및 HTTPS 공격 표면이 급격히 증가하였습니다. 승인되지 않은 외부/내부 자산의 접근을 철저히 차단해야 합니다.
- [recent] Day 4에 은퇴한 Reporting Warehouse(10.60.30.40)는 공식적으로 사용이 중단되었으나, 잔여 트래픽이나 정찰 스캔 목적의 접근이 지속될 수 있으므로 지속 관찰이 필요합니다.
- [medium-term] Tomcat 기반의 Lab Results API(10.60.20.30) 및 Appointment API(203.0.113.30)는 CVE-2025-24813 취약점에 계속 노출되어 있어 악성 외부 스캐너의 집중 타겟이 되고 있습니다.

## Top Attack Hypotheses
- [recent] 가설 1: FortiManager 취약점(CVE-2024-47575)을 악용한 무인증 관리 평면 장악 및 외부 악성 C2로의 데이터 유출 시도.
  - evidence: Day 5 신규 FortiManager 취약점 권고 및 방화벽 관리자(10.60.50.30) 자산의 노출.
  - observable_conditions: 비인가 소스(10.60.50.8, 10.60.60.20 이외)가 10.60.50.30의 TCP/541 포트로 접근을 시도하거나, 해당 자산이 외부 미확인 IP로 대용량 HTTPS 연결을 생성하는 경우.
  - negative_conditions: 승인된 관리 점프박스(10.60.50.8) 또는 모니터링 시스템(10.60.60.20)이 유지보수 시간대(01:00-05:00) 내에 접근하는 경우.
  - confidence: High
  - review_condition: 비인가 자산에서 10.60.50.30:541 접근 발생 시 즉시 검토.
- [medium-term] 가설 2: Tomcat 취약점(CVE-2025-24813)을 이용한 API 서버 침투 및 내부망 정찰 활동.
  - evidence: 알려진 악성 IP인 198.51.100.90 및 198.51.100.91에 의한 Appointment API(203.0.113.30) 대상 8443 포트 탐색 이력.
  - observable_conditions: 외부 미확인 IP가 203.0.113.30 혹은 10.60.20.30의 8080/8443 포트로 비정상적인 요청을 지속적으로 전송하거나, 해당 자산이 외부로 비정상 아웃바운드 연결을 수립하는 행위.
  - negative_conditions: 클리닉 워크스테이션이 업무 시간(08:00-19:00) 내에 내부망 Lab Results API(10.60.20.30)에 정상 접근하는 행위.
  - confidence: High
  - review_condition: 외부 IP의 8080/8443 접근 및 취약점 대상 자산의 아웃바운드 시도 시 검토.
- [medium-term] 가설 3: 내부 감염된 워크스테이션을 통한 백업 스토리지(10.60.40.12) 변조 및 랜섬웨어 유포 사전 Staging.
  - evidence: 일부 내부 워크스테이션(10.60.100.72 등)에서 백업 NAS로의 비정상 SMB(445) 연결 시도 및 백업 NAS의 외부 비정상 IP(198.51.100.123) 연결 이력.
  - observable_conditions: 일반 클리닉 워크스테이션 대역에서 백업 유지보수 시간 외에 백업 NAS로 SMB 연결을 시도하는 경우.
  - negative_conditions: 승인된 관리자 자산 또는 백업 복제 게이트웨이가 허용된 시간대(02:00-04:00)에 접근하는 경우.
  - confidence: Critical
  - review_condition: 비인가 대역의 10.60.40.12:445 접근 발견 시 검토.

## Repeated Patterns
- [medium-term] 외부 악성 소스(198.51.100.77)가 VPN 게이트웨이(203.0.113.20:443)를 대상으로 무차별 대입 공격(Brute-force)을 반복 수행하는 패턴이 지속 관찰됨.
- [medium-term] 외부 스캐너(198.51.100.88)에 의한 환자 포털(203.0.113.10) 대상 PHP-CGI RCE(CVE-2024-4577) 스캔 패턴 반복.
- [medium-term] 내부 일부 워크스테이션에서 로컬 메타데이터 주소(169.254.169.254)로의 비정상 HTTP 연결 시도 지속 관찰.

## Watchlist Feedback
- [recent] 이전 주기에서 설정된 백업 자산의 비정상 외부 통신 및 Tomcat API 스캔에 대한 탐지 룰이 유효하게 작동하여 다수의 얼럿을 식별함. 이번 주기에는 신규 추가된 FortiManager 관리 평면 타겟 위협에 모니터링 역량을 집중해야 함.

## Next-Cycle Guidance
- maintain: VPN 게이트웨이 무차별 대입 공격 및 내부 자산의 IMDS(169.254.169.254) 접근 시도 모니터링 유지.
- soften: 은퇴 자산(10.60.30.40)으로의 일회성 잔여 트래픽은 단순 스캔으로 판단 시 에스컬레이션 우선순위 하향 조정.
- strengthen: FortiManager(10.60.50.30:541)에 대한 비인가 접근 시도 탐지 룰 강화 및 엄격한 에스컬레이션 기준 적용.