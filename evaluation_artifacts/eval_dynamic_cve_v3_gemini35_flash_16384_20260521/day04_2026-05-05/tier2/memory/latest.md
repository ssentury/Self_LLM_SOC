# Attack Surface Memory - 20260521T111455+0900

## Derived Attack Surface Changes
- [recent] **자산 은퇴 및 변경**: Day 4 기준 보고서 웨어하우스(`10.60.30.40`) 자산이 은퇴(Retired) 처리되었습니다. 이 자산으로 향하는 잔여 스캔성 트래픽은 주의 깊게 검토해야 하지만 단순 일회성 유입은 오탐 방지를 위해 걸러내야 합니다.
- [recent] **Tomcat 취약점 노출**: Tomcat 기반의 예약 API(`203.0.113.30`) 및 실험실 결과 API(`10.60.20.30`)를 대상으로 한 CVE-2025-24813 취약점 탐색 정황이 포착되고 있어 감시 강화가 필요합니다.
- [medium-term] **랜섬웨어 선행 행위 지속**: 내부 워크스테이션에서 백업 NAS(`10.60.40.12`)로의 비인가 시간대 SMB 접근 및 백업 NAS의 외부 비정상 아웃바운드 연결 시도가 반복 관찰되어 심각한 위협으로 분류됩니다.

## Top Attack Hypotheses
- [recent] **Tomcat 취약점(CVE-2025-24813) 악용 내부 침투 가설**
  - evidence: 외부 위협 IP(`198.51.100.90`, `198.51.100.91`)가 Tomcat 포트인 8080/8443을 대상으로 지속 탐색 수행.
  - observable_conditions: 외부 미승인 대역에서 Tomcat 자산의 8080/8443 포트 접속 후 해당 자산에서 외부로 비정상 HTTPS 아웃바운드 연결 수립.
  - negative_conditions: 업무 시간 중 인가된 내부 클리닉 워크스테이션의 정상적인 API 호출.
  - confidence: High
  - review_condition: 외부 비인가 IP가 Tomcat 포트에 접근하거나 성공 후 외부 세션 수립을 시도할 때.
- [recent] **은퇴 자산(Reporting Warehouse) 비인가 스캔 가설**
  - evidence: Day 4 은퇴 이후에도 내부 워크스테이션 또는 외부 위협 소스로부터 포스트그레스 포트(5432) 접근 시도 가능성 존재.
  - observable_conditions: 외부 또는 내부 비인가 자산이 `10.60.30.40:5432`로 반복적으로 세션 수립을 시도하는 정황.
  - negative_conditions: 이전에 권한이 있던 내부 재무 호스트에서의 단순 일회성 잔여 세션 유입.
  - confidence: Medium
  - review_condition: 은퇴한 데이터베이스 자산으로 반복적인 스캔성 접속 시도가 발생할 때.
- [medium-term] **백업 타겟 템퍼링 및 자료 유출 가설**
  - evidence: 워크스테이션 대역에서 백업 NAS(`10.60.40.12`)로의 비인가 SMB 접근 및 백업 NAS에서 외부 IP(`198.51.100.123`)로의 대량 전송 이력 존재.
  - observable_conditions: 공식 백업 시간 외에 일반 임직원 PC가 `10.60.40.12:445`에 접속하거나 백업 자산이 외부로 세션을 개시하는 행위.
  - negative_conditions: 공식 백업 윈도우(02:00-04:00) 내 승인된 소스(`10.60.40.10`, `10.60.50.8`)에서의 통신.
  - confidence: Critical
  - review_condition: 비인가 소스의 백업 NAS 접근 혹은 백업 NAS의 외부 아웃바운드 세션 생성 시.

## Repeated Patterns
- [medium-term] 외부 위협 IP(`198.51.100.77`)의 VPN 게이트웨이 대상 무차별 대입 공격.
- [medium-term] 내부 특정 워크스테이션의 외부 DNS 터널링(`8.8.8.8:53`) 및 링크 로컬 메타데이터 IP(`169.254.169.254`) 직접 접근 시도.

## Watchlist Feedback
- [recent] 설정된 Tomcat 취약점 탐색 및 백업 자산 비인가 접근 감시 워치리스트가 실제 침해 정황 탐지에 기여하여 유효성이 증명됨.

## Next-Cycle Guidance
- maintain: Tomcat 취약점 및 백업 NAS 비인가 SMB 접근 감시 유지.
- soften: 단순 포털 웹 접근에 대한 오경보 방지를 위해 정상 유저 웹 패턴의 필터링 완화.
- strengthen: 은퇴 자산(`10.60.30.40`) 대응 룰 보강 및 다음 주기 예정된 FortiManager 관련 감시 설계 준비.