# Attack Surface Memory - 20260516T154137+0900

## Derived Attack Surface Changes
- [recent] **자산 상태 변경**: Reporting Warehouse(10.60.30.40)가 Day 4부로 'Retired' 상태로 변경되었습니다. 이 자산으로 유입되는 모든 반복적 트래픽은 스캔 또는 잔류 공격 시도로 간주해야 합니다.
- [medium-term] **Tomcat 취약점 노출 지속**: CVE-2025-24813 취약점이 적용된 Lab-results(10.60.20.30) 및 Appointment API(203.0.113.30)가 외부 및 내부 위협 노출의 중심입니다.
- [long-term] **DMZ 접점 관리**: 환자 포털(PHP-CGI)과 VPN 게이트웨이는 상시적인 무단 로그인 시도와 익스플로잇 스캔의 주 대상입니다.

## Top Attack Hypotheses
- [recent] **Tomcat 취약점 악용 시도**
  - evidence: 198.51.100.91, 192.0.2.210 등 다수의 외부 IP가 8080/8443 포트를 타겟팅하는 패턴 확인.
  - observable_conditions: 외부 IP 또는 비인가 내부 호스트가 10.60.20.30, 203.0.113.30의 8080/8443 포트로 반복 접속.
  - negative_conditions: 업무 시간 내 클리닉 워크스테이션의 정상적인 API 호출.
  - confidence: high
  - review_condition: 동일 외부 소스가 여러 API 자산을 순차적으로 접근할 때.

- [recent] **랜섬웨어 준비 단계 (백업 변조)**
  - evidence: 10.60.100.x 대역 워크스테이션에서 백업 NAS(10.60.40.12)로의 비정상 SMB 접근 이력.
  - observable_conditions: 백업 윈도우(02:00-04:00) 외 시간에 일반 워크스테이션의 SMB(445) 접근.
  - confidence: medium
  - review_condition: 특정 워크스테이션이 대량의 파일을 백업 서버로 전송하거나 삭제 시도 시.

## Repeated Patterns
- [medium-term] **고정 위협 소스**: 198.51.100.88(PHP-CGI 스캔), 198.51.100.77(VPN 브루트포스), 198.51.100.90(DB 스캔) 등 특정 위협 소스의 반복적 활동이 관찰됨.

## Watchlist Feedback
- [recent] Tier 1 DB 검토 결과, 198.51.100.90의 DB 스캔 및 192.0.2.210의 Tomcat API 스캔에 대한 탐지가 정확하게 이루어지고 있음.

## Next-Cycle Guidance
- maintain: 외부 접점 서비스(VPN, Portal, API)에 대한 스캔 모니터링 강화.
- strengthen: 은퇴 자산(10.60.30.40)에 대한 접근 차단 여부 및 로그 감시 강화.