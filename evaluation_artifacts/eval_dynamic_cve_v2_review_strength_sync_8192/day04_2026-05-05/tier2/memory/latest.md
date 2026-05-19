# Attack Surface Memory - 20260519T122109+0900

## Derived Attack Surface Changes
- [recent] **10.60.30.40 (Reporting Warehouse) 사용 중단**: Day 4 기준 이 자산은 Retired 상태로 변경됨. 이후 발생하는 모든 트래픽은 스캔 또는 잔류 설정 오류로 간주하며, 반복 발생 시 조사 필요.
- [medium-term] **Tomcat CVE-2025-24813 노출 지속**: Lab API(10.60.20.30) 및 Appointment API(203.0.113.30)가 여전히 취약한 상태이며, 위협 피드에서 관련 스캐너 활동(198.51.100.91)이 식별됨.
- [long-term] **공공 대면 자산 집중 공격**: Patient Portal(203.0.113.10) 및 VPN Gateway(203.0.113.20)는 지속적인 브루트포스 및 웹 스캔의 주요 타겟임.

## Top Attack Hypotheses
- [recent] **내부 자산을 통한 클라우드 권한 탈취 시도**
  - evidence: Tier 1 DB에서 워크스테이션(10.60.100.42)의 169.254.169.254(IMDS) 접속 이력 확인.
  - observable_conditions: 내부 호스트가 목적지 포트 80으로 IMDS IP에 접속.
  - negative_conditions: 클라우드 관리 도구의 정기적인 업데이트 통신.
  - confidence: high
  - review_condition: 동일 소스에서 반복적으로 발생하거나 성공 응답(200 OK 수준의 페이로드 크기) 확인 시.

- [medium-term] **랜섬웨어 준비를 위한 백업 시스템 변조**
  - evidence: 워크스테이션(10.60.100.72 등)에서 백업 NAS(10.60.40.12)로의 비정상 시간대 SMB 접속 알람 발생.
  - observable_conditions: maintenance_window(02:00-04:00) 이외 시간의 SMB(445) 트래픽.
  - confidence: medium
  - review_condition: 다수의 파일 접근 또는 대용량 데이터 전송 패턴 식별 시.

## Repeated Patterns
- [recent] **외부 스캐너 198.51.100.88**: Patient Portal(203.0.113.10)에 대해 지속적인 HTTP/HTTPS 스캔 수행 중.
- [medium-term] **워크스테이션 DNS/NTP 이상**: 다수의 내부 PC에서 외부 DNS(8.8.8.8) 또는 NTP 서버로의 비정상적인 트래픽 발생. 터널링 가능성 존재.

## Watchlist Feedback
- [recent] VPN 및 Portal 관련 Watchlist 항목이 실제 공격(198.51.100.77, 198.51.100.88)을 성공적으로 탐지함. 탐지 임계치 유지 필요.

## Next-Cycle Guidance
- maintain: Tomcat CVE 관련 API 모니터링 강화.
- soften: 의료진 워크스테이션의 PACS(DICOM) 정상 접속에 대한 알람 감도 완화.
- strengthen: Day 5 예정된 FortiManager CVE 대비를 위해 10.60.50.30(Firewall Manager) 접속 기록 감시 강화.