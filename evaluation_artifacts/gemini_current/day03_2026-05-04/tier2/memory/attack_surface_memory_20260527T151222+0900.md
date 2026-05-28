# Attack Surface Memory - 20260527T151222+0900

## Derived Attack Surface Changes
- [recent] Day 3 신규 Apache Tomcat 취약점(CVE-2025-24813) 도입으로 인해 외부 노출된 예약 API(203.0.113.30) 및 내부 검사결과 API(10.60.20.30)의 잠재적 위험도가 매우 높아짐.
- [recent] 위협 피드 IP인 198.51.100.90이 예약 API의 8443 포트를 탐색한 비정상 흐름이 감지됨.
- [medium-term] 포털 웹서버(203.0.113.10) 대상 PHP-CGI 취약점 스캔 및 VPN 게이트웨이(203.0.113.20) 대상 무차별 대입 시도가 외부 위협원에 의해 반복 지속 중.
- [long-term] 내부 워크스테이션 세그먼트에서 클라우드 메타데이터(169.254.169.254) 및 비인가 시간대 백업 NAS(10.60.40.12)로의 비정상 접근 패턴이 정기적으로 관찰됨.

## Top Attack Hypotheses
- [recent] Apache Tomcat 취약점(CVE-2025-24813) 표적 스캔 및 침투 시도
  - evidence: 위협 피드 IP 198.51.100.90이 203.0.113.30:8443에 접근하여 경보 발생.
  - observable_conditions: 외부 미식별 호스트가 8080 또는 8443 포트로 반복 접근하거나, 공격 성공 후 API 서버가 외부로 비정상 HTTPS 아웃바운드 세션을 생성하는 행위.
  - negative_conditions: 임상 업무 시간대(08:00-19:00) 내 내부 워크스테이션의 정상적인 API 통신.
  - confidence: High
  - review_condition: 외부 IP 혹은 미식별 대역에서 203.0.113.30 또는 10.60.20.30의 8080/8443 포트로 접근 탐지 시.
- [medium-term] 내부 비인가 호스트를 통한 클라우드 자격 증명 탈취 및 백업 변조 시도
  - evidence: 다수의 내부 워크스테이션에서 169.254.169.254:80 접근 시도 및 비인가 시간대 백업 NAS SMB 연결 탐지.
  - observable_conditions: 내부 워크스테이션이 메타데이터 IP로 HTTP 요청을 보내거나, 백업 점검 시간대(02:00-04:00) 외에 10.60.40.12:445로 연결을 수립하는 행위.
  - negative_conditions: 지정된 백업/관리 소스(10.60.40.10, 10.60.50.8)의 허용 시간대 내 백업 활동.
  - confidence: High
  - review_condition: 메타데이터 IP 접근 흐름 발생 또는 비인가 시간대 백업 NAS 대상 SMB 연결 발생 시.

## Repeated Patterns
- [medium-term] 198.51.100.77에 의한 VPN 게이트웨이(203.0.113.20:443) 패스워드 스프레잉 시도 지속.
- [medium-term] 198.51.100.88에 의한 포털 웹서버(203.0.113.10) HTTP/HTTPS 취약점 탐색 지속.
- [medium-term] 192.0.2.77에 의한 관리자 점프박스(10.60.50.8:22) 무단 SSH 접근 시도.

## Watchlist Feedback
- [recent] 신규 Tomcat CVE 취약 자산 탐색 및 내부망 메타데이터/백업 접근 시도가 이전 감시 항목과 정확히 부합하여 유의미한 경보를 생성함. 오탐 유발 방지를 위한 정상 비즈니스 시간대 필터링 유효성 검증 완료.

## Next-Cycle Guidance
- maintain: 신규 Tomcat CVE 관련 포트(8080, 8443)에 대한 외부 스캔 감시 수준 유지.
- soften: 임상 워크스테이션 대역의 정상적인 업무 시간 내 검사결과 API 호출에 대한 단순 매칭 경보 완화.
- strengthen: 외부 위협 IP의 내부망 침투 목적 스캔 및 백업 NAS 비인가 접근에 대한 차단 룰 및 심층 검토 강화.