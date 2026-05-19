# Attack Surface Memory - 20260519T121557+0900

## Derived Attack Surface Changes
- [recent] **Tomcat 취약점 노출 확대**: Day 3를 기점으로 CVE-2025-24813이 추가되어, 외부 접점인 Appointment API(203.0.113.30)와 내부 Lab-results API(10.60.20.30)의 위험도가 급증함. 특히 8080, 8443 포트를 통한 경로 우회 공격 가능성 존재.
- [medium-term] **백업 시스템 표적화**: Tier 1 이력에서 Backup NAS(10.60.40.12)에 대한 워크스테이션의 비정상 SMB 접근 및 외부 IP(198.51.100.123)로의 유출 정황이 반복 확인됨. 랜섬웨어 전조 현상으로 판단.
- [long-term] **공공 서비스 노출**: Patient Portal 및 VPN Gateway는 지속적인 PHP-CGI 및 Citrix RCE 시도 대상임.

## Top Attack Hypotheses
- [recent] **Tomcat 경로 우회 및 권한 탈취**
  - evidence: CVE-2025-24813 공지 및 해당 서비스를 사용하는 자산(Tomcat 기반) 확인.
  - observable_conditions: 외부/내부 미승인 소스의 8080/8443 포트 반복 접근, 공격 시도 후 해당 API 자산의 외부 HTTPS 통신.
  - negative_conditions: 업무 시간 내 클리닉 워크스테이션의 정상적인 API 호출.
  - confidence: high
  - review_condition: 미승인 소스에서의 접근 시도가 3회 이상 발생하거나 이상 포트 사용 시.

- [medium-term] **내부망을 통한 랜섬웨어 확산 및 백업 파괴**
  - evidence: Tier 1 DB 내 10.60.100.72 등 워크스테이션의 SMB(445) 접근 경보 다수.
  - observable_conditions: 백업 윈도우(02-04시) 외 시간대의 SMB 접근, 다량의 파일 변경 패턴.
  - confidence: high

## Repeated Patterns
- [recent] **고정적 위협원**: 198.51.100.88(PHP 스캐너), 198.51.100.77(VPN 브루트포스)이 지속적으로 외부 접점 공격 중.
- [medium-term] **클라우드 메타데이터 시도**: 내부 워크스테이션(10.60.100.42 등)에서 169.254.169.254 접근 시도가 반복됨.

## Next-Cycle Guidance
- maintain: 외부 접점 RCE 및 VPN 로그인 실패 감시.
- strengthen: Tomcat CVE 관련 8080/8443 포트 유입 및 해당 자산의 Outbound 트래픽 정밀 모니터링.
- soften: 정상 업무 시간 내 클리닉 워크스테이션의 API 호출에 대한 민감도 하향.