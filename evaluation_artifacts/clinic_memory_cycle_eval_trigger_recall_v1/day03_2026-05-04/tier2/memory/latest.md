# Attack Surface Memory - 20260510T214354+0900

## Derived Attack Surface Changes
- [recent] VPN 게이트웨이(203.0.113.20) 및 환자 포털(203.0.113.10)에 대한 외부 공격 시도가 지속적으로 관찰됨. 특히 198.51.100.77 및 192.0.2.44로부터의 VPN 접근 시도가 빈번함.
- [recent] 내부 워크스테이션(10.42.100.45)에서 백업 NAS 및 점프박스로의 비정상적인 접근이 식별되어 내부 확산(Lateral Movement) 위험이 증가함.
- [medium-term] EHR API 서버(10.42.20.15)에서 클라우드 메타데이터 서비스(IMDS)로의 접근 시도가 확인되어 클라우드 권한 탈취 시나리오가 유효함.

## Top Attack Hypotheses
- [recent] VPN 무단 접근 및 초기 침투
  - evidence: 198.51.100.77의 반복적인 VPN 로그인 실패 및 성공 시도.
  - observable_conditions: dst_ip: 203.0.113.20, dst_port: 443, 다수의 실패 로그 또는 알려진 위협 IP.
  - negative_conditions: 승인된 사용자의 정상적인 업무 시간 내 VPN 연결.
  - confidence: high
  - review_condition: 동일 소스 IP에서 반복적인 연결 시도 발생 시.

- [recent] 랜섬웨어 준비 단계 (백업 변조 및 내부 확산)
  - evidence: 워크스테이션(10.42.100.45)이 백업 윈도우 외 시간에 SMB(445) 및 SSH(22)로 내부 주요 자산 접근.
  - observable_conditions: src_zone: clinic-workstations, dst_port: [445, 22, 3389], 시간외 접근.
  - negative_conditions: 정기 유지보수 시간(02:00-04:00) 내 관리자 호스트의 접근.
  - confidence: medium
  - review_condition: 워크스테이션에서 백업 NAS 또는 점프박스로의 신규 연결 발생 시.

## Repeated Patterns
- [medium-term] 외부 IP 198.51.100.90의 지속적인 Postgres(5432) 포트 스캐닝.
- [recent] 환자 포털을 대상으로 한 PHP-CGI 취약점(CVE-2024-4577) 탐색 시도 (198.51.100.88, 192.0.2.210).

## Watchlist Feedback
- [recent] VPN 및 DB 스캐닝 관련 Watchlist 항목이 실제 공격 시도와 높은 일치율을 보임. 워크스테이션의 내부 확산 패턴에 대한 감시 강화 필요.

## Next-Cycle Guidance
- maintain: 외부 노출 자산(VPN, Portal)에 대한 위협 IP 기반 차단 정책 유지.
- strengthen: 워크스테이션 존에서 백업 및 인프라 존으로의 접근 제어 모니터링 강화.
- soften: 정기 백업 시간대(02:00-04:00)의 정상적인 백업 트래픽에 대한 탐지 우선순위 하향.