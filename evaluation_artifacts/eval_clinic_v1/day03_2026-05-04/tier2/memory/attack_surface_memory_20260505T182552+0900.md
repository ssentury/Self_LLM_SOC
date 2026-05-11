# Attack Surface Memory - 20260505T182552+0900

## Derived Attack Surface Changes
- [recent] **VPN 게이트웨이(203.0.113.20) 집중 공격**: 다수의 외부 IP(192.0.2.x, 198.51.100.77)로부터의 무차별 대입 및 취약점 탐색 패턴이 관찰됨. 외부 노출 접점 중 가장 위험도가 높음.
- [recent] **클라우드 메타데이터(IMDS) 접근 시도**: EHR API 서버(10.42.20.15)에서 169.254.169.254로의 접근이 확인됨. 이는 클라우드 권한 탈취 시도로 간주됨.
- [medium-term] **데이터 유출 의심**: 백업 NAS(10.42.40.12)가 외부 IP로 통신한 이력이 발견되어, 내부 데이터의 외부 유출 가능성이 제기됨.

## Top Attack Hypotheses
- [recent] **VPN 초기 침투 및 랜섬웨어 준비**
  - evidence: 198.51.100.77(알려진 위협 IP) 및 다수 외부 대역의 VPN 포트(443) 집중 접속.
  - observable_conditions: 동일 외부 IP의 반복적 연결 실패 또는 비정상적 페이로드 크기.
  - negative_conditions: 정규 업무 시간 내 승인된 사용자의 정상 로그인.
  - confidence: high
  - review_condition: VPN 로그인 실패 후 내부 자원(DB, NAS)으로의 횡적 이동 시도 시 즉시 에스컬레이션.

- [recent] **EHR API 서버 권한 오용 및 자격 증명 탈취**
  - evidence: EHR API 서버에서 IMDS(169.254.169.254) 호출 발생.
  - observable_conditions: dst_ip: 169.254.169.254, dst_port: 80.
  - negative_conditions: 인프라 팀의 정기 점검 또는 클라우드 에이전트 업데이트(사전 공지 필요).
  - confidence: high
  - review_condition: IMDS 접근 후 외부로의 비정상적 아웃바운드 통신 발생 시.

## Repeated Patterns
- [recent] 외부 IP 192.0.2.x 대역을 통한 조직적인 VPN 게이트웨이 스캐닝.
- [medium-term] 환자 포털(203.0.113.10)에 대한 PHP-CGI 취약점(CVE-2024-4577) 관련 탐색 시도 지속.

## Watchlist Feedback
- [recent] 이전 주기에서 198.51.100.90(DB 스캐너) 탐지 성공. 해당 IP는 지속 감시 필요.

## Next-Cycle Guidance
- maintain: VPN 및 IMDS 접근 감시 강화.
- soften: 내부 DNS(10.42.60.5)의 정상적인 쿼리 패턴에 대한 경보 완화.
- strengthen: 백업 NAS의 비정상 시간대(02:00-04:00 외) 외부 통신 차단 로직 검토.