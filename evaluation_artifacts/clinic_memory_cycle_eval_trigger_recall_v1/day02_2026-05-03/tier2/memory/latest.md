# Attack Surface Memory - 20260510T214253+0900

## Derived Attack Surface Changes
- [recent] **VPN 및 포털 노출 위험 증가**: CVE-2023-3519 및 CVE-2024-4577과 관련된 취약점 정보와 함께 외부 스캐너(198.51.100.x 계열)의 활동이 관찰됨에 따라 DMZ 자산의 방어 우선순위가 상향됨.
- [medium-term] **내부 자산 간 비정상 경로 확인**: 워크스테이션에서 백업 NAS로의 SMB 접근 및 내부 자산의 클라우드 메타데이터(IMDS) 접근 시도가 이력 데이터에서 확인됨. 이는 단순 오설정보다는 권한 탈취 및 랜섬웨어 준비 단계의 가설을 뒷받침함.
- [long-term] **데이터베이스 직접 노출 금지**: 정책상 외부에서 Billing Postgres(10.42.30.25)로의 직접 접근은 절대 금지되어 있으나, 이력상 시도가 존재하므로 지속적인 모니터링이 필요함.

## Top Attack Hypotheses
- [recent] **VPN 자격 증명 무차별 대입 및 취약점 공격**
  - evidence: 198.51.100.77의 VPN 브루트포스 이력 및 CVE-2023-3519 취약점 존재.
  - observable_conditions: 동일 외부 IP의 반복적 로그인 실패, HTTPS를 통한 비정상적 페이로드 전송.
  - negative_conditions: 승인된 사용자 대역에서의 정상적인 VPN 세션 수립.
  - confidence: high
  - review_condition: 동일 소스 IP에서 5회 이상의 연결 시도 발생 시.

- [recent] **랜섬웨어 준비를 위한 백업 변조 및 데이터 유출**
  - evidence: 10.42.100.45(워크스테이션)의 백업 NAS 접근 및 NAS의 외부 통신 이력.
  - observable_conditions: 백업 윈도우(02:00-04:00) 외 시간대의 SMB(445) 접근, NAS에서 외부 IP로의 대량 아웃바운드.
  - negative_conditions: 지정된 관리자 호스트(10.42.50.8)의 점검 활동.
  - confidence: medium
  - review_condition: 비인가 호스트의 SMB 연결 성공 시.

## Repeated Patterns
- [medium-term] **외부 스캐너 그룹 활동**: 198.51.100.0/24 대역의 IP들이 포털, VPN, DB를 순차적으로 스캐닝하는 패턴이 반복됨.
- [recent] **IMDS 접근 시도**: EHR API 서버(10.42.20.15)에서 169.254.169.254로의 접근이 발생함. 이는 클라우드 환경에서의 자격 증명 탈취 시도로 해석됨.

## Watchlist Feedback
- [recent] 이전 주기에서 198.51.100.77(VPN) 및 198.51.100.90(DB)에 대한 탐지가 유효했음. 해당 소스들에 대한 차단 여부 확인 필요.

## Next-Cycle Guidance
- maintain: DMZ 자산(포털, VPN)에 대한 외부 스캐닝 탐지 강화.
- strengthen: 백업 NAS 및 IMDS 접근에 대한 내부 횡적 이동 감시 수준 상향.
- soften: 정상 업무 시간 내의 VPN 접속에 대해서는 임계치 완화.