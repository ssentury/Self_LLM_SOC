# Attack Surface Memory - 20260511T144458+0900

## Derived Attack Surface Changes
- [recent] VPN 게이트웨이(203.0.113.20) 및 환자 포털(203.0.113.10)에 대한 외부 위협 소스의 공격 시도가 급증함. 특히 198.51.100.77, 198.51.100.88 등의 알려진 악성 IP가 반복적으로 관찰됨.
- [recent] 내부 워크스테이션(10.42.100.45)에서 백업 NAS(10.42.40.12)로의 비정상적인 SMB 접근이 확인되어 내부 확산 및 랜섬웨어 준비 단계의 위험이 상승함.
- [medium-term] 과금 DB(10.42.30.25)에 대한 외부 직접 접근 시도가 지속적으로 차단되고 있으나, 노출 시 파급력이 매우 큼.

## Top Attack Hypotheses
- [recent] VPN 자격 증명 탈취 및 RCE 시도
  - evidence: 198.51.100.77의 반복적 VPN 접근 및 CVE-2023-3519 관련 정황.
  - observable_conditions: 동일 외부 소스의 반복적 443/TCP 연결, 작은 패킷 사이즈의 반복.
  - negative_conditions: 승인된 임직원 IP에서의 정상적인 로그인 성공.
  - confidence: high
  - review_condition: 동일 IP에서 5회 이상의 연결 시도 발생 시.

- [recent] 환자 포털 PHP-CGI 취약점 악용
  - evidence: 198.51.100.88의 포털 스캐닝 및 CVE-2024-4577 취약점 존재 가능성.
  - observable_conditions: HTTP/HTTPS 요청 내 특수 파라미터(?+ 등) 포함.
  - negative_conditions: 단순 정적 리소스 요청 및 정상적인 예약 프로세스.
  - confidence: medium
  - review_condition: 알려진 스캐너 IP의 접근 또는 비정상 쿼리 스트링 탐지 시.

- [recent] 내부 랜섬웨어 확산 및 백업 변조
  - evidence: 워크스테이션 대역에서 백업 윈도우 외 시간에 NAS 접근 발생.
  - observable_conditions: 10.42.100.0/24 대역에서 10.42.40.12:445 접근.
  - negative_conditions: 유지보수 시간(02:00-04:00) 내 관리자 호스트의 접근.
  - confidence: medium
  - review_condition: 비인가 호스트의 SMB 연결 시도.

## Repeated Patterns
- [recent] 외부 IP 198.51.100.88, 198.51.100.77, 198.51.100.90이 각각 포털, VPN, DB를 타겟팅하는 고정된 패턴을 보임.

## Watchlist Feedback
- [recent] 이전 사이클의 Watchlist가 96건의 매칭을 기록하며 15건의 유효한 경보를 생성함. 특히 외부 스캐너와 내부 백업 접근 탐지 효율이 높음.

## Next-Cycle Guidance
- maintain: 외부 노출 서비스(VPN, Portal)에 대한 모니터링 강화.
- strengthen: 클라우드 메타데이터(IMDS) 접근 시도에 대한 탐지 로직 구체화.