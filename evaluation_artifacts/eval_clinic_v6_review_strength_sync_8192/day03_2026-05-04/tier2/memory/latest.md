# Attack Surface Memory - 20260519T120427+0900

## Derived Attack Surface Changes
- [recent] **외부 노출 서비스 공격 압력 증가**: 환자 포털(203.0.113.10) 및 VPN 게이트웨이(203.0.113.20)에 대한 외부 스캐너 및 브루트포스 시도가 빈번하게 관찰됨. 특히 PHP-CGI(CVE-2024-4577) 및 Citrix(CVE-2023-3519) 관련 취약점 노출 가능성이 핵심 경계 대상임.
- [medium-term] **내부 자산 보호 우선순위**: Billing DB(10.42.30.25) 및 Backup NAS(10.42.40.12)가 랜섬웨어 및 데이터 유출의 최종 목표로 식별됨. 최근 워크스테이션에서의 비정상적인 접근 시도가 포착되어 내부 확산 단계에 대한 감시 강화가 필요함.

## Top Attack Hypotheses
- [recent] **VPN 자격 증명 탈취 및 초기 침투**
  - evidence: 198.51.100.77 등 알려진 위협 IP로부터의 VPN 게이트웨이(203.0.113.20) 접근 및 반복적인 로그인 실패 발생.
  - observable_conditions: 동일 외부 IP의 반복적 443 포트 접속, 비정상적인 응답 크기.
  - negative_conditions: 승인된 임직원 IP의 정상적인 VPN 연결 성공.
  - confidence: high
  - review_condition: 동일 소스 IP에서 5회 이상의 연결 시도 발생 시.

- [recent] **랜섬웨어 준비를 위한 백업 변조**
  - evidence: 클리닉 워크스테이션(10.42.100.45)에서 백업 NAS(10.42.40.12)로의 비정기적 SMB 접근 시도.
  - observable_conditions: 유지보수 시간(02:00-04:00) 외의 SMB(445) 트래픽.
  - negative_conditions: 관리자 점프박스(10.42.50.8)에서의 정기 점검.
  - confidence: medium
  - review_condition: 워크스테이션 세그먼트에서 백업망으로의 직접 연결 시.

## Repeated Patterns
- [recent] 외부 스캐너(192.0.2.210)에 의한 환자 포털 디렉토리 열거 및 취약점 프로빙 패턴 반복.
- [medium-term] EHR API 서버(10.42.20.15)에서의 클라우드 메타데이터(169.254.169.254) 호출 시도.

## Watchlist Feedback
- [recent] 위협 피드 기반의 IP(198.51.100.77, 198.51.100.90) 매칭이 실제 고위험 경보로 이어지는 높은 정확도를 보임. 외부 소스 기반 탐지 룰 유지 필요.

## Next-Cycle Guidance
- maintain: 외부 노출 자산(Portal, VPN)에 대한 취약점 스캐닝 감시.
- strengthen: 내부망 간 비정상적인 횡적 이동(특히 DB 및 백업망 방향)에 대한 임계치 하향 조정.