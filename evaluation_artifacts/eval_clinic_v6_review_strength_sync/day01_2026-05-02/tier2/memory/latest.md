# Attack Surface Memory - 20260519T120041+0900

## Derived Attack Surface Changes
- [recent] 외부 노출 서비스인 환자 포털(203.0.113.10)과 VPN 게이트웨이(203.0.113.20)에 대한 최신 RCE 취약점(CVE-2024-4577, CVE-2023-3519) 노출 위험이 매우 높음.
- [recent] 내부 자산인 백업 NAS(10.42.40.12) 및 관리용 점프박스(10.42.50.8)에 대한 SSH 취약점(CVE-2024-6387) 공격 가능성 식별.
- [long-term] 의료 데이터(EHR, 빌링) 보호를 위해 내부 DB 및 백업 시스템에 대한 비인가 접근 감시가 상시 필수적임.

## Top Attack Hypotheses
- [recent] 외부 RCE 취약점 기반 초기 침투
  - evidence: CVE-2024-4577, CVE-2023-3519 정보 및 알려진 스캐너 IP(198.51.100.88 등) 존재.
  - observable_conditions: 포털/VPN 대상 특이 HTTP 인자 주입 또는 비정상적인 HTTPS 요청.
  - negative_conditions: 정상적인 환자 포털 이용 및 승인된 VPN 세션 수립.
  - confidence: High
  - review_condition: 알려진 위협 IP로부터의 접근 또는 반복적인 접속 실패 발생 시.

- [recent] 랜섬웨어 전조로서의 백업 데이터 변조
  - evidence: 정책상 비인가 시간대(02-04시 외) 워크스테이션의 백업 NAS 접근 금지.
  - observable_conditions: 10.42.100.0/24 대역에서 10.42.40.12로의 SMB 접근.
  - negative_conditions: 정기 유지보수 시간 내 승인된 관리자 호스트(10.42.50.8)의 접근.
  - confidence: Medium
  - review_condition: 업무 시간 중 워크스테이션 대역에서의 대량 파일 접근 시.

## Repeated Patterns
- [recent] 외부 위협 소스(198.51.100.0/24 대역)를 통한 VPN 브루트포스 및 웹 취약점 스캐닝 패턴 주의.

## Next-Cycle Guidance
- maintain: 외부 노출 자산(Portal, VPN)에 대한 실시간 취약점 스캐닝 탐지 유지.
- strengthen: 클라우드 메타데이터(IMDS) 접근 및 비인가 DNS 터널링 의심 행위 모니터링 강화.