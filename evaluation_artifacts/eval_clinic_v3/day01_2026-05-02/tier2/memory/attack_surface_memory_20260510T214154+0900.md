# Attack Surface Memory - 20260510T214154+0900

## Derived Attack Surface Changes
- [long-term] 한빛 케어 네트워크는 텔레헬스 서비스를 제공하며, 환자 포털(203.0.113.10)과 VPN 게이트웨이(203.0.113.20)가 주요 외부 노출 접점임.
- [long-term] 내부망의 Billing Postgres(10.42.30.25) 및 Backup NAS(10.42.40.12)는 랜섬웨어 및 데이터 유출의 핵심 타겟으로 식별됨.

## Top Attack Hypotheses
- [recent] VPN 게이트웨이를 통한 초기 침투 및 권한 상승
  - evidence: CVE-2023-3519 취약점 및 알려진 VPN 브루트포스 IP(198.51.100.77) 존재.
  - observable_conditions: 외부 IP로부터의 반복적인 VPN 접속 실패 또는 비정상적 소스에서의 접근.
  - negative_conditions: 승인된 사용자의 정상적인 업무 시간 내 접속.
  - confidence: high
  - review_condition: 동일 소스 IP에서 5회 이상의 접속 시도 발생 시.

- [recent] 환자 포털 PHP-CGI 취약점 악용 (CVE-2024-4577)
  - evidence: 포털 자산(203.0.113.10)의 서비스 특성과 알려진 스캐너 IP(198.51.100.88).
  - observable_conditions: HTTP/HTTPS 요청 내 비정상적인 인자 주입 패턴.
  - confidence: medium

- [medium-term] 백업 데이터 변조를 통한 랜섬웨어 준비
  - evidence: 정책상 백업 윈도우(02:00-04:00) 외의 SMB 접근은 비정상으로 간주.
  - observable_conditions: 워크스테이션 구역(10.42.100.0/24)에서 NAS(10.42.40.12)로의 SMB 접근.
  - confidence: high

## Repeated Patterns
- [recent] 현재 첫 번째 분석 사이클로, 반복 패턴은 아직 관찰되지 않음.

## Watchlist Feedback
- [recent] 이전 피드백 없음.

## Next-Cycle Guidance
- maintain: 외부 노출 자산(Portal, VPN)에 대한 취약점 스캐닝 시도 모니터링 강화.
- strengthen: 백업 NAS 및 클라우드 메타데이터(169.254.169.254) 접근에 대한 엄격한 정책 적용.