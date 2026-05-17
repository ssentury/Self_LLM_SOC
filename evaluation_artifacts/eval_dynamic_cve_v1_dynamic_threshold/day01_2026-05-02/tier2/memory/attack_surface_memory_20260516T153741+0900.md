# Attack Surface Memory - 20260516T153741+0900

## Derived Attack Surface Changes
- [long-term] Hanbit Regional Care Network의 주요 노출 지점은 환자 포털(203.0.113.10)과 VPN 게이트웨이(203.0.113.20)로, 이들은 외부 공격의 1차 관문임.
- [recent] 최근 공개된 PHP-CGI(CVE-2024-4577) 및 Citrix(CVE-2023-3519) 취약점으로 인해 DMZ 영역의 자산 위험도가 급격히 상승함.
- [medium-term] 내부망의 백업 NAS(10.60.40.12) 및 PACS(10.60.35.10)는 랜섬웨어 및 데이터 유출의 핵심 타겟으로 식별됨.

## Top Attack Hypotheses
- [recent] 외부 취약점 악용을 통한 초기 침투
  - evidence: CVE-2024-4577, CVE-2023-3519 공표 및 관련 위협 IP(198.51.100.88 등) 존재.
  - observable_conditions: DMZ 자산에 대한 비정상적인 HTTP 파라미터 포함 요청 또는 VPN 반복 로그인 실패.
  - negative_conditions: 정상적인 환자 포털 이용 및 승인된 사용자의 VPN 접속 성공.
  - confidence: high
  - review_condition: 알려진 위협 IP로부터의 접근 시 즉시 검토.

- [medium-term] 백업 시스템 변조를 통한 랜섬웨어 준비
  - evidence: 시나리오상 의료 네트워크 대상 랜섬웨어 위협 증가 및 백업 윈도우 정책 존재.
  - observable_conditions: 02:00-04:00 이외의 시간에 워크스테이션에서 백업 NAS(10.60.40.12)로의 SMB 접근.
  - negative_conditions: 관리자 점프박스(10.60.50.8)를 통한 정기 유지보수 활동.
  - confidence: medium
  - review_condition: 비정상 시간대 SMB 트래픽 발생 시 검토.

## Repeated Patterns
- [long-term] 업무 시간(08:00-19:00) 내 의사 워크스테이션의 PACS 접근은 정상 패턴으로 간주.
- [long-term] 야간 백업 윈도우(02:00-04:00) 동안의 정기 백업 트래픽은 정상 패턴임.

## Watchlist Feedback
- [recent] Cycle Day 1 기준 초기 왓치리스트 구성 단계로 피드백 데이터 미비.

## Next-Cycle Guidance
- maintain: 외부 노출 자산에 대한 취약점 기반 모니터링 유지.
- strengthen: 위협 피드의 IP와 내부 자산 간의 매칭 감시 강화.