# Attack Surface Memory - 20260516T152816+0900

## Derived Attack Surface Changes
- [recent] 외부 노출 자산인 환자 포털(203.0.113.10)과 VPN 게이트웨이(203.0.113.20)가 최우선 방어 지점으로 식별됨. 특히 PHP-CGI 및 Citrix 관련 최신 CVE 영향권에 있음.
- [recent] 내부 자산 중 빌링 DB(10.42.30.25)와 백업 NAS(10.42.40.12)는 랜섬웨어 공격의 핵심 타겟으로 분류됨.

## Top Attack Hypotheses
- [recent] VPN 초기 침투 및 자격 증명 탈취
  - evidence: 위협 피드 내 VPN 브루트포스 IP(198.51.100.77) 존재 및 관련 정책 수립됨.
  - observable_conditions: 동일 외부 소스의 반복적 VPN 접속 실패 또는 알려진 위협 IP의 접근.
  - negative_conditions: 승인된 사용자의 정상적인 업무 시간 내 로그인 성공.
  - confidence: high
  - review_condition: ml_prob >= 0.20 또는 위협 IP 매칭 시.

- [recent] 웹 취약점(PHP-CGI)을 이용한 RCE 시도
  - evidence: CVE-2024-4577 정보 및 웹 스캐너 IP(198.51.100.88, 192.0.2.210) 식별.
  - observable_conditions: 포털 자산에 대한 비정상적인 HTTP 인자 전달 또는 스캐닝 행위.
  - negative_conditions: 정규 API 호출 및 일반적인 환자 포털 이용 패턴.
  - confidence: medium
  - review_condition: 특정 취약점 패턴 매칭 시 즉시 리뷰.

- [recent] 백업 데이터 변조를 통한 랜섬웨어 준비
  - evidence: 의료 섹터 대상 랜섬웨어 전조 증상 가이드 및 백업 윈도우 정책 존재.
  - observable_conditions: 02:00-04:00 외 시간대에 클리닉 워크스테이션에서 백업 NAS로의 SMB 접근.
  - negative_conditions: 유지보수 시간 내 승인된 관리자(10.42.50.8)의 접근.
  - confidence: high
  - review_condition: 정책 위반 시간대 접근 발생 시.

## Repeated Patterns
- [recent] 현재 첫 사이클로 반복 패턴 미식별. 외부 스캐너의 지속적인 탐색 여부 모니터링 필요.

## Next-Cycle Guidance
- maintain: 외부 노출 자산(Portal, VPN)에 대한 위협 IP 매칭 강화.
- strengthen: 내부망 내에서 클라우드 메타데이터(169.254.169.254) 접근 시도에 대한 감시 수준 상향.