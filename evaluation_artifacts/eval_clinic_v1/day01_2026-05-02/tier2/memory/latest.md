# Attack Surface Memory - 20260505T182236+0900

## Derived Attack Surface Changes
- [long-term] 한빛 케어 네트워크의 주요 노출 지점은 환자 포털(203.0.113.10)과 VPN 게이트웨이(203.0.113.20)로 식별됨. 소규모 의료 기관 특성상 초기 침투 시도가 랜섬웨어로 이어질 가능성이 매우 높음.
- [medium-term] 내부 자산 중 빌링 DB(10.42.30.25)와 EHR API(10.42.20.15)는 외부 직접 접근이 엄격히 금지되어 있으며, 이를 시도하는 흐름은 즉각적인 위협으로 간주함.

## Top Attack Hypotheses
- [recent] VPN 게이트웨이를 통한 초기 침투 및 자격 증명 탈취
  - evidence: 위협 피드 내 VPN 브루트포스 IP(198.51.100.77) 및 CVE-2023-3519 취약점 존재.
  - observable_conditions: 외부 미확인 대역에서 203.0.113.20:443으로의 반복적인 연결 실패 또는 비정상적 페이로드.
  - negative_conditions: 업무 시간 내 정상적인 VPN 세션 수립.
  - confidence: high
  - review_condition: 동일 외부 IP에서 5회 이상의 연결 시도 발생 시.

- [recent] 환자 포털 PHP-CGI 원격 코드 실행(RCE)
  - evidence: CVE-2024-4577 취약점 및 관련 스캐너 IP(198.51.100.88) 식별.
  - observable_conditions: 203.0.113.10으로의 HTTP/HTTPS 요청 중 인자 주입 패턴 포함.
  - negative_conditions: 정적 리소스 호출 및 정상적인 예약 페이지 접근.
  - confidence: medium
  - review_condition: 위협 피드 IP의 접근 또는 비정상 쿼리 스트링 탐지 시.

## Repeated Patterns
- [long-term] 야간 백업 윈도우(02:00-04:00) 외의 백업 NAS(10.42.40.12) 접근은 랜섬웨어 전조 증상으로 관리함.

## Watchlist Feedback
- [recent] 첫 분석 사이클로 이전 피드백 없음.

## Next-Cycle Guidance
- maintain: DMZ 자산에 대한 외부 위협 IP 매칭 모니터링 강화.
- strengthen: 내부망에서 클라우드 메타데이터(169.254.169.254)로의 접근 시도 감시.