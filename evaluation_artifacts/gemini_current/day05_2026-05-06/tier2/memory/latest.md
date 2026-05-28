# Attack Surface Memory - 20260527T151633+0900

## Derived Attack Surface Changes
- [recent] **FortiManager 취약점 (CVE-2024-47575) 유입**: Day 5 기준 방화벽 관리 서버(`10.60.50.30`)를 대상으로 하는 미인증 RCE 위협이 식별됨. 관리 평면 포트(TCP/541) 및 HTTPS 통신에 대한 극도의 모니터링 필요.
- [recent] **은퇴 자산 잔존 트래픽 모니터링**: Day 4에 퇴역한 리포팅 웨어하우스(`10.60.30.40`)에 대한 비정상적인 스캔 및 접근 시도가 식별될 시 경계 강화 필요.
- [medium-term] **Tomcat 취약점 (CVE-2025-24813) 노출**: 임베디드 Tomcat을 사용하는 예약 API(`203.0.113.30`) 및 내부 실험실 결과 API(`10.60.20.30`)에 대한 외부 스캐너 집단의 RCE 시도가 지속 관찰됨.

## Top Attack Hypotheses
- [recent] **FortiManager 관리 평면 하이재킹 시도**
  - evidence: Day 5 신규 취약점 발표 및 외부 악성 IP의 관리망 탐색 가능성 증가.
  - observable_conditions: 비인가 출발지에서 `10.60.50.30:541` (fgfmd) 또는 HTTPS 포트 접근 시도, 혹은 방화벽 관리 서버에서 외부 인터넷으로의 이상 HTTPS 아웃바운드 발생.
  - negative_conditions: 사전에 정의된 Jumpbox(`10.60.50.8`) 또는 모니터링 서버(`10.60.60.20`)에서의 접근 및 유지보수 시간대 내의 정상 통신.
  - confidence: high
  - review_condition: 비인가 IP로부터의 포트 541 연결 시도가 1회 이상 탐지될 경우.
- [medium-term] **Tomcat RCE 및 내부망 침투**
  - evidence: 외부 위협 IP(`198.51.100.90`, `192.0.2.210`)가 예약 API(`203.0.113.30:8443`)를 반복 탐색한 이력 존재.
  - observable_conditions: 동일 외부 소스가 포트 8080/8443에 반복 접근 후 외부 C2로의 아웃바운드 연결 시도.
  - negative_conditions: 원격 클리닉 워크스테이션에서 정상적인 업무 시간 내에 수행하는 API 호출.
  - confidence: high
  - review_condition: ML 탐지 스코어가 낮더라도 알려진 위협 소스 대역에서 유입되는 경우.
- [medium-term] **백업 랜섬웨어 스테이징 및 데이터 탈취**
  - evidence: 내부 워크스테이션(`10.60.100.72` 등)에서 백업 NAS(`10.60.40.12`)로의 비인가 SMB 접근 및 백업 NAS에서 외부 IP(`198.51.100.123`)로의 HTTPS 유출 시도 관찰.
  - observable_conditions: 비업무 시간대 비인가 대역의 SMB(445) 접근 또는 백업 자산의 미승인 외부 인터넷 아웃바운드.
  - negative_conditions: 공식 백업 윈도우(02:00-04:00) 내 인가된 관리자 소스(`10.60.40.10`, `10.60.50.8`) 통신.
  - confidence: high

## Repeated Patterns
- [medium-term] 알려진 악성 IP 대역(`198.51.100.0/24`)을 중심으로 한 다각도 스캐닝: `198.51.100.88`은 포털 웹 RCE를, `198.51.100.77`은 VPN 무차별 대입 공격을, `198.51.100.90`은 내부 DB 및 Tomcat API를 지속적으로 프로빙함.
- [medium-term] 내부 사용자 단말에서의 메타데이터 서비스(`169.254.169.254`) 오남용 및 외부 C2 DNS 터널링 유사 행위 반복.

## Watchlist Feedback
- [recent] 이전 주기에 배포된 DB 직접 접근 및 외부 VPN 무차별 대입 관련 워치리스트 항목이 위협 IP들의 실제 공격 행위와 정확히 일치하여 고위험 경보를 적시에 유도함.

## Next-Cycle Guidance
- maintain: FortiManager 및 Tomcat 취약 자산 대상 탐지 룰 유지.
- soften: 업무 시간 중 의사 워크스테이션의 정상 PACS 접근 경보 완화.
- strengthen: 퇴역 자산(`10.60.30.40`) 대상의 스캔형 트래픽 및 백업 NAS 외부 유출 행위 자동 차단/검토 강화.