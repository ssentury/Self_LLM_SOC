# Dynamic CVE 시나리오 설명

## 한 줄 요약

`regional_care_dynamic_cve_5day`는 기존 clinic full 시나리오의 과적합을 줄이기 위한 5일치 동적 CVE 평가 시나리오다. 총 1000개 flow를 사용하며, 3일차와 5일차에 CVE가 단계적으로 추가될 때 Tier 2 산출물과 탐지 판단이 어떻게 바뀌는지 관찰하는 것이 핵심이다.

## 왜 새 시나리오가 필요한가

기존 clinic full은 파이프라인 전체가 동작하는지 보여주기에는 좋지만, 조직 상태가 거의 고정되어 있다. 그래서 시스템이 특정 clinic IP/포트/패턴에 익숙해진 것인지, 아니면 새 자산·위협·CVE 변화에 맞춰 Tier 2가 맥락을 다시 정리하고 Tier 1 판단을 도와주는 것인지 분리해서 보기 어렵다.

새 시나리오는 조직 규모를 조금 키우고, 업무 PC와 일반 업무 트래픽을 늘리고, CVE 변화를 시간축에 넣어 이 문제를 줄인다.

## 기본 구성

- 기간: 2026-05-02부터 2026-05-06까지 5일
- 전체 flow: 1000개
- 하루 flow: 200개
- 하루 정상/공격 비율: 정상 180개, 공격 20개
- 전체 정상/공격 비율: 정상 900개, 공격 100개
- ML 입력: `mock_prob` 없이 NF-CICIDS2018-v3 기반 XGBoost feature 사용
- 생성 원칙: 원본 데이터의 Label-Feature 관계를 보존하고, IP/포트/시간/flow_id만 시나리오 토폴로지에 맞게 투영

## 조직 토폴로지

가상의 지역 외래 진료 네트워크를 기준으로 한다. 기존 clinic보다 자산이 많지만, 여전히 작은 보안팀이 운영하는 조직이라는 설정이다.

주요 자산은 다음과 같다.

- DMZ: 환자 포털, VPN, 예약 API, 파트너 SFTP 게이트웨이
- 내부 앱: EHR API, lab-results API, notification service
- DB: EHR Postgres, billing MSSQL, lab MySQL, reporting warehouse
- 임상 시스템: PACS image archive, DICOM router
- 백업/스토리지: backup NAS, object storage gateway
- 관리망: admin jumpbox, patch management, EDR management, firewall manager
- 인프라: DNS, domain controller, NTP, monitoring, SIEM collector
- 업무 PC: reception, nurse station, doctor laptop, billing PC, shared kiosk PC

업무 PC와 일반 DNS/SaaS/업데이트/파일공유 트래픽을 넣은 이유는, 중요한 서버만 있는 장난감 같은 네트워크가 되지 않게 하기 위해서다.

## 5일 변화 흐름

Day 1은 기준 상태다. 기존 clinic과 비슷하게 포털, VPN, DB, 백업, DNS tunnel, metadata access, exfiltration 류의 공격과 정상 업무 트래픽이 섞인다.

Day 2는 소스 입력 변화 없이 안정 상태를 유지한다. 이 날은 Tier 2가 raw source 변화 없이 이전 피드백과 반복 패턴만으로 얼마나 안정적인 산출물을 유지하는지 보기 위한 날이다.

Day 3에는 첫 번째 CVE가 추가된다.

- CVE: `CVE-2025-24813`
- 대상: `lab-results-api`, `appointment-api`
- 의미: Tomcat 기반 API에 대한 exploit probe와 후속 egress를 관찰
- 주의점: NetFlow만으로 HTTP URI나 partial PUT 내용을 볼 수 없으므로, Tier 1이 단순 자산 매칭만으로 alert하면 안 된다.

Day 4에는 CVE를 새로 추가하지 않는다. 대신 작은 운영 변화만 넣는다.

- shared/kiosk PC 일부 추가
- reporting warehouse retired 처리
- Day 3 Tomcat 스캐너와 관련된 IOC 1개 추가

Day 5에는 두 번째 CVE가 추가된다.

- CVE: `CVE-2024-47575`
- 대상: `firewall-manager`
- 의미: FortiManager류 관리 평면 TCP/541 접근과 후속 egress를 관찰
- 주의점: admin jumpbox에서 firewall manager로 가는 정상 관리 트래픽도 있으므로, TCP/541이라고 무조건 alert하면 안 된다.

## 공격 설계

공격 flow는 실제 NF-CICIDS2018-v3의 공격 label row를 사용한다. 즉, 임의로 feature를 만든 것이 아니라 실제 공격 label의 feature 특성을 유지한다.

사용하는 주요 공격 label은 다음과 같다.

- `Brute_Force_-Web`
- `SSH-Bruteforce`
- `SQL_Injection`
- `Infilteration`
- `DDOS_attack-HOIC`

특히 기존 clinic full에서 약점이었던 `Infilteration` 계열을 더 많이 포함했다. DNS tunnel, metadata access, backup exfiltration, app host follow-up, firewall manager egress 같은 저점수/맥락형 공격을 보려는 목적이다.

## 정상 트래픽 설계

정상 트래픽은 공격보다 더 중요하다. CVE 대상 자산으로 가는 정상 업무 flow를 유지해야, 시스템이 "CVE가 있으니 무조건 위험"처럼 과민 반응하는지 확인할 수 있다.

예를 들어 다음 정상 트래픽이 포함된다.

- 업무 PC에서 lab-results API 접근
- 환자/직원의 환자 포털 및 예약 API 접근
- doctor laptop의 PACS 접근
- admin jumpbox의 firewall manager 관리 접근
- 백업 윈도우 안의 SMB 백업
- 일반 DNS, NTP, SaaS, 업데이트, 파일공유 트래픽

## 생성된 파일

- `data/sample/regional_care_dynamic_cve_flows_xgb.csv`
  - 실제 1000개 flow CSV
- `data/sample/regional_care_dynamic_cve_flows_xgb_manifest.json`
  - source row, projection override, label/count, CVE count 기록
- `config/scenarios/regional_care_dynamic_cve/base/`
  - Day 1-2 기준 organization/assets/policy/CVE/threat feed
- `config/scenarios/regional_care_dynamic_cve/overlays/`
  - Day 3, Day 4, Day 5 변화 정의
- `config/scenarios/regional_care_dynamic_cve/generated/day01..day05/`
  - 각 날짜별로 실제 Tier 2가 읽을 수 있는 materialized YAML
- `scripts/generate_regional_care_dynamic_cve_xgb_flows.py`
  - CSV, manifest, generated YAML 재생성 스크립트

## 이 시나리오로 보고 싶은 것

- Day 3 이후 Tier 2 watchlist가 Tomcat CVE 관련 자산을 올바르게 반영하는가
- Day 5 이후 Tier 2 watchlist가 firewall manager 관리 평면 위험을 반영하는가
- 정상 lab API 접근과 정상 firewall manager 관리 접근을 과하게 alert하지 않는가
- 기존 clinic full에서 약했던 low-ML `Infilteration` 계열 recall이 어떻게 나오는가
- Watchlist 때문에 Tier 1 호출이 늘어나는 정도가 비용 관점에서 납득 가능한가

## 현재 상태

현재는 풀 파이프라인 평가 직전 상태까지 준비되어 있다. CSV, manifest, day별 YAML, generator, 입력 검증 테스트는 만들어져 있다. 실제 Tier 2/Tier 1 실행 결과 분석은 별도 환경에서 나중에 수행한다.
