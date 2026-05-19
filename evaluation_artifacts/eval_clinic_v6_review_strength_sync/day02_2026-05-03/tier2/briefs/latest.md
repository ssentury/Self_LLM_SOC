# Brief Context - 20260519T120142+0900

## 조직 현황 요약
내부망은 172.31.0.0/16 대역으로 가정합니다.

- 주의 자산: 203.0.113.10 (patient-portal-web)
- 주의 자산: 203.0.113.20 (vpn-gateway)
- 주의 자산: 10.42.20.15 (ehr-api)
- 주의 자산: 10.42.30.25 (billing-postgres)
- 주의 자산: 10.42.40.12 (backup-nas)
- 주의 자산: 10.42.50.8 (admin-jumpbox)

## 정책 지침

### 위험 증가 규칙
- 조건: external-unknown -> dmz-public vpn-gateway repeated failures (위험도: +1)
- 조건: external-unknown -> internal-db (위험도: +2)
- 조건: clinic-workstations -> internal-backup smb outside backup window (위험도: +1)
- 조건: internal host -> 169.254.169.254 (위험도: +2)

### 자산별 접근 정책
- 203.0.113.10: Public HTTP/HTTPS is allowed, but admin paths and exploit-like probing should be escalated.
- 203.0.113.20: VPN HTTPS is allowed from the internet; repeated failures, unusual sources, or exploit patterns are high risk.
- 10.42.30.25: Postgres access is allowed only from 10.42.20.15 and approved admin hosts.
- 10.42.40.12: SMB backup traffic is expected only during the backup window and from backup/admin hosts.
- 10.42.50.8: SSH/RDP to the jumpbox is allowed only from admin or VPN-controlled sources.

## Tier 1 판정 지침
Tier 1은 원천 CVE, 자산, 정책 파일을 직접 펼쳐 읽지 않습니다. 이 brief와 watchlist에서 정리된 맥락만 사용합니다.