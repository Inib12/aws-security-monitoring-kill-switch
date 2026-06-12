# AWS Security Monitoring & Alerting: Secrets Manager Access Detection + Automated Kill-Switch
> **Tools & Services:** AWS CloudTrail | CloudWatch | Amazon EventBridge | SNS | Lambda | Secrets Manager | IAM | AWS CLI  
> **Domain:** Cloud Security | Threat Detection | Incident Response | Security Automation  
> **📄 [View Full Technical Documentation](./AWS_Security_Monitoring_Full_Report.pdf)**

---

## Background

Sensitive credentials stored in AWS Secrets Manager represent a high-value target for attackers. A compromised IAM user silently retrieving production database credentials could go completely undetected in an environment relying only on periodic log reviews. Organisations need real-time detection of sensitive data access events and, critically, automated response capability to contain the threat before damage escalates.

---

## Objective

Build a multi-layered AWS security monitoring system that detects any access to a sensitive secret in Secrets Manager, delivers real-time alerts through two independent detection flows, and automatically revokes the permissions of any compromised IAM user that triggers the detection, a fully automated "kill-switch."

---

## Approach

**Phase 1 — Infrastructure & Logging**
- Created a **multi-region AWS CloudTrail** trail with log file integrity validation and CloudWatch Logs integration, configured to capture both Read and Write management events while excluding high-volume KMS noise
- Stored a test secret (`Production_Database_Credentials`) in **AWS Secrets Manager** to serve as the honeypot
- Enabled **S3 Server Access Logging** to a separate bucket to prevent recursive log loops

**Phase 2 — Detection Flow 1 (CloudWatch)**
- Created a **CloudWatch Metric Filter** on the CloudTrail log group targeting `GetSecretValue` events
- Built a **CloudWatch Alarm** set to trigger when the metric count reached ≥ 1 within a 1-minute window
- Attached an **SNS topic with email subscription** to the alarm for notification delivery

**Phase 3 — Detection Flow 2 (EventBridge)**
- Created an **Amazon EventBridge rule** with a JSON event pattern targeting `GetSecretValue` calls on `secretsmanager.amazonaws.com` via CloudTrail
- **Identified and resolved a critical AWS behaviour:** The default rule state (`ENABLED`) only matches write management events. Since `GetSecretValue` is a read-only event, the rule did not trigger initially. Resolved by updating the rule state to `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` via AWS CLI. a post-November 2023 AWS requirement
- Created a **second SNS topic** as the EventBridge target, confirming email delivery

**Phase 4 — Automated Kill-Switch (Lambda)**
- Authored a **Python 3.12 Lambda function** that parses the EventBridge/CloudTrail event payload, extracts the IAM username from the ARN, lists all attached managed policies, and detaches every policy, effectively revoking all permissions instantly
- Attached `IAMFullAccess` to the Lambda execution role
- Added the Lambda as a **second target** on the EventBridge rule alongside the SNS topic
- **Resolved a console limitation:** Adding targets to a rule in `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` state is blocked in the AWS console; added the Lambda target and granted invocation permissions entirely via AWS CLI

**Phase 5 — Red Team Test**
- Created a simulated **victim IAM user** (`VictimUser`) with `SecretsManagerReadWrite` permissions and CLI access keys
- Configured a separate AWS CLI profile (`--profile victim`) to impersonate the compromised user
- Ran `aws secretsmanager get-secret-value` as VictimUser, triggering the full detection and response pipeline
- **Confirmed kill-switch success:** A subsequent `aws s3 ls` command as VictimUser returned `AccessDenied`, with the IAM Permissions tab showing zero attached policies

---

## Outcome

- **Dual-path detection operational:** Both CloudWatch (Flow 1) and EventBridge (Flow 2) independently detected the `GetSecretValue` call and delivered email alerts
- **EventBridge proved significantly faster** than CloudWatch alarms for real-time response, a key finding for time-sensitive security scenarios
- **Automated remediation confirmed:** The Lambda kill-switch successfully stripped all IAM permissions from the compromised user within seconds of the trigger, with CloudShell and the IAM console both providing proof of revocation
- **Forensic evidence captured:** CloudTrail logs contained the full JSON event record of both the initial access and the post-revocation `AccessDenied` error, including IP address, user agent, and timestamps
- **NIST compliance alignment demonstrated:** The architecture satisfies NIST Continuous Monitoring requirements through ongoing CloudTrail visibility and automated enforcement of access controls
