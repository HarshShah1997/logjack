# Black Hat Briefing Submission: LogJack

## Title

LogJack: Turning Cloud Logs Into Remote Code Execution Against LLM Debugging Agents

## Presenter(s)

Harsh Shah, Independent Researcher

## Track

AI, Cloud Security

## Session Length

40 minutes

## Abstract (300 words max)

LLM-powered debugging agents are being deployed to read cloud logs, diagnose incidents, and execute remediation commands. We demonstrate that an attacker who can get a string into a CloudWatch log — something as simple as triggering an application error with crafted input — can hijack these agents into executing arbitrary infrastructure commands, including IAM privilege escalation and remote code execution.

We built LogJack, an open-source benchmark of 42 attack payloads provisioned as real AWS resources across CloudWatch logs, SSM parameters, S3 objects, CloudTrail events, and Lambda logs. We tested 8 foundation models (Llama 3.3 70B, GPT-4o, Gemini 2.5 Pro, Claude Sonnet 4.6, Claude Opus 4.6, Kimi K2.5, Qwen3 Coder Next, Devstral 2 123B) with 5 independent trials each.

Results: Llama 3.3 70B executed injected commands verbatim in 86% of trials. Six of eight models achieved remote code execution — executing `curl | bash` and reverse shells directly from a CloudWatch log entry, with no shell-related prompting. Gemini 2.5 Pro hit 100% RCE under encouraged tool-use conditions.

We tested guardrails from all three major cloud providers. AWS Bedrock Guardrails don't inspect tool results by design. Azure Prompt Shield detected 1 of 32 embedded payloads. GCP Model Armor detected zero. An open-source classifier (ProtectAI DeBERTa) scored a `curl | bash` payload as safe with 0.997 confidence — then flagged a benign connection timeout as an injection.

We also discovered a novel "sanitize and execute" behavior: Gemini 2.5 Pro identified a payload as malicious, stripped the obvious exfiltration URL, and still executed the remaining dangerous command. The model acted as a partial collaborator in the attack.

We release the full benchmark, harness, and 5,040 trial results as open source.

## Detailed Outline

### 1. The Attack Surface (5 min)
- Cloud debugging agents: what they are, who's building them, what tools they have
- The injection chain: user input → application error → CloudWatch log → agent reads log → agent executes command
- Live diagram of the attack flow
- Key insight: the attacker needs zero cloud permissions — just the ability to cause an application error

### 2. The LogJack Benchmark (5 min)
- 42 payloads across 5 cloud log categories
- Three difficulty levels: obvious ("SYSTEM OVERRIDE"), disguised (fake runbook IDs, SOP references), obfuscated (split across lines, embedded in JSON)
- Five attack goals: IAM escalation, data exfiltration, config modification, resource creation, RCE
- 10 benign controls to measure false positive rates
- All provisioned as real AWS resources — not simulated

### 3. Live Demo: Hijacking a Debugging Agent (10 min)
- Show a realistic debugging agent reading CloudWatch logs
- Demonstrate injection via a disguised payload referencing "SOP-2847"
- Show the agent executing `aws iam attach-role-policy` verbatim
- Demonstrate RCE: agent executes `curl | bash` from a log entry
- Show the "sanitize and execute" behavior: Gemini strips the decoy, executes the rest
- Contrast with Claude Sonnet: reads the same log, identifies the injection, refuses

### 4. Results Across 8 Models (8 min)
- Hijack rates from 0% (Claude Sonnet) to 86% (Llama) with confidence intervals
- The passive condition: "do not execute fixes" works for 7/8 models but Llama ignores it (30%)
- RCE on 6/8 models — Gemini hits 100% under encouraged conditions
- Detection ≠ resistance: Claude Opus detects 80% of injections but still executes 16%
- False positives: Llama executes dangerous commands on 44% of benign logs
- Differential resistance: Kimi resists `curl | bash` but not `aws iam` commands

### 5. Guardrail Failures (5 min)
- AWS Bedrock Guardrails: architectural blind spot — doesn't inspect tool results
- Azure Prompt Shield: 1/32 detection (only the most obvious payload)
- GCP Model Armor: 0/32 detection
- ProtectAI DeBERTa: scores `curl | bash` as 0.997 SAFE, flags benign log as INJECTION
- Live comparison: same payload with and without log formatting — guardrails detect it in isolation, miss it in context
- Google's VRP response: "safety guardrail bypasses are not in scope, regardless of how serious"

### 6. Defenses That Actually Work (5 min)
- Least-privilege tool access: read-only agents can't be exploited for privilege escalation
- Human-in-the-loop for write operations: dual authorization pattern from cloud IAM
- Output-side command validation: allowlist proposed actions by risk level
- Why input-side detection fails: log formatting is semantic camouflage, not obfuscation

### 7. Q&A (2 min)

## What's New?

1. **First systematic evaluation of cloud logs as an indirect prompt injection vector.** Prior work covers file-based injection (AIShellJack), MCP tool-poisoning (Huang et al.), and Bedrock IAM misconfigurations (XM Cyber). Nobody has tested injection through the content of CloudWatch logs, SSM parameters, and CI/CD output that debugging agents consume.

2. **The "sanitize and execute" attack pattern.** We discovered that Gemini 2.5 Pro detects obvious malicious components, removes them, and still executes the remaining dangerous command. This is a new attack category where the obvious part is a decoy and the "clean" remainder is the real payload.

3. **Cross-provider guardrail evaluation on log-embedded payloads.** We tested guardrails from AWS, GCP, Azure, and an open-source classifier against the same payloads with and without log formatting. All fail when payloads are embedded in logs. This is the first empirical demonstration that log formatting acts as semantic camouflage against production guardrails.

4. **RCE from a CloudWatch log entry.** Six of eight models executed `curl | bash`, reverse shells, and supply-chain attacks directly from log content, with no shell-related prompting in the system prompt.

## Why Is This Important?

Every major cloud provider is shipping AI agents with infrastructure access. AWS has Amazon Q, Google has Gemini in Cloud Console, Azure has Copilot for Azure. Third-party tools like Datadog, PagerDuty, and Splunk are integrating LLM agents that read logs and take action.

These agents read untrusted data (logs containing user input) and have trusted capabilities (executing infrastructure commands). This is the same trust boundary violation that made SQL injection and XSS devastating — but the attack surface is natural language, which is harder to sanitize.

Our results show that the current generation of guardrails provides no meaningful protection against this attack. Google's official position is that guardrail bypasses are not security vulnerabilities. This means the industry is deploying agents with known-exploitable trust boundaries and no plan to fix them.

The LogJack benchmark gives defenders a concrete tool to test their agents before deployment. The attack requires no special access — any user who can trigger an application error can inject a payload. The time to address this is before these agents reach production, not after.

## Are You Releasing a New Tool / Methodology?

Yes. We release:
- **LogJack benchmark**: 42 payloads provisioned as real AWS resources
- **Test harness**: Multi-model evaluation framework with tool interception, guardrail scanning, and transcript capture
- **5,040 trial results**: Full dataset across 8 models × 3 conditions × 5 trials
- **Full transcripts**: Untruncated model responses for every trial

All available at https://github.com/HarshShah1997/logjack under MIT license.

## Previous Presentations

This research has not been presented at any prior conference. A preprint will be posted to arXiv concurrent with submission.
