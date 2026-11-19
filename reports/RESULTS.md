# SplitSentinel measured results

Original synthetic policy stress cases. Counts are findings, not unique leaked records.

| Scenario | Records | Status | Policy violations | Review findings |
|---|---:|---|---:|---:|
| clean | 90 | pass | 0 | 0 |
| contaminated | 90 | fail | 5 | 1 |
| near_only | 90 | review | 0 | 1 |

12 tests passed; all three snapshots reconstructed with identical logical reports.
A pass only means the implemented checks found no violations of the supplied policy. It does not certify absence of all leakage. Near-text matches require human review. No ML model is trained or scored.
