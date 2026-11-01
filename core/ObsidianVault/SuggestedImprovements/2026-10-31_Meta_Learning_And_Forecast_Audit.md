---
type: meta-learning-audit
date: 2026-10-31
brier_score: 0.102
ece_pct: 4.2
top_engine: cbr_fingerprints
status: ACTIVE
---

# Meta-Learning & Next-Tool Forecast Calibration Audit (2026-10-31)

> [!IMPORTANT]
> Automatically synthesized by **Engine 13 (`meta_learner.py`)** to audit reasoning accuracy, calibrate tool-forecasting weights, and prune redundant diagnostic steps.

- **Parent Index:** [[00_MEMORY_INDEX]] | [[00_SUGGESTED_IMPROVEMENTS_INDEX]]

### Engine 17: Meta-Learning Hedge Arbiter & Forecast Calibration (`0.13 ms`)
- **Global Forecast Brier Score:** `0.1020` (Lower is better; `< 0.15` = High Calibration)
- **Expected Calibration Error (ECE):** `4.20%`
- **Top Authority Engine Family:** **`cbr_fingerprints`** (Weight `1.200`)

#### Multiplicative-Weights (Hedge) Engine Attribution Table
| Rank | Engine Family | Hedge Trust Weight ($w_k$) | Empirical Hit Rate | Family Brier Score |
| :--- | :--- | :--- | :--- | :--- |
| **1** | `cbr_fingerprints` (Engine 11: CBR Failure-to-Fix Fingerprints) | **`1.200`** | `100.0%` (8 evals) | `0.0600` |
| **2** | `mdp_tactical` (Engine 15: Hierarchical Tactical MDP & Optimal Stopping) | **`1.150`** | `91.7%` (12 evals) | `0.0900` |
| **3** | `rl_network_policy` (Engine 19: Dual-Mode Pessimistic Q_LCB Trajectory RL & Network World-Model) | **`1.150`** | `91.7%` (12 evals) | `0.0850` |
| **4** | `spectral_manifold_pca` (Engine 20: Prototype-Anchored K-Means++, SVD PCA & Mahalanobis Shield) | **`1.120`** | `90.0%` (10 evals) | `0.0960` |
| **5** | `bayesian_eig` (Engine 4: Bayesian Abduction & Shannon EIG) | **`1.100`** | `83.3%` (12 evals) | `0.1100` |
| **6** | `vsa_somatic` (Engine 7: 32,768-D VSA & Damasio Somatic Valence) | **`1.050`** | `90.0%` (10 evals) | `0.1100` |

#### META-MIND Channel Health & Temporal Pacing Telemetry
- **Serial/UART Channel Status:** **`HEALTHY`** (Sessions=`0`, Drops=`0`, Consecutive Drops=`0`)
- **Hardware Pacing Policy:** `-o 15 -O 120` | Inter-Session Cooldown `>=1.6s` | Max `1` command per burst
