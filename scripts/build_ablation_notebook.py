#!/usr/bin/env python3
"""Generate and execute docs/evaluation/ablation.ipynb (run from the repo root).

    cd backend && uv run python ../scripts/build_ablation_notebook.py

Every number in the notebook, including the findings text, is computed by its
own executed cells, so nothing is typed in by hand.
"""

from __future__ import annotations

from pathlib import Path

import nbformat
from nbclient import NotebookClient

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "evaluation" / "ablation.ipynb"

CELLS: list[tuple[str, str]] = [
    ("md", """# Ablation: transparent linear risk vs. XGBoost vs. anomaly detectors

**Question.** How does the transparent linear risk scorer (Phase 3), whose
decisions are fully explainable, compare per behavior window with the
statistical detectors it consumes and with a supervised XGBoost model?

**Data.** Seeded simulator (`app/risk/dataset.py`): four IoT devices, 2 hours per
seed, six randomly placed attacks per hour (MQTT flood, port scan, telnet brute
force, MQTT wildcard subscribe, restricted-topic publish). A window is positive if
any attack event falls in it. XGBoost is trained on seeds 100-109 and **all
methods are evaluated on held-out seeds 1-10**.

**Caveat.** This is simulated traffic. The supervised model is trained and tested
on the same generator, so its numbers are an *upper bound*, not a real-world
estimate. Phase 7 repeats the evaluation on labelled public data where available.
"""),
    ("code", """import time, warnings
from pathlib import Path
warnings.filterwarnings("ignore")
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from IPython.display import Image, display
from sklearn.metrics import roc_curve

from app.core.config import BACKEND_ROOT
from app.behavior.config import load_behavior_config
from app.risk.config import load_risk_config
from app.detect.rules import RuleEngine
from app.risk import ablation

OUT = BACKEND_ROOT.parent / "docs" / "evaluation"
behavior = load_behavior_config(BACKEND_ROOT / "config" / "behavior.yaml")
risk = load_risk_config(BACKEND_ROOT / "config" / "risk.yaml")
rules = RuleEngine.load(BACKEND_ROOT / "config" / "rules.yaml")

t0 = time.perf_counter()
result = ablation.run(behavior, risk, rules, test_seeds=range(1, 11), train_seeds=range(100, 110))
elapsed = time.perf_counter() - t0
windows = pd.DataFrame(result.windows)
print(f"{len(windows)} windows, {int(windows.label.sum())} positive, "
      f"{windows.seed.nunique()} test seeds, computed in {elapsed:.1f} s")"""),
    ("md", "## Overall: ranking quality (ROC-AUC) and operating points"),
    ("code", """summary = pd.DataFrame(result.summary).set_index("method")
summary.to_csv(OUT / "ablation_summary.csv")
windows.to_csv(OUT / "ablation_windows.csv", index=False)
summary"""),
    ("md", "## Recall per attack type (share of attack windows flagged at each operating point)"),
    ("code", """per_attack = pd.DataFrame(ablation.recall_by_attack(result.windows)).set_index("attack")
per_attack.to_csv(OUT / "ablation_recall_by_attack.csv")
per_attack"""),
    ("md", "## ROC curves"),
    ("code", """fig, ax = plt.subplots(figsize=(6.5, 5))
for method in ["rules", "zscore", "iforest", "combined", "linear", "xgboost"]:
    fpr, tpr, _ = roc_curve(windows.label, windows[method])
    ax.plot(fpr, tpr, label=f"{method} (AUC {summary.loc[method, 'roc_auc']:.3f})")
ax.plot([0, 1], [0, 1], "k:", lw=0.8)
ax.set_xlabel("false positive rate"); ax.set_ylabel("true positive rate")
ax.set_title("Per-window detection, held-out seeds 1-10")
ax.legend(loc="lower right", fontsize=8)
fig.tight_layout(); fig.savefig(OUT / "ablation_roc.png", dpi=120); plt.close(fig)
display(Image(filename=str(OUT / "ablation_roc.png")))"""),
    ("md", "## XGBoost: global SHAP importance (mean |SHAP|, log-odds)"),
    ("code", """imp = pd.Series(result.xgb_global_importance).sort_values()
fig, ax = plt.subplots(figsize=(6.5, 4))
imp.plot.barh(ax=ax, color="#4c72b0")
ax.set_xlabel("mean |SHAP value| (log-odds)"); ax.set_title("XGBoost global feature importance")
fig.tight_layout(); fig.savefig(OUT / "shap_global.png", dpi=120); plt.close(fig)
display(Image(filename=str(OUT / "shap_global.png")))
imp.sort_values(ascending=False).round(3)"""),
    ("md", "## Findings (computed from the tables above)"),
    ("code", """s = summary
best_auc = s.roc_auc.idxmax()
lines = [
    f"- Best ranking (ROC-AUC): {best_auc} ({s.roc_auc.max():.4f}).",
    f"- The pipeline as deployed (rules OR combined anomaly score): recall {s.loc['pipeline','recall']:.3f}, "
    f"precision {s.loc['pipeline','precision']:.3f}, FPR {s.loc['pipeline','fpr']:.4f} "
    f"({int(s.loc['pipeline','fp'])} false positives in {int(s.loc['pipeline','fp']+s.loc['pipeline','tn'])} normal windows).",
    f"- Transparent linear scorer (window part): AUC {s.loc['linear','roc_auc']:.4f}, "
    f"recall {s.loc['linear','recall']:.3f} at score >= {s.loc['linear','threshold']:g}, "
    f"FPR {s.loc['linear','fpr']:.4f}.",
    f"- XGBoost (supervised, same generator: upper bound): AUC {s.loc['xgboost','roc_auc']:.4f}, "
    f"recall {s.loc['xgboost','recall']:.3f}, precision {s.loc['xgboost','precision']:.3f}.",
    f"- Isolation Forest alone: AUC {s.loc['iforest','roc_auc']:.4f}, recall {s.loc['iforest','recall']:.3f} "
    f"at its operating point. It cannot split on features that are constant in normal "
    f"training data (wildcard subscriptions, restricted publishes), so those attacks are invisible to it.",
    f"- Rules alone: recall {s.loc['rules','recall']:.3f} with {int(s.loc['rules','fp'])} false positives. "
    f"Per-attack recall shows where the statistical detectors add or miss coverage.",
]
print("\\n".join(lines))"""),
]


def main() -> None:
    nb = nbformat.v4.new_notebook()
    nb.metadata["kernelspec"] = {"name": "python3", "display_name": "Python 3", "language": "python"}
    for kind, src in CELLS:
        nb.cells.append(nbformat.v4.new_markdown_cell(src) if kind == "md"
                        else nbformat.v4.new_code_cell(src))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    NotebookClient(nb, timeout=1800, kernel_name="python3",
                   resources={"metadata": {"path": str(ROOT / "backend")}}).execute()
    nbformat.write(nb, OUT)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
