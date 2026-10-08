"""Phase 7: seeded scenario simulation and evaluation.

``harness`` runs the five scenarios through the real runtime (pipeline, risk
engine, response service, event bus) on seeded simulated traffic; ``ws_latency``
measures event delivery over a real Socket.IO connection; ``report`` writes CSVs,
plots and a summary to ``docs/evaluation/phase7``. Every number in the output is
measured by these scripts; nothing is estimated or hand-entered.
"""
