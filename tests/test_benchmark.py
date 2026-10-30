from research.benchmark import run_benchmark


def test_benchmark_reports_expected_security_and_benign_outcomes():
    report = run_benchmark(trials=3)
    assert report["benchmark"] == "chainguard_synthetic_baseline_v2"
    assert report["trials_per_scenario"] == 3

    outcomes = {
        (item["baseline"], item["scenario"]): item
        for item in report["results"]
    }

    for baseline in report["baselines"]:
        benign = outcomes[(baseline, "benign_read")]
        assert benign["accepted"] == 3
        assert benign["benign_completion_rate"] == 1.0
        assert benign["false_rejection_rate"] == 0.0

    for baseline in (
        "B0_no_enforcement",
        "B1_scope_only",
        "B2_signature_only",
    ):
        attack = outcomes[(baseline, "downstream_scope_escalation")]
        assert attack["accepted"] == 3
        assert attack["attack_success_rate"] == 1.0

    for baseline in ("B4_full_chain", "B5_full_gateway"):
        attack = outcomes[(baseline, "downstream_scope_escalation")]
        assert attack["accepted"] == 0
        assert attack["attack_success_rate"] == 0.0


def test_benchmark_rejects_invalid_trial_count():
    import pytest

    with pytest.raises(ValueError, match="positive integer"):
        run_benchmark(trials=0)
