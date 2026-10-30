from research.revocation_toctou import run_experiment


def test_revocation_toctou_experiment_reports_expected_interleavings():
    report = run_experiment()

    assert report["experiment"] == "chainguard_revocation_toctou_v1"
    before, after = report["cases"]

    assert before["scenario"] == "revoked_before_gateway_check"
    assert before["gateway_rejected"] is True
    assert before["revoked_before_adapter"] is True
    assert before["adapter_calls"] == 0

    assert after["scenario"] == "revoked_after_gateway_check_before_adapter"
    assert after["gateway_rejected"] is False
    assert after["revoked_before_adapter"] is True
    assert after["adapter_calls"] == 1
    assert after["observed_status"] == "executed_after_revocation"
