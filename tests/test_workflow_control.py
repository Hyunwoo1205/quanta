"""Host cancellation preserves completed evidence and checks publication boundaries."""
import copy
import uuid

import pytest

from quanta.run_store import read_bundle, validate_run_report, write_bundle
from quanta.workflow import WorkflowCancelled, run_experiment


def experiment(pair, count=2):
    value = copy.deepcopy(pair)
    value["definition"]["observables"] = ["energy"]
    value["definition"]["protocol"] = {
        "steps": [{"step_id": f"measure{i}", "operation": "energy_forces", "source": "initial", "overrides": []}
                  for i in range(count)], "sweep": {"axes": []}}
    return value


def assert_cancelled(report):
    assert report["valid"], report["errors"]
    result = report["result"]
    assert result["execution_status"] == "CANCELLED", result["errors"]
    assert result["partial"] is True
    assert any(error["code"] == "CANCELLED" for error in result["errors"])
    checked = validate_run_report(report)
    assert checked["valid"], checked["errors"]
    return result


def test_host_run_id_binds_result_runtime_states_and_progress(pair):
    ident = str(uuid.uuid4())
    progress = []
    report = run_experiment(experiment(pair), run_id=ident, progress_callback=progress.append)
    assert report["result"]["execution_status"] == "SUCCEEDED", report["result"]["errors"]
    assert report["result"]["run_id"] == report["resolved_record"]["run_id"] == ident
    assert all(state["producer"].get("run_id", ident) == ident for state in report["result"]["states"])
    assert progress[0] == {"completed_steps": 0, "total_steps": 2, "active_step": "measure0", "active_branch": 0}
    assert progress[-1] == {"completed_steps": 2, "total_steps": 2, "active_step": None, "active_branch": None}
    assert [p["completed_steps"] for p in progress] == sorted(p["completed_steps"] for p in progress)
    assert validate_run_report(report)["valid"]


@pytest.mark.parametrize("identifier", ["bad", str(uuid.uuid1()), str(uuid.uuid4()).upper(), 17])
def test_host_run_id_must_be_canonical_v4(pair, identifier):
    report = run_experiment(experiment(pair, 1), run_id=identifier)
    assert report["result"] is None
    assert report["errors"][0]["code"] == "INPUT_SEMANTIC"


def test_cancel_before_first_calculation_has_no_scientific_state(pair, tmp_path):
    progress = []

    def cancel():
        raise WorkflowCancelled()

    report = run_experiment(experiment(pair), control_check=cancel, progress_callback=progress.append)
    result = assert_cancelled(report)
    assert all(step["outcome"] == "CANCELLED" for step in result["steps"])
    assert result["states"] == []
    assert progress[-1] == {"completed_steps": 0, "total_steps": 2, "active_step": None, "active_branch": None}
    assert report["resolved_record"]["runtime_evidence"]["effective_step_inputs"] == []
    write_bundle(report, tmp_path / "cancelled")
    assert read_bundle(tmp_path / "cancelled")["result"] == result


def test_cancel_during_dispatch_prevents_output_state(pair, monkeypatch):
    import quanta.workflow as workflow
    requested = False

    def control():
        if requested:
            raise WorkflowCancelled()

    def dispatch(definition, operation, registry, check):
        nonlocal requested
        requested = True
        check()
        raise AssertionError("Cancelled dispatch must not continue")

    monkeypatch.setattr(workflow, "_dispatch", dispatch)
    report = run_experiment(experiment(pair), control_check=control)
    result = assert_cancelled(report)
    assert [step["outcome"] for step in result["steps"]] == ["CANCELLED", "CANCELLED"]
    assert all(state["producer"]["kind"] != "step" for state in result["states"])
    assert result["steps"][0]["source_binding"] is not None
    assert result["steps"][0]["payload"] is None


def test_cancel_between_steps_retains_completed_payload_and_artifacts(pair, tmp_path):
    requested = False

    def progress(snapshot):
        nonlocal requested
        if snapshot["completed_steps"] == 1:
            requested = True

    def control():
        if requested:
            raise WorkflowCancelled()

    report = run_experiment(experiment(pair), control_check=control, progress_callback=progress)
    result = assert_cancelled(report)
    first, second = result["steps"]
    assert first["outcome"] == "SUCCEEDED" and first["partial"] is False
    assert first["payload"]["operation"] == "energy_forces"
    assert first["state_ref"] in {state["state_id"] for state in result["states"]}
    assert first["artifacts"][0]["artifact_id"] in report["artifact_contents"]
    assert second["outcome"] == "CANCELLED" and second["state_ref"] is None
    write_bundle(report, tmp_path / "partial")
    assert read_bundle(tmp_path / "partial")["result"] == result


def test_cancel_at_final_publication_keeps_completed_work_but_never_success(pair):
    requested = False

    def progress(snapshot):
        nonlocal requested
        if snapshot["completed_steps"] == snapshot["total_steps"]:
            requested = True

    def control():
        if requested:
            raise WorkflowCancelled()

    report = run_experiment(experiment(pair, 1), control_check=control, progress_callback=progress)
    result = assert_cancelled(report)
    assert result["steps"][0]["outcome"] == "SUCCEEDED"
    assert result["steps"][0]["partial"] is False


def test_cancel_after_kernel_return_retains_payload_without_admitting_state(pair, monkeypatch):
    import quanta.workflow as workflow
    original = workflow._dispatch
    requested = False

    def dispatch(*args):
        nonlocal requested
        payload = original(*args)
        requested = True
        return payload

    def control():
        if requested:
            raise WorkflowCancelled()

    monkeypatch.setattr(workflow, "_dispatch", dispatch)
    report = run_experiment(experiment(pair, 1), control_check=control)
    result = assert_cancelled(report)
    assert result["steps"][0]["payload"] is not None
    assert result["steps"][0]["state_ref"] is None
    assert all(state["producer"]["kind"] != "step" for state in result["states"])


def test_real_relax_kernel_preserves_wrapped_cancellation_code(pair, monkeypatch):
    import quanta.workflow as workflow
    original = workflow._dispatch
    requested = False

    def dispatch(*args):
        nonlocal requested
        requested = True
        return original(*args)

    def control():
        if requested:
            raise WorkflowCancelled()

    authored = experiment(pair, 1)
    authored["definition"]["protocol"]["steps"][0]["operation"] = "relax"
    monkeypatch.setattr(workflow, "_dispatch", dispatch)
    report = run_experiment(authored, control_check=control)
    result = assert_cancelled(report)
    assert result["steps"][0]["outcome"] == "CANCELLED"
    assert result["steps"][0]["state_ref"] is None


def test_cancel_during_final_evidence_validation_is_checked_again(pair, monkeypatch):
    import quanta.run_store as store
    requested = False
    original = store.validate_run_report

    def verification(report, **kwargs):
        nonlocal requested
        checked = original(report, **kwargs)
        requested = True
        return checked

    def control():
        if requested:
            raise WorkflowCancelled()

    monkeypatch.setattr(store, "validate_run_report", verification)
    report = run_experiment(experiment(pair, 1), control_check=control)
    assert_cancelled(report)


def test_saved_cancelled_status_requires_cancellation_diagnostic(pair):
    report = run_experiment(experiment(pair, 1))
    report["result"].update(execution_status="CANCELLED", partial=True)
    assert not validate_run_report(report)["valid"]


def test_cancelled_step_cannot_be_stored_as_failed_execution(pair):
    report = run_experiment(experiment(pair, 1), control_check=lambda: (_ for _ in ()).throw(WorkflowCancelled()))
    assert_cancelled(report)
    report["result"]["execution_status"] = "FAILED"
    assert not validate_run_report(report)["valid"]


def test_completed_output_after_a_cancelled_step_is_rejected(pair):
    report = run_experiment(experiment(pair))
    assert report["result"]["execution_status"] == "SUCCEEDED", report["result"]["errors"]
    first = report["result"]["steps"][0]
    removed_output = first["state_ref"]
    report["result"]["states"][:] = [state for state in report["result"]["states"]
                                      if state["state_id"] != removed_output]
    del report["state_content_hashes"][removed_output]
    del report["resolved_record"]["runtime_evidence"]["state_unit_contexts"][removed_output]
    first.update(outcome="CANCELLED", state_ref=None, partial=True)
    report["result"].update(execution_status="CANCELLED", partial=True)
    report["result"]["errors"].append({"code": "CANCELLED", "category": "runtime", "message": "Cancellation requested",
                                       "path": None, "step_id": first["step_id"], "branch_index": 0,
                                       "retryable": False, "details": {}})
    checked = validate_run_report(report)
    assert not checked["valid"]
    assert "after cancellation" in checked["errors"][0]["message"]
