import os
import pytest
from unittest.mock import patch
from src.core.onboarding import (
    generate_expected_workflow,
    classify_workflow_content,
    check_onboarding_status,
    onboard_repository,
    get_orchestrator_full_name,
)

def test_canonical_workflow_generator_default():
    """Scenario 1: Default orchestrator owner and repo in generated workflow."""
    with patch.dict(os.environ, {}, clear=True):
        workflow = generate_expected_workflow("main")
        assert "uses: Heydo-Tech/tech-risk/.github/workflows/reusable-analysis.yml@main" in workflow
        assert "uses: Heydo-Tech/tech-risk/.github/workflows/reusable-finding-recheck.yml@main" in workflow
        assert "analysis:" in workflow
        assert "recheck:" in workflow

def test_canonical_workflow_generator_custom_env():
    """Scenario 2: Custom ORCHESTRATOR_OWNER and ORCHESTRATOR_REPO environment variables."""
    with patch.dict(os.environ, {"ORCHESTRATOR_OWNER": "Heydo-Tech", "ORCHESTRATOR_REPO": "tech-risk"}):
        workflow = generate_expected_workflow("main")
        assert "uses: Heydo-Tech/tech-risk/.github/workflows/reusable-analysis.yml@main" in workflow
        assert "uses: Heydo-Tech/tech-risk/.github/workflows/reusable-finding-recheck.yml@main" in workflow

def test_classify_up_to_date():
    """Scenario 3: Classify workflow returning UP_TO_DATE for exact match."""
    expected = generate_expected_workflow("main")
    status = classify_workflow_content(expected, "main")
    assert status == "UP_TO_DATE"

def test_classify_not_onboarded():
    """Scenario 4: Classify empty or missing content as NOT_ONBOARDED."""
    assert classify_workflow_content("") == "NOT_ONBOARDED"
    assert classify_workflow_content("   \n ") == "NOT_ONBOARDED"
    assert classify_workflow_content(None) == "NOT_ONBOARDED"

def test_classify_drift_stale_ref():
    """Scenario 5: Classify outdated central workflow references as DRIFT."""
    stale_content = """name: Code Analysis
on:
  pull_request:
jobs:
  analysis:
    uses: manasvipaweria/repo-analysis/.github/workflows/reusable-analysis.yml@v1.0.0
"""
    assert classify_workflow_content(stale_content, "main") == "DRIFT"

    heydo_stale = """name: Code Analysis
on:
  push:
jobs:
  analysis:
    uses: Heydo-Tech/repo-analysis/.github/workflows/reusable-analysis.yml@main
"""
    assert classify_workflow_content(heydo_stale, "main") == "DRIFT"

def test_classify_customized_extra_jobs():
    """Scenario 6: Classify workflows with custom jobs as CUSTOMIZED."""
    customized_content = """name: Code Analysis
on:
  push:
jobs:
  analysis:
    uses: Heydo-Tech/tech-risk/.github/workflows/reusable-analysis.yml@main
  custom_build_step:
    runs-on: ubuntu-latest
    steps:
      - run: echo "building..."
"""
    assert classify_workflow_content(customized_content, "main") == "CUSTOMIZED"

def test_onboard_repository_skips_customized():
    """Scenario 7: onboard_repository skips repositories with CUSTOMIZED workflows."""
    mock_preflight = ("CUSTOMIZED", {"default_branch": "main", "current_content": "custom"})
    res = onboard_repository("fake_token", "Heydo-Tech", "custom-repo", preflight=mock_preflight)
    assert res["status"] == "CUSTOMIZED"
    assert "pr_number" not in res

def test_workflow_dispatch_input_names():
    """Scenario 8: Validate all workflow dispatch input names and recheck parameter mappings in canonical workflow."""
    workflow = generate_expected_workflow("main")
    required_inputs = [
        "run_id",
        "recheck_finding_id",
        "recheck_attempt_id",
        "recheck_tool",
        "recheck_rule_id",
        "recheck_file_path",
        "recheck_line_start",
        "recheck_line_end",
        "recheck_commit_sha",
    ]
    for inp in required_inputs:
        assert f"{inp}:" in workflow, f"Input '{inp}' missing from workflow_dispatch configuration"

    mappings = [
        "finding_id: ${{ inputs.recheck_finding_id }}",
        "attempt_id: ${{ inputs.recheck_attempt_id }}",
        "tool: ${{ inputs.recheck_tool }}",
        "rule_id: ${{ inputs.recheck_rule_id }}",
        "file_path: ${{ inputs.recheck_file_path }}",
        "line_start: ${{ inputs.recheck_line_start }}",
        "line_end: ${{ inputs.recheck_line_end }}",
        "commit_sha: ${{ inputs.recheck_commit_sha }}",
    ]
    for m in mappings:
        assert m in workflow, f"Mapping '{m}' missing or mismatched in recheck job"

def test_onboard_sh_template_consistency():
    """Scenario 9: Verify onboard.sh workflow output consistency with generate_expected_workflow()."""
    onboard_sh_path = os.path.join(os.path.dirname(__file__), "..", "onboard.sh")
    assert os.path.exists(onboard_sh_path)
    with open(onboard_sh_path, "r", encoding="utf-8") as f:
        sh_content = f.read()

    assert "ORCHESTRATOR_OWNER=" in sh_content
    assert "ORCHESTRATOR_REPO=" in sh_content
    assert "reusable-analysis.yml" in sh_content
    assert "reusable-finding-recheck.yml" in sh_content
    assert "file_path: \\${{ inputs.recheck_file_path }}" in sh_content
    assert "recheck_finding_id" in sh_content

