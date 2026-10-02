import pytest
from unittest.mock import MagicMock, patch
from onboard_org import GitHubClient, generate_template

@pytest.fixture
def mock_client():
    client = GitHubClient("fake_token")
    client._request = MagicMock()
    return client

def test_generate_template():
    content = generate_template("v1")
    assert "uses: manasvipaweria/tech-risk/.github/workflows/reusable-analysis.yml@v1" in content
    assert "enable_codex: true" in content
    assert "enable_deslint: true" in content
    assert "enable_design_ai: true" in content
    assert "${{ secrets.SNYK_TOKEN }}" in content
    assert "${{ secrets.OPENAI_API_KEY }}" in content

def test_get_repos_pagination(mock_client):
    # Mock pagination logic
    mock_client._request.side_effect = [
        [{"full_name": "org/repo1", "archived": False, "default_branch": "main"}] * 100,
        [{"full_name": "org/repo2", "archived": False, "default_branch": "main"}] * 50
    ]
    repos = mock_client.get_repos_list("orgs", "org")
    assert len(repos) == 150
    assert mock_client._request.call_count == 2

def test_get_repos_ignores_archived(mock_client):
    mock_client._request.side_effect = [
        [
            {"full_name": "org/repo1", "archived": False, "default_branch": "main"},
            {"full_name": "org/repo2", "archived": True, "default_branch": "main"}
        ]
    ]
    repos = mock_client.get_repos_list("users", "owner")
    assert len(repos) == 1
    assert repos[0]["full_name"] == "org/repo1"

def test_get_repo(mock_client):
    mock_client._request.return_value = {"full_name": "owner/repo", "archived": False, "default_branch": "main"}
    repo = mock_client.get_repo("owner/repo")
    assert repo["full_name"] == "owner/repo"

def test_get_file_content_missing(mock_client):
    mock_client._request.return_value = None
    content, sha = mock_client.get_file_content("org/repo1", ".github/workflows/code-analysis.yml")
    assert content is None
    assert sha is None

def test_get_file_content_exists(mock_client):
    import base64
    fake_content = base64.b64encode(b"name: Code Analysis").decode("utf-8")
    mock_client._request.return_value = {"content": fake_content, "sha": "abcdef"}
    content, sha = mock_client.get_file_content("org/repo1", ".github/workflows/code-analysis.yml")
    assert content == "name: Code Analysis"
    assert sha == "abcdef"

@patch("onboard_org.GitHubClient")
@patch("os.environ.get")
@patch("sys.argv", ["onboard_org.py", "--org", "Heydo-Tech"])
def test_main_org_only(mock_env_get, mock_client_class):
    mock_env_get.return_value = "fake_token"
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    mock_client.get_repos_list.return_value = [
        {"full_name": "Heydo-Tech/repo1", "default_branch": "main"}
    ]
    mock_client.get_file_content.return_value = (None, None)
    mock_client.get_open_onboarding_prs.return_value = []
    
    from onboard_org import main
    main()
    mock_client.get_repos_list.assert_called_with("orgs", "Heydo-Tech")
    mock_client.create_pr.assert_called_once()

@patch("onboard_org.GitHubClient")
@patch("os.environ.get")
@patch("sys.argv", ["onboard_org.py", "--owner", "user1", "--repo", "user1/repo2"])
def test_main_owner_and_repo_dedup(mock_env_get, mock_client_class):
    mock_env_get.return_value = "fake_token"
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    # user1 has repo1 and repo2
    mock_client.get_repos_list.return_value = [
        {"full_name": "user1/repo1", "default_branch": "main"},
        {"full_name": "user1/repo2", "default_branch": "main"}
    ]
    # Explicit repo is also user1/repo2
    mock_client.get_repo.return_value = {"full_name": "user1/repo2", "default_branch": "main"}
    mock_client.get_file_content.return_value = (None, None)
    mock_client.get_open_onboarding_prs.return_value = []
    
    from onboard_org import main
    main()
    # It should only create PRs for repo1 and repo2 exactly once (total 2 PRs)
    assert mock_client.create_pr.call_count == 2
    mock_client.get_repos_list.assert_called_with("users", "user1")
    mock_client.get_repo.assert_called_with("user1/repo2")

@patch("onboard_org.GitHubClient")
@patch("os.environ.get")
@patch("sys.argv", ["onboard_org.py", "--owner", "user1", "--limit", "1"])
def test_main_limit(mock_env_get, mock_client_class):
    mock_env_get.return_value = "fake_token"
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    mock_client.get_repos_list.return_value = [
        {"full_name": "user1/repo1", "default_branch": "main"},
        {"full_name": "user1/repo2", "default_branch": "main"}
    ]
    mock_client.get_file_content.return_value = (None, None)
    mock_client.get_open_onboarding_prs.return_value = []
    
    from onboard_org import main
    main()
    # It should only create 1 PR due to the limit
    assert mock_client.create_pr.call_count == 1

@patch("sys.argv", ["onboard_org.py"])
def test_main_missing_args(capsys):
    from onboard_org import main
    with pytest.raises(SystemExit):
        main()
    captured = capsys.readouterr()
    assert "At least one target" in captured.err
