import os
import sys
import json
import base64
import time
import argparse
import urllib.request
import urllib.error

from src.core.onboarding import generate_expected_workflow, classify_workflow_content

GITHUB_API_URL = "https://api.github.com"
DEFAULT_REF = "main"
TEMPLATE_PATH = ".github/workflows/code-analysis.yml"

def generate_template(orchestrator_ref):
    return generate_expected_workflow(orchestrator_ref)

class GitHubClient:
    def __init__(self, token):
        self.token = token
        
    def _request(self, method, endpoint, data=None):
        url = f"{GITHUB_API_URL}{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Repo-Onboarder"
        }
        
        body = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        
        retries = 3
        for attempt in range(retries):
            try:
                with urllib.request.urlopen(req) as response:
                    content = response.read().decode("utf-8")
                    return json.loads(content) if content else {}
            except urllib.error.HTTPError as e:
                if e.code == 403 and "rate limit" in str(e.headers).lower():
                    reset_time = int(e.headers.get("X-RateLimit-Reset", time.time() + 60))
                    sleep_time = max(1, reset_time - int(time.time()))
                    print(f"[!] Rate limited. Sleeping for {sleep_time} seconds...")
                    time.sleep(sleep_time)
                    continue
                elif e.code == 404:
                    return None
                else:
                    try:
                        err_data = json.loads(e.read().decode("utf-8"))
                        raise Exception(f"HTTP {e.code}: {err_data}")
                    except:
                        raise e
            except Exception as e:
                raise e
        raise Exception("Max retries exceeded")

    def get_repos_list(self, prefix, entity):
        repos = []
        page = 1
        while True:
            res = self._request("GET", f"/{prefix}/{entity}/repos?per_page=100&page={page}")
            if res is None:
                break
            if not res:
                break
            for r in res:
                if not r.get("archived"):
                    repos.append(r)
            if len(res) < 100:
                break
            page += 1
        return repos

    def get_repo(self, repo_full_name):
        res = self._request("GET", f"/repos/{repo_full_name}")
        if res and not res.get("archived"):
            return res
        return None

    def get_file_content(self, repo_full_name, path):
        res = self._request("GET", f"/repos/{repo_full_name}/contents/{path}")
        if res and "content" in res:
            return base64.b64decode(res["content"]).decode("utf-8"), res["sha"]
        return None, None

    def get_open_onboarding_prs(self, repo_full_name):
        res = self._request("GET", f"/repos/{repo_full_name}/pulls?state=open")
        if not res:
            return []
        return [pr for pr in res if pr.get("head", {}).get("ref", "").startswith("setup/code-analysis")]

    def get_default_branch_sha(self, repo_full_name, branch):
        res = self._request("GET", f"/repos/{repo_full_name}/git/ref/heads/{branch}")
        if res and "object" in res:
            return res["object"]["sha"]
        return None

    def create_branch(self, repo_full_name, branch_name, sha):
        return self._request("POST", f"/repos/{repo_full_name}/git/refs", {
            "ref": f"refs/heads/{branch_name}",
            "sha": sha
        })

    def create_or_update_file(self, repo_full_name, path, content, message, branch, sha=None):
        data = {
            "message": message,
            "content": base64.b64encode(content.encode("utf-8")).decode("utf-8"),
            "branch": branch
        }
        if sha:
            data["sha"] = sha
        return self._request("PUT", f"/repos/{repo_full_name}/contents/{path}", data)

    def create_pr(self, repo_full_name, title, body, head, base):
        return self._request("POST", f"/repos/{repo_full_name}/pulls", {
            "title": title,
            "body": body,
            "head": head,
            "base": base
        })

def main():
    parser = argparse.ArgumentParser(
        description="Repository Onboarding",
        epilog="Examples:\n"
               "  python onboard_org.py --org Heydo-Tech\n"
               "  python onboard_org.py --owner Heydo-Tech\n"
               "  python onboard_org.py --repo Heydo-Tech/Steady",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--org", help="Target an entire GitHub Organization")
    parser.add_argument("--owner", help="Target a GitHub personal account/user")
    parser.add_argument("--repo", help="Target a specific repository (e.g. owner/repo)")
    parser.add_argument("--dry-run", action="store_true", help="Do not make any changes")
    parser.add_argument("--limit", type=int, help="Maximum number of PRs to create")
    parser.add_argument("--check-drift", action="store_true", help="Only check for drift, do not create PRs unless --fix-drift is set")
    parser.add_argument("--fix-drift", action="store_true", help="Create PRs to fix drifted repositories")
    parser.add_argument("--orchestrator-ref", default=DEFAULT_REF, help="Reference to use for reusable workflow")
    
    args = parser.parse_args()
    
    if not (args.org or args.owner or args.repo):
        parser.error("At least one target (--org, --owner, or --repo) must be specified.")
    
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("Error: GITHUB_TOKEN environment variable is not set.")
        sys.exit(1)
        
    client = GitHubClient(token)
    
    target_repos = {}
    try:
        if args.org:
            print(f"[*] Target: organization {args.org}")
            for r in client.get_repos_list("orgs", args.org):
                target_repos[r["full_name"]] = r
                
        if args.owner:
            print(f"[*] Target: user {args.owner}")
            for r in client.get_repos_list("users", args.owner):
                target_repos[r["full_name"]] = r
                
        if args.repo:
            print(f"[*] Target: repository {args.repo}")
            r = client.get_repo(args.repo)
            if r:
                target_repos[r["full_name"]] = r
            else:
                print(f"Repository {args.repo} not found or is archived.")
                if not target_repos:
                    sys.exit(1)
    except Exception as e:
        print(f"Error fetching repositories: {e}")
        sys.exit(1)
        
    repos = list(target_repos.values())
    if not repos:
        print("No active repositories found to process.")
        sys.exit(1)
        
    print(f"[*] Found {len(repos)} active repositories.")
    
    desired_content = generate_template(args.orchestrator_ref)
    
    stats = {
        "UP_TO_DATE": 0,
        "NEEDS_ONBOARDING": 0,
        "DRIFT": 0,
        "CUSTOMIZED": 0,
        "FAILED": 0,
        "PR_CREATED": 0,
        "SKIPPED_LIMIT": 0,
        "PR_ALREADY_EXISTS": 0
    }
    
    prs_created = 0
    
    for r in repos:
        repo_name = r["full_name"]
        default_branch = r.get("default_branch")
        if not default_branch:
            print(f"[FAILED] {repo_name}: Missing default branch")
            stats["FAILED"] += 1
            continue
        
        try:
            content, sha = client.get_file_content(repo_name, TEMPLATE_PATH)
            
            if content is None:
                state = "NEEDS_ONBOARDING"
            else:
                state = classify_workflow_content(content, args.orchestrator_ref)
                
            stats[state] += 1
            print(f"[{state}] {repo_name}")
            
            if state in {"UP_TO_DATE", "CUSTOMIZED"}:
                continue
                
            if state == "DRIFT" and not args.fix_drift and not args.dry_run:
                continue
                
            if args.check_drift and not args.fix_drift:
                continue
                
            if args.dry_run:
                continue
                
            if args.limit and prs_created >= args.limit:
                stats["SKIPPED_LIMIT"] += 1
                continue
                
            existing_prs = client.get_open_onboarding_prs(repo_name)
            if existing_prs:
                print(f"  -> PR already exists for {repo_name}, skipping.")
                stats["PR_ALREADY_EXISTS"] += 1
                continue
                
            timestamp = int(time.time())
            branch_name = f"setup/code-analysis-{timestamp}"
            
            base_sha = client.get_default_branch_sha(repo_name, default_branch)
            client.create_branch(repo_name, branch_name, base_sha)
            
            client.create_or_update_file(
                repo_name, TEMPLATE_PATH, desired_content,
                "ci: add/update central Code Analysis workflow",
                branch_name, sha
            )
            
            title = "Setup Code Analysis Workflow" if state == "NEEDS_ONBOARDING" else "Update Code Analysis Workflow"
            body = "This PR onboards or updates the repository to the central security and AI code analysis pipeline."
            
            client.create_pr(repo_name, title, body, branch_name, default_branch)
            print("  -> PR created successfully.")
            prs_created += 1
            stats["PR_CREATED"] += 1
            
        except Exception as e:
            print(f"[FAILED] {repo_name}: {e}")
            stats["FAILED"] += 1
            
    print("\n=== Repo Analysis Organization Onboarding ===")
    print(f"Repositories discovered: {len(repos)}\n")
    print(f"UP_TO_DATE:       {stats['UP_TO_DATE']}")
    print(f"NEEDS_ONBOARDING: {stats['NEEDS_ONBOARDING']}")
    print(f"DRIFT:             {stats['DRIFT']}")
    print(f"CUSTOMIZED:        {stats['CUSTOMIZED']}")
    print(f"FAILED:            {stats['FAILED']}\n")
    print(f"PR_ALREADY_EXISTS: {stats['PR_ALREADY_EXISTS']}")
    print(f"PRs created:       {stats['PR_CREATED']}")
    print(f"Skipped by limit:  {stats['SKIPPED_LIMIT']}")

if __name__ == "__main__":
    main()
