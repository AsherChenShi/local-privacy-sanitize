"""Public references and synthetic privileged links for the native smoke tests."""

PUBLIC_URLS = (
    "https://github.com/octocat/Hello-World",
    "https://github.com/octocat/Hello-World/actions/runs/13800138000",
    "https://api.github.com/repos/octocat/Hello-World/actions/runs"
    "?head_sha=0123456789abcdef0123456789abcdef01234567&per_page=3",
    "https://learn.chatgpt.com/docs/hooks#userpromptsubmit",
    "https://code.claude.com/docs/en/hooks",
)
PRIVILEGED_URL_CASES = (
    ("https://api.github.com/repos/octocat/Hello-World?access_token=synthetic-token", "synthetic-token"),
    ("https://code.claude.com/docs/en/hooks?X-Amz-Signature=synthetic-signature", "synthetic-signature"),
    ("https://localhost:8443/private/local-smoke", "localhost:8443/private/local-smoke"),
)
PUBLIC_URL_FIXTURE = "\n".join(PUBLIC_URLS)
