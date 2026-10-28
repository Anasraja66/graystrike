"""
Crawler & Reconnaissance Agent
Discovers permitted surface area:
- Pages, forms, inputs, scripts, cookies, security headers
- Technology fingerprinting (React, Express, Nginx, PHP, etc.)
- Strict scope validation & request budget enforcement
"""
import re
import asyncio
from typing import Dict, Any, List, Set
from urllib.parse import urljoin, urlparse
import httpx
from pydantic import BaseModel, Field


class DiscoveredForm(BaseModel):
    action: str
    method: str = "GET"
    inputs: List[Dict[str, str]] = Field(default_factory=list)


class DiscoveredPage(BaseModel):
    url: str
    status_code: int
    title: str = ""
    content_type: str = ""
    security_headers: Dict[str, str] = Field(default_factory=dict)
    missing_security_headers: List[str] = Field(default_factory=list)
    cookies: List[Dict[str, Any]] = Field(default_factory=list)
    forms: List[DiscoveredForm] = Field(default_factory=list)
    scripts: List[str] = Field(default_factory=list)
    links: List[str] = Field(default_factory=list)


class CrawlResult(BaseModel):
    target_url: str
    total_pages_crawled: int
    pages: List[DiscoveredPage] = Field(default_factory=list)
    technologies: Dict[str, str] = Field(default_factory=dict)
    api_endpoints: List[str] = Field(default_factory=list)


class CrawlerAgent:
    RECOMMENDED_HEADERS = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    TECH_SIGNATURES = {
        "Lovable.dev (AI App)": [re.compile(r"lovable\.app", re.I), re.compile(r"lovable", re.I), re.compile(r"gpt-engineer", re.I)],
        "Bolt.new (AI App)": [re.compile(r"bolt\.new", re.I), re.compile(r"stackblitz", re.I), re.compile(r"webcontainer", re.I)],
        "v0.dev (AI App)": [re.compile(r"v0\.dev", re.I), re.compile(r"v0\.app", re.I)],
        "Supabase (BaaS)": [re.compile(r"supabase\.co", re.I), re.compile(r"supabase", re.I)],
        "Firebase (BaaS)": [re.compile(r"firebaseapp\.com", re.I), re.compile(r"firebase", re.I)],
        "Clerk Auth": [re.compile(r"clerk\.accounts\.dev", re.I), re.compile(r"clerk", re.I)],
        "Stripe Payments": [re.compile(r"js\.stripe\.com", re.I), re.compile(r"stripe", re.I)],
        "Tailwind CSS": [re.compile(r"tailwind", re.I)],
        "Next.js": [re.compile(r"/_next/", re.I), re.compile(r"__NEXT_DATA__", re.I)],
        "React": [re.compile(r"react", re.I), re.compile(r"_next", re.I)],
        "Vue.js": [re.compile(r"vue", re.I), re.compile(r"nuxt", re.I)],
        "Django": [re.compile(r"csrftoken", re.I), re.compile(r"django", re.I)],
        "Laravel": [re.compile(r"laravel_session", re.I), re.compile(r"XSRF-TOKEN", re.I)],
        "Express/Node.js": [re.compile(r"express", re.I), re.compile(r"connect\.sid", re.I)],
        "Spring Boot": [re.compile(r"whitelabel error page", re.I), re.compile(r"jsessionid", re.I)],
        "FastAPI": [re.compile(r"fastapi", re.I), re.compile(r"/openapi\.json", re.I)],
        "GraphQL": [re.compile(r"/graphql", re.I), re.compile(r"apollo", re.I)],
        "WordPress": [re.compile(r"wp-content", re.I), re.compile(r"wp-includes", re.I)],
        "Bootstrap": [re.compile(r"bootstrap", re.I)],
        "jQuery": [re.compile(r"jquery", re.I)],
        "Nginx": [re.compile(r"nginx", re.I)],
        "Apache": [re.compile(r"apache", re.I)],
        "Cloudflare": [re.compile(r"cloudflare", re.I)],
    }

    def __init__(self, max_pages: int = 25, max_depth: int = 3, timeout_seconds: float = 10.0):
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout_seconds = timeout_seconds

    async def crawl(self, base_url: str, scope_enforcer=None) -> CrawlResult:
        """
        Crawl the target URL within scope, extracting metadata without state modification.
        """
        visited: Set[str] = set()
        queue: List[tuple[str, int]] = [(base_url, 0)]
        pages: List[DiscoveredPage] = []
        discovered_tech: Dict[str, str] = {}
        api_endpoints: Set[str] = set()

        base_domain = urlparse(base_url).hostname

        headers = {
            "User-Agent": "APTAgents-SecurityScanner/1.0 (+https://apt-agents.internal)",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"
        }

        async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True, headers=headers) as client:
            while queue and len(visited) < self.max_pages:
                current_url, depth = queue.pop(0)

                # Clean / Canonicalize URL
                parsed = urlparse(current_url)
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.query:
                    clean_url += f"?{parsed.query}"

                if clean_url in visited:
                    continue

                # Scope enforcement check
                if scope_enforcer:
                    is_valid, reason = scope_enforcer.validate_url(clean_url)
                    if not is_valid:
                        continue

                visited.add(clean_url)

                try:
                    resp = await client.get(clean_url)
                    content_type = resp.headers.get("content-type", "")

                    # Extract security headers
                    sec_headers = {}
                    missing_sec_headers = []
                    for h in self.RECOMMENDED_HEADERS:
                        val = resp.headers.get(h)
                        if val:
                            sec_headers[h] = val
                        else:
                            missing_sec_headers.append(h)

                    # Extract cookies
                    cookies_meta = []
                    for cookie in resp.cookies.jar:
                        cookies_meta.append({
                            "name": cookie.name,
                            "secure": cookie.secure,
                            "httponly": bool(cookie.has_nonstandard_attr("HttpOnly")),
                            "samesite": getattr(cookie, "samesite", None)
                        })

                    # Extract title, forms, scripts, links
                    html = resp.text if "text/html" in content_type else ""
                    title = ""
                    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        title = title_match.group(1).strip()

                    # Extract forms (non-destructive inspection only)
                    forms: List[DiscoveredForm] = []
                    form_matches = re.finditer(r"<form([^>]*)>(.*?)</form>", html, re.IGNORECASE | re.DOTALL)
                    for fm in form_matches:
                        attrs = fm.group(1)
                        body = fm.group(2)

                        action_m = re.search(r'action=[\'"]([^\'"]*)[\'"]', attrs, re.I)
                        method_m = re.search(r'method=[\'"]([^\'"]*)[\'"]', attrs, re.I)

                        action = action_m.group(1) if action_m else clean_url
                        form_action = urljoin(clean_url, action)
                        method = (method_m.group(1) if method_m else "GET").upper()

                        inputs = []
                        input_matches = re.finditer(r"<input([^>]*)>", body, re.IGNORECASE)
                        for im in input_matches:
                            input_attrs = im.group(1)
                            name_m = re.search(r'name=[\'"]([^\'"]*)[\'"]', input_attrs, re.I)
                            type_m = re.search(r'type=[\'"]([^\'"]*)[\'"]', input_attrs, re.I)
                            if name_m:
                                inputs.append({
                                    "name": name_m.group(1),
                                    "type": type_m.group(1) if type_m else "text"
                                })

                        forms.append(DiscoveredForm(action=form_action, method=method, inputs=inputs))

                    # Detect technology signatures
                    server_header = resp.headers.get("server", "")
                    x_powered = resp.headers.get("x-powered-by", "")
                    for tech, patterns in self.TECH_SIGNATURES.items():
                        for pattern in patterns:
                            if pattern.search(html) or pattern.search(server_header) or pattern.search(x_powered):
                                discovered_tech[tech] = "High"

                    # Extract same-origin links
                    page_links = []
                    link_matches = re.finditer(r'href=[\'"]([^\'"]+)[\'"]', html, re.IGNORECASE)
                    for lm in link_matches:
                        href = lm.group(1).strip()
                        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                            continue
                        absolute_link = urljoin(clean_url, href)
                        link_host = urlparse(absolute_link).hostname

                        if link_host == base_domain:
                            page_links.append(absolute_link)
                            if depth < self.max_depth and absolute_link not in visited:
                                queue.append((absolute_link, depth + 1))

                        # API paths detection
                        if "/api/" in absolute_link or absolute_link.endswith((".json", "/v1", "/v2")):
                            api_endpoints.add(absolute_link)

                    pages.append(DiscoveredPage(
                        url=clean_url,
                        status_code=resp.status_code,
                        title=title,
                        content_type=content_type,
                        security_headers=sec_headers,
                        missing_security_headers=missing_sec_headers,
                        cookies=cookies_meta,
                        forms=forms,
                        links=page_links[:30]
                    ))

                except Exception as crawl_err:
                    pages.append(DiscoveredPage(
                        url=clean_url,
                        status_code=0,
                        title=f"Failed to crawl: {str(crawl_err)}"
                    ))

        return CrawlResult(
            target_url=base_url,
            total_pages_crawled=len(pages),
            pages=pages,
            technologies=discovered_tech,
            api_endpoints=list(api_endpoints)
        )
