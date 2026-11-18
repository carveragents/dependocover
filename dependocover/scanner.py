"""Static, evidence-oriented discovery for Python repositories.

Repository code is never imported or executed. Findings are leads for review,
not proof that a service is required at runtime.
"""
from __future__ import annotations

import ast
import json
import ipaddress
from datetime import datetime, timezone
import os
import re
import sys
import subprocess
import tempfile
import urllib.parse
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

IGNORES = {".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__", "site-packages", "node_modules", "dist", "build", ".mypy_cache", ".pytest_cache", ".tox"}
MAX_FILE_SIZE = 2_000_000
MAX_MANIFEST_SIZE = 50_000_000
DEFAULT_MAX_REPOSITORY_SIZE = 500_000_000
IMPORT_MAP = {"PIL": "Pillow", "cv2": "opencv-python", "yaml": "PyYAML", "sklearn": "scikit-learn", "bs4": "beautifulsoup4", "Crypto": "pycryptodome", "dotenv": "python-dotenv"}
JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
JAVA_EXTENSIONS = {".java"}
C_EXTENSIONS = {".c", ".h"}
CPP_EXTENSIONS = {".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".ipp", ".tpp"}
CSHARP_EXTENSIONS = {".cs"}
CODE_EXTENSIONS = JS_EXTENSIONS | JAVA_EXTENSIONS | C_EXTENSIONS | CPP_EXTENSIONS | CSHARP_EXTENSIONS
NODE_BUILTINS = {"assert", "buffer", "child_process", "crypto", "events", "fs", "http", "https", "module", "os", "path", "process", "stream", "timers", "url", "util", "zlib"}
JS_IMPORT_PATTERN = re.compile(r"(?:\b(?:import|export)\s+(?:[^;]*?\s+from\s+)?|\brequire\s*\(\s*|\bimport\s*\(\s*)['\"]([^'\"]+)['\"]")
SERVICE_PATTERNS = [
    ("AWS", r"\bboto3\b|\baioboto3\b|\bbotocore\b|\bAWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|REGION|DEFAULT_REGION|S3_BUCKET)\b|\bs3://", "AWS SDK/configuration"),
    ("AWS resource", r"\b(?:SQS|SNS|DYNAMODB|LAMBDA|ECS|EKS|RDS|CLOUDFORMATION|SAM)_", "AWS service configuration"),
    ("Google Cloud", r"\b(?:from|import)\s+google\.cloud\b", "Google Cloud SDK"),
    ("Microsoft Azure", r"\b(?:from|import)\s+azure\.", "Azure SDK"),
    ("Stripe", r"\bstripe\b", "Stripe library/configuration"),
    ("Twilio", r"\btwilio\b", "Twilio library/configuration"),
    ("SendGrid", r"\bsendgrid\b", "SendGrid library/configuration"),
    ("Postmark", r"\bpostmark\b", "Postmark library/configuration"),
    ("Mailgun", r"\bmailgun\b", "Mailgun library/configuration"),
    ("SMTP email", r"\bsmtplib\b|\bSMTP(?:_HOST|_PORT|_USER|_PASSWORD)?\b", "SMTP client/configuration"),
    ("Redis", r"\bredis(?:\.Redis|\.from_url)?\b|\bREDIS_URL\b", "Redis client/configuration"),
    ("PostgreSQL", r"\bpsycopg(?:2)?\b|\bDATABASE_URL\b|\bpostgres(?:ql)?://", "PostgreSQL client/configuration"),
    ("MySQL", r"\bpymysql\b|\bmysql(?:\+\w+)?://", "MySQL client/configuration"),
    ("MongoDB", r"\bpymongo\b|\bmongodb(?:\+srv)?://", "MongoDB client/configuration"),
    ("Celery broker", r"\bcelery\b|\bBROKER_URL\b", "Task queue client/configuration"),
    ("HTTP API", r"\brequests\.(?:get|post|put|patch|delete|request)\s*\(|\bhttpx\.(?:get|post|put|patch|delete|request|Client|AsyncClient)\s*\(|\baiohttp\.ClientSession\b", "Outbound HTTP client"),
]
URL_PATTERN = re.compile(r"(?:https?|redis|rediss|postgres(?:ql)?(?:\+\w+)?|mysql(?:\+\w+)?|mongodb(?:\+srv)?|amqps?|smtps?|s3a?|gs)://[^\s\"'<>`\\]+", re.I)


def _safe_port(parsed: urllib.parse.SplitResult) -> int | None:
    try:
        return parsed.port
    except ValueError:
        return None


def _safe_netloc(parsed: urllib.parse.SplitResult) -> str:
    host = parsed.hostname or ""
    port = _safe_port(parsed)
    if port:
        return f"{host}:{port}"
    raw_netloc = parsed.netloc.rsplit("@", 1)[-1]
    if raw_netloc.count(":") == 1:
        raw_port = raw_netloc.rsplit(":", 1)[-1]
        if raw_port and not raw_port.isdigit():
            return f"{host}:{raw_port}"
    return host


def _normalize_url(raw_url: str) -> tuple[str | None, str | None, list[str]]:
    raw_url = raw_url.rstrip(".,;:)]}")
    try:
        parsed = urllib.parse.urlsplit(raw_url)
        if not parsed.hostname:
            return None, None, []
        safe_url = urllib.parse.urlunsplit((parsed.scheme, _safe_netloc(parsed), parsed.path, "", ""))
        params = sorted({key for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)})
        return safe_url, parsed.hostname.lower(), params
    except ValueError:
        return None, None, []


def _known_provider(host: str) -> str | None:
    provider_domains = {
        "OpenAI": ("api.openai.com",), "Anthropic": ("api.anthropic.com", "anthropic.com"),
        "Stripe": ("api.stripe.com", "stripe.com"), "Twilio": ("api.twilio.com", "twilio.com"),
        "SendGrid": ("api.sendgrid.com", "sendgrid.com"), "Mailgun": ("api.mailgun.net", "mailgun.com"),
        "Postmark": ("api.postmarkapp.com", "postmarkapp.com"), "Voyage AI": ("api.voyageai.com", "voyageai.com"),
        "Z.ai": ("api.z.ai", "open.bigmodel.cn"), "Langfuse": ("cloud.langfuse.com", "langfuse.com"),
    }
    return next((name for name, domains in provider_domains.items()
                 if any(host == domain or host.endswith("." + domain) for domain in domains)), None)


def _url_subcategory(host: str) -> str:
    provider = _known_provider(host)
    subcategories = {
        "OpenAI": "llm_api", "Anthropic": "llm_api", "Voyage AI": "embedding_api",
        "Z.ai": "llm_api", "Stripe": "payments", "Twilio": "communications",
        "SendGrid": "email_delivery", "Mailgun": "email_delivery", "Postmark": "email_delivery",
        "Langfuse": "llm_observability",
    }
    if provider:
        return subcategories.get(provider, "third_party_api")
    if host.endswith((".amazonaws.com", ".amazonaws.com.cn", ".googleapis.com", ".azure.com", ".windows.net")):
        return "cloud_api"
    if host in {"arxiv.org", "openaccess.thecvf.com", "doi.org", "paperswithcode.com"}:
        return "research_or_document_reference"
    return "http_endpoint"


def _scheme_service(scheme: str) -> tuple[str, str, str] | None:
    if scheme in {"s3", "s3a"}:
        return "AWS S3", "standard_cloud", "cloud_storage"
    if scheme == "gs":
        return "Google Cloud Storage", "standard_cloud", "cloud_storage"
    if scheme.startswith("postgres"):
        return "PostgreSQL", "internal_or_managed_unknown", "relational_database"
    if scheme.startswith("mysql"):
        return "MySQL", "internal_or_managed_unknown", "relational_database"
    return {"redis": ("Redis", "internal_or_managed_unknown", "cache_or_key_value_store"),
            "rediss": ("Redis", "internal_or_managed_unknown", "cache_or_key_value_store"),
            "postgres": ("PostgreSQL", "internal_or_managed_unknown", "relational_database"),
            "postgresql": ("PostgreSQL", "internal_or_managed_unknown", "relational_database"),
            "mysql": ("MySQL", "internal_or_managed_unknown", "relational_database"),
            "mongodb": ("MongoDB", "internal_or_managed_unknown", "document_database"),
            "mongodb+srv": ("MongoDB", "internal_or_managed_unknown", "document_database"),
            "amqp": ("Message broker", "internal_or_managed_unknown", "task_queue"),
            "amqps": ("Message broker", "internal_or_managed_unknown", "task_queue"),
            "smtp": ("SMTP email provider", "third_party", "email_delivery"),
            "smtps": ("SMTP email provider", "third_party", "email_delivery")}.get(scheme.lower())


def _service_subcategory(name: str) -> str:
    n = name.lower()
    rules = (("aws", "cloud_infrastructure"), ("google cloud", "cloud_platform"),
             ("azure", "cloud_platform"), ("openai", "llm_api"), ("anthropic", "llm_api"),
             ("genai", "llm_api"),
             ("voyage", "embedding_api"), ("z.ai", "llm_api"), ("ollama", "model_runtime"),
             ("redis", "cache_or_key_value_store"), ("postgres", "relational_database"),
             ("mysql", "relational_database"), ("mongo", "document_database"),
             ("qdrant", "vector_database"), ("milvus", "vector_database"), ("pinecone", "vector_database"),
             ("neo4j", "graph_database"), ("opensearch", "search_database"),
             ("celery", "task_queue"), ("bullmq", "task_queue"), ("sendgrid", "email_delivery"),
             ("mailgun", "email_delivery"), ("postmark", "email_delivery"),
             ("resend", "email_delivery"), ("smtp", "email_delivery"), ("stripe", "payments"),
             ("twilio", "communications"), ("langfuse", "llm_observability"),
             ("http api", "http_api"))
    return next((category for fragment, category in rules if fragment in n), "external_service")


@dataclass
class Finding:
    category: str
    name: str
    evidence: str
    file: str
    line: int | None = None
    confidence: str = "medium"
    details: dict = field(default_factory=dict)


@dataclass
class ScanReport:
    repository: str
    languages: list[str]
    files_scanned: int
    findings: list[Finding]
    warnings: list[str]
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        deduplicated_findings: dict[tuple, dict] = {}
        for finding in self.findings:
            item = asdict(finding)
            item.pop("file", None)
            item.pop("line", None)
            key = (finding.category, finding.name,
                   json.dumps(finding.details, sort_keys=True, ensure_ascii=False))
            grouped = deduplicated_findings.setdefault(key, {
                "category": finding.category, "name": finding.name,
                "evidence": [], "locations": [], "confidence": finding.confidence,
                "details": finding.details,
            })
            if finding.evidence not in grouped["evidence"]:
                grouped["evidence"].append(finding.evidence)
            location = f"{finding.file}:{finding.line}" if finding.line else finding.file
            if location not in grouped["locations"]:
                grouped["locations"].append(location)
            if finding.confidence == "high":
                grouped["confidence"] = "high"
        compact_findings = sorted(deduplicated_findings.values(),
                                  key=lambda item: (item["category"], item["name"].lower(), item["locations"]))
        return {"repository": self.repository, "languages": self.languages,
                "files_scanned": self.files_scanned,
                "metadata": self.metadata,
                "inventory": _build_inventory(self.findings),
                "findings": compact_findings, "warnings": self.warnings}


def _build_inventory(findings: list[Finding]) -> dict:
    """Aggregate raw clues into deduplicated, environment-oriented inventory."""
    def loc(f: Finding) -> str:
        return f"{f.file}:{f.line}" if f.line else f.file

    def keyname(value: str) -> str:
        return re.sub(r"[\s\-_.]+", "-", value.split("[", 1)[0]).strip("-").lower()

    local_roots = {f.file.split("/", 1)[0] for f in findings if "/" in f.file and not f.file.startswith(".")}
    libraries: dict[str, dict] = {}
    for f in findings:
        if f.category not in {"package", "python_import", "javascript_import", "source_import"}:
            continue
        module = f.details.get("imported_module") if f.category in {"python_import", "javascript_import"} else None
        if f.category == "python_import" and f.details.get("local_import"):
            continue
        if f.category == "python_import" and (module in sys.stdlib_module_names or module in local_roots or (module or "").startswith("_")):
            continue
        if f.category == "javascript_import" and (module in NODE_BUILTINS or module in local_roots):
            continue
        if f.category == "source_import" and (module or "").startswith((".", "/", "<", '"')):
            continue
        key = keyname(f.name)
        item = libraries.setdefault(key, {"name": f.name, "versions": set(), "imported_as": set(), "declared_in": set(), "locations": set(), "evidence": set(), "ecosystems": set()})
        item["ecosystems"].add(f.details.get("ecosystem", "npm" if f.category == "javascript_import" else "python"))
        if f.category == "package":
            # Preserve specifiers/URLs from manifests as version/source declarations.
            item["declared_in"].add(f.file)
            spec = f.evidence.strip()
            item["versions"].add(spec)
        if module:
            item["imported_as"].add(module)
        item["locations"].add(loc(f))
        item["evidence"].add(f.evidence)
    library_out = []
    for item in sorted(libraries.values(), key=lambda x: x["name"].lower()):
        library_out.append({"name": item["name"], "version_or_specifier": sorted(item["versions"]),
                            "ecosystem": sorted(item["ecosystems"]),
                            "imported_as": sorted(item["imported_as"]), "declared_in": sorted(item["declared_in"]),
                            "locations": sorted(item["locations"]), "evidence": sorted(item["evidence"])[:10]})

    service_class = {
        "AWS": ("standard_cloud", "AWS"), "AWS resource": ("standard_cloud", "AWS"),
        "Google Cloud": ("standard_cloud", "Google Cloud"), "Microsoft Azure": ("standard_cloud", "Microsoft Azure"),
        "Redis": ("internal_or_managed_service", "Redis"), "PostgreSQL": ("internal_or_managed_service", "PostgreSQL"),
        "MySQL": ("internal_or_managed_service", "MySQL"), "MongoDB": ("internal_or_managed_service", "MongoDB"),
        "Celery broker": ("internal_or_managed_service", "Celery/message broker"),
        "SMTP email": ("third_party_service", "SMTP email provider"), "Stripe": ("third_party_service", "Stripe"),
        "Twilio": ("third_party_service", "Twilio"), "SendGrid": ("third_party_service", "SendGrid"),
        "Postmark": ("third_party_service", "Postmark"), "Mailgun": ("third_party_service", "Mailgun"),
        "HTTP API": ("unclassified_api", "HTTP API (provider unresolved)"),
    }
    service_findings: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        if f.category == "external_service" and f.name not in {"External URL", "HTTP API"}:
            classification, canonical = service_class.get(f.name, ("unclassified_api", f.name))
            service_findings.setdefault((classification, canonical), []).append(f)
    # URL literals are API endpoint candidates, not automatically classified as a service.
    urls: dict[str, dict] = {}
    url_pattern = URL_PATTERN
    for f in findings:
        if f.category != "external_service" or f.name != "External URL":
            continue
        match = url_pattern.search(f.evidence)
        raw_url = f.details.get("url") or (match.group(0) if match else None)
        if not raw_url:
            continue
        safe_url, host, param_names = _normalize_url(raw_url)
        if not safe_url or not host:
            continue
        canonical_url = safe_url
        item = urls.setdefault(canonical_url, {"url": canonical_url, "host": host, "parameter_names": set(), "locations": set(), "evidence": set(), "methods": set(), "reference_context": set()})
        item["parameter_names"].update(param_names)
        item["parameter_names"].update(f.details.get("parameter_names", []))
        item["locations"].add(loc(f))
        item["evidence"].add(f.evidence)
        if f.details.get("reference_context"):
            item["reference_context"].add(f.details["reference_context"])
    dynamic_api_calls = []
    for f in findings:
        if f.category != "api_call":
            continue
        url = f.details.get("url")
        if not url:
            dynamic_api_calls.append({"method": f.details.get("method"), "url": None,
                                      "parameter_names": f.details.get("parameter_names", []), "locations": [loc(f)]})
            continue
        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError:
            continue
        host = (parsed.hostname or "").lower()
        item = urls.setdefault(url, {"url": url, "host": host, "parameter_names": set(), "locations": set(), "evidence": set(), "methods": set(), "reference_context": set()})
        item["parameter_names"].update(f.details.get("parameter_names", []))
        item["methods"].add(f.details.get("method"))
        item["locations"].add(loc(f))
        item["evidence"].add(f.evidence)
    service_out = []
    for (classification, name), group in sorted(service_findings.items()):
        service_out.append({"name": name, "classification": classification,
                            "evidence_count": len(group), "locations": sorted({loc(f) for f in group}),
                            "parameters": sorted({k for f in group for k in re.findall(r"\b(?:AWS_[A-Z0-9_]+|REDIS_URL|DATABASE_URL|BROKER_URL|SMTP_[A-Z0-9_]+)\b", f.evidence)}),
                            "evidence_samples": sorted({f.evidence for f in group})[:12]})
    sdk_services = {
        "aioboto3": ("AWS SDK integration (specific AWS services unresolved)", "standard_cloud"),
        "boto3": ("AWS SDK integration (specific AWS services unresolved)", "standard_cloud"),
        "openai": ("OpenAI API", "third_party_service"),
        "anthropic": ("Anthropic API", "third_party_service"),
        "voyageai": ("Voyage AI API", "third_party_service"),
        "zai-sdk": ("Z.ai API", "third_party_service"),
        "google-genai": ("Google GenAI API", "standard_cloud"),
        "ollama": ("Ollama model service", "internal_or_managed_service"),
        "qdrant-client": ("Qdrant vector database", "internal_or_managed_service"),
        "pymilvus": ("Milvus vector database", "internal_or_managed_service"),
        "neo4j": ("Neo4j graph database", "internal_or_managed_service"),
        "opensearch-py": ("OpenSearch", "internal_or_managed_service"),
        "langfuse": ("Langfuse observability", "third_party_service"),
        "@anthropic-ai/sdk": ("Anthropic API", "third_party_service"),
        "@google/generative-ai": ("Google GenAI API", "standard_cloud"),
        "@google-cloud": ("Google Cloud", "standard_cloud"),
        "@aws-sdk": ("AWS SDK integration (specific AWS services unresolved)", "standard_cloud"),
        "aws-sdk": ("AWS SDK integration (specific AWS services unresolved)", "standard_cloud"),
        "@azure": ("Microsoft Azure", "standard_cloud"),
        "ioredis": ("Redis", "internal_or_managed_service"),
        "pg": ("PostgreSQL", "internal_or_managed_service"),
        "mysql2": ("MySQL", "internal_or_managed_service"),
        "mongoose": ("MongoDB", "internal_or_managed_service"),
        "mongodb": ("MongoDB", "internal_or_managed_service"),
        "@qdrant/js-client-rest": ("Qdrant vector database", "internal_or_managed_service"),
        "@pinecone-database/pinecone": ("Pinecone vector database", "internal_or_managed_service"),
        "@sendgrid/mail": ("SendGrid", "third_party_service"),
        "nodemailer": ("SMTP email provider", "third_party_service"),
        "resend": ("Resend email API", "third_party_service"),
        "bullmq": ("Redis-backed task queue", "internal_or_managed_service"),
    }
    known_names = {s["name"] for s in service_out}
    for lib in library_out:
        lib_key = keyname(lib["name"])
        mapping = sdk_services.get(lib_key) or next((value for sdk, value in sdk_services.items()
                                                      if sdk.startswith("@") and lib_key.startswith(sdk + "/")), None)
        if not mapping or mapping[0] in known_names:
            continue
        matches = [f for f in findings if f.category in {"package", "python_import", "javascript_import"}
                   and (keyname(f.name) == keyname(lib["name"]) or f.details.get("imported_module") in lib["imported_as"])]
        service_out.append({"name": mapping[0], "classification": mapping[1],
                            "evidence_count": len(matches), "locations": sorted({loc(f) for f in matches}),
                            "parameters": [], "evidence_samples": sorted({f.evidence for f in matches})[:8],
                            "inferred_from_library": lib["name"]})
    url_references = []
    api_endpoint_candidates = []
    for _, v in sorted(urls.items()):
        host = v["host"]
        parsed_url = urllib.parse.urlsplit(v["url"])
        path = parsed_url.path.lower()
        protocol = parsed_url.scheme.lower()
        protocol_info = _scheme_service(protocol)
        source_files = {p.split(":", 1)[0] for p in v["locations"]}
        docs_host = host in {"arxiv.org", "openaccess.thecvf.com", "doi.org", "paperswithcode.com"}
        docs_path = path.endswith((".pdf", ".doc", ".docx", ".ppt", ".pptx")) or "/abs/" in path
        docs_source = any(p.lower().startswith(("docs/", "doc/", "examples/", "example/")) for p in source_files)
        ref_context = bool(v["reference_context"])
        info_reference = docs_host or docs_path or docs_source or ref_context
        try:
            private_ip = ipaddress.ip_address(host).is_private
        except ValueError:
            private_ip = False
        if protocol_info and protocol_info[1] == "standard_cloud":
            classification, basis = "standard_cloud_candidate", f"resource URI scheme indicates {protocol_info[0]}"
        elif private_ip or host in {"localhost", "host.docker.internal"} or ".internal" in host or host.endswith(".svc") or "." not in host:
            classification, basis = "internal_candidate", "local or private-service hostname pattern"
        elif host.endswith((".amazonaws.com", ".amazonaws.com.cn", ".googleapis.com", ".azure.com", ".windows.net")):
            classification, basis = "standard_cloud_candidate", "recognized cloud endpoint domain"
        elif protocol_info and protocol_info[1] == "internal_or_managed_unknown":
            classification, basis = "internal_or_managed_candidate", f"connection-string protocol indicates {protocol_info[0]}"
        elif protocol_info:
            classification, basis = "known_third_party_candidate", f"connection-string protocol indicates {protocol_info[0]}"
        else:
            provider = _known_provider(host)
            if provider:
                classification, basis = "known_third_party_candidate", f"known provider domain: {provider}"
            elif info_reference:
                classification, basis = "informational_reference", "document/reference domain, file type, or repository context"
            else:
                classification, basis = "unclassified_reference", "URL found without evidence of an operational request"
        entry = {"url": v["url"], "host": host, "protocol": protocol, "classification": classification,
                 "classification_basis": basis, "subcategory": protocol_info[2] if protocol_info else _url_subcategory(host),
                 "parameter_names": sorted(v["parameter_names"]), "methods": sorted(m for m in v["methods"] if m),
                 "locations": sorted(v["locations"])}
        url_references.append(entry)
        if v["methods"]:
            api_endpoint_candidates.append(entry)

    containers: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        if f.category in {"container", "container_service", "cloud_infrastructure", "runtime_requirement"}:
            category = ("container_image_or_directive" if f.category.startswith("container") else
                        "runtime_requirement" if f.category == "runtime_requirement" else "cloud_infrastructure_declaration")
            containers.setdefault((category, f.name), []).append(f)
    environment = []
    for (category, name), group in sorted(containers.items()):
        versions = sorted({value for f in group for value in ([f.details["version"]] if f.details.get("version") else [])} |
                          {tag for f in group for tag in re.findall(r"\b(?:python|node|bun|postgres|pgvector|redis)[/:@-]?[A-Za-z0-9._-]*", f.name, re.I)})
        ports = sorted({int(p) for f in group for p in re.findall(r"\bEXPOSE\s+(\d+)", f.evidence, re.I)})
        environment.append({"name": name, "type": category, "versions_or_tags": versions,
                            "ports": ports, "locations": sorted({loc(f) for f in group})})
    compose_service_map: dict[str, dict] = {}
    for f in findings:
        if f.category == "container_service":
            name = f.details.get("service") or f.name
            item = compose_service_map.setdefault(name, {"name": name, "image_or_build": set(), "parameters": {}, "classification": "internal", "locations": set()})
            item["image_or_build"].add(f.name)
            item["locations"].add(loc(f))
    for f in findings:
        if f.category == "container_parameter":
            service = f.details.get("service") or "unknown"
            item = compose_service_map.setdefault(service, {"name": service, "image_or_build": set(), "parameters": {}, "classification": "internal", "locations": set()})
            item["parameters"].setdefault(f.details.get("parameter", f.name), set()).add(f.details.get("value", "detected"))
            item["locations"].add(loc(f))
    compose_services = [{"name": v["name"], "subcategory": _service_subcategory(v["name"]),
                         "image_or_build": sorted(v["image_or_build"]),
                         "parameters": {k: sorted(values) for k, values in sorted(v["parameters"].items())},
                         "classification": v["classification"], "locations": sorted(v["locations"])}
                        for _, v in sorted(compose_service_map.items())]
    # Consolidate service detections, endpoint calls, and config keys into one
    # service record per normalized service identity.
    def service_key(name: str) -> str:
        n = keyname(name)
        for suffix in ("-api", "-sdk-integration-specific-aws-services-unresolved", "-provider"):
            n = n.removesuffix(suffix)
        if "aws-sdk-integration" in n:
            return "aws"
        return n

    def normalized_category(classification: str) -> str:
        return {"internal_or_managed_service": "internal_or_managed_unknown",
                "third_party_service": "third_party", "unclassified_api": "unclassified"}.get(classification, classification)

    unified: dict[str, dict] = {}

    def add_service(name: str, category: str, source: dict | None = None) -> dict:
        k = service_key(name)
        if k not in unified:
            unified[k] = {"name": name, "category": category, "subcategory": _service_subcategory(name),
                          "endpoints": [], "request_parameter_names": set(), "configuration_parameters": [],
                          "locations": set(), "evidence_samples": set(), "image_or_build": set(), "deployment_parameters": {}}
        item = unified[k]
        # An explicit Compose declaration is stronger hosting evidence than a client import.
        if category == "internal" or item["category"] == "unclassified":
            item["category"] = category
        if source:
            item["locations"].update(source.get("locations", []))
            item["evidence_samples"].update(source.get("evidence_samples", []))
            item["image_or_build"].update(source.get("image_or_build", []))
            if not isinstance(source.get("parameters"), dict):
                for param in source.get("parameters", []):
                    if isinstance(param, str):
                        item["configuration_parameters"].append({"name": param, "locations": source.get("locations", [])})
            item["deployment_parameters"].update(source.get("parameters", {}) if isinstance(source.get("parameters"), dict) else {})
        return item

    for svc in service_out:
        category = normalized_category(svc["classification"])
        target = add_service(svc["name"], category, svc)
        target["evidence_count"] = target.get("evidence_count", 0) + svc.get("evidence_count", 0)
    for svc in compose_services:
        target = add_service(svc["name"], "internal", svc)
        target["image_or_build"].update(svc["image_or_build"])
        target["deployment_parameters"].update(svc["parameters"])
    provider_service_names = {"OpenAI": "OpenAI API", "Anthropic": "Anthropic API", "Voyage AI": "Voyage AI API",
                             "Z.ai": "Z.ai API", "Stripe": "Stripe", "Twilio": "Twilio",
                             "SendGrid": "SendGrid", "Mailgun": "Mailgun", "Postmark": "Postmark", "Langfuse": "Langfuse"}
    for endpoint in url_references:
        if endpoint["classification"] == "informational_reference":
            continue
        if not endpoint["methods"] and endpoint["classification"] in {"unclassified_reference"}:
            continue
        provider = _known_provider(endpoint["host"])
        protocol_info = _scheme_service(endpoint["protocol"])
        if protocol_info:
            name, category, _ = protocol_info
            if endpoint["classification"] == "internal_candidate":
                category = "internal"
        elif provider:
            name = provider_service_names.get(provider, provider)
            category = "third_party"
        elif endpoint["classification"] == "standard_cloud_candidate":
            if ".amazonaws." in endpoint["host"]:
                name, category = "AWS", "standard_cloud"
            elif ".googleapis.com" in endpoint["host"]:
                name, category = "Google Cloud", "standard_cloud"
            else:
                name, category = "Microsoft Azure", "standard_cloud"
        elif endpoint["classification"] == "internal_candidate":
            name, category = endpoint["host"].split(".")[0], "internal"
        else:
            name, category = endpoint["host"], "unclassified"
        target = add_service(name, category)
        endpoint_record = {"url": endpoint["url"], "methods": endpoint["methods"],
                           "parameter_names": endpoint["parameter_names"], "locations": endpoint["locations"]}
        if endpoint_record not in target["endpoints"]:
            target["endpoints"].append(endpoint_record)
        target["request_parameter_names"].update(endpoint["parameter_names"])
        target["locations"].update(endpoint["locations"])
    config_prefixes = {
        "AWS_": "aws", "OPENAI_": "openai", "ANTHROPIC_": "anthropic", "VOYAGE_": "voyage-ai",
        "ZAI_": "z-ai", "STRIPE_": "stripe", "TWILIO_": "twilio", "SENDGRID_": "sendgrid",
        "MAILGUN_": "mailgun", "POSTMARK_": "postmark", "SMTP_": "smtp-email-provider",
        "REDIS_": "redis", "MONGO": "mongodb", "POSTGRES": "postgresql", "MYSQL": "mysql",
    }
    config_groups = _group_findings(findings, "configuration_parameter")
    for parameter, group in config_groups.items():
        upper = parameter.upper()
        target_key = next((value for prefix, value in config_prefixes.items() if upper.startswith(prefix)), None)
        if not target_key:
            token_map = {"OPENAI": "openai", "ANTHROPIC": "anthropic", "VOYAGE": "voyage-ai", "GOOGLE": "google-cloud",
                         "AZURE": "microsoft-azure", "STRIPE": "stripe",
                         "TWILIO": "twilio", "SENDGRID": "sendgrid", "MAILGUN": "mailgun", "POSTMARK": "postmark",
                         "REDIS": "redis", "MONGO": "mongodb", "POSTGRES": "postgresql", "MYSQL": "mysql", "AWS": "aws"}
            target_key = next((value for token, value in token_map.items() if token in upper), None)
        candidates = [value for key, value in unified.items()
                      if target_key and (key == target_key or (target_key == "celery" and "celery" in key))]
        if upper.startswith("DATABASE_"):
            db_candidates = [value for value in unified.values()
                             if value["subcategory"] in {"relational_database", "document_database", "graph_database", "vector_database", "search_database"}]
            if len(db_candidates) == 1:
                candidates = db_candidates
        if not candidates:
            continue
        candidates[0]["configuration_parameters"].append({"name": parameter, "locations": sorted({loc(f) for f in group})})
        candidates[0]["locations"].update(loc(f) for f in group)
    all_services = []
    for item in unified.values():
        item["endpoints"].sort(key=lambda e: (e["url"], e["methods"]))
        params = {(p["name"], tuple(p.get("locations", []))): p for p in item["configuration_parameters"]}
        item["configuration_parameters"] = sorted(params.values(), key=lambda p: p["name"])
        item["request_parameter_names"] = sorted(item["request_parameter_names"])
        item["locations"] = sorted(item["locations"])
        item["evidence_samples"] = sorted(item["evidence_samples"])
        item["image_or_build"] = sorted(item["image_or_build"])
        item["subcategory"] = _service_subcategory(item["name"])
        all_services.append(item)
    return {"taxonomy_version": "1.0",
            "taxonomy": {"categories": ["internal", "internal_or_managed_unknown", "standard_cloud", "third_party", "unclassified"],
                         "subcategories": ["cloud_infrastructure", "cloud_platform", "cloud_api", "cloud_storage", "llm_api", "embedding_api", "model_runtime",
                                           "vector_database", "relational_database", "document_database", "graph_database", "search_database",
                                           "cache_or_key_value_store", "task_queue", "email_delivery", "payments", "communications",
                                           "llm_observability", "http_api", "third_party_api", "research_or_document_reference", "http_endpoint", "external_service"]},
            "libraries": library_out,
            "services": {"internal": [s for s in all_services if s["category"] == "internal"],
                         "internal_or_managed_unknown": [s for s in all_services if s["category"] == "internal_or_managed_unknown"],
                         "standard_cloud": [s for s in all_services if s["category"] == "standard_cloud"],
                         "third_party": [s for s in all_services if s["category"] == "third_party"],
                         "unclassified": [s for s in all_services if s["category"] == "unclassified"]},
            "api_endpoint_candidates": api_endpoint_candidates,
            "url_references": url_references,
            "dynamic_api_call_candidates": dynamic_api_calls,
            "configuration_parameters": [{"name": name, "locations": sorted({loc(f) for f in group})}
                                          for name, group in sorted(_group_findings(findings, "configuration_parameter").items())],
            "environment": environment,
            "classification_legend": {
                "internal": "Declared as an app/container service in repository deployment files.",
                "internal_or_managed_unknown": "A database/broker client is detected, but the repository evidence does not show where it is hosted.",
                "standard_cloud": "Cloud SDK or cloud configuration evidence is present.",
                "third_party": "A named provider library/configuration clue is present.",
                "api_endpoint_candidates": "URLs observed in recognized HTTP request calls.",
                "url_references": "All extracted URL literals; includes informative/document links and unresolved references.",
            }}


def _group_findings(findings: list[Finding], category: str) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.category == category:
            grouped.setdefault(finding.name, []).append(finding)
    return grouped


def _files(root: Path) -> Iterable[Path]:
    for directory, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in IGNORES)
        for name in names:
            path = Path(directory) / name
            try:
                size = path.stat().st_size
                limit = MAX_MANIFEST_SIZE if path.name in {"package-lock.json", "npm-shrinkwrap.json", "uv.lock", "poetry.lock"} else MAX_FILE_SIZE
                if not path.is_symlink() and size <= limit:
                    yield path
            except OSError:
                continue


def _add(out: list[Finding], category: str, name: str, evidence: str, rel: str,
         line: int | None = None, confidence: str = "medium", **details) -> None:
    safe = re.sub(r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]*@", r"\1[REDACTED]@", evidence)
    safe = re.sub(r"(?i)([?&](?:token|key|secret|password|api_key|access_token)=)[^&\s]+", r"\1[REDACTED]", safe)
    safe = re.sub(r"(?i)(\b[A-Z0-9_.-]*(?:PASSWORD|SECRET|TOKEN|API_KEY|ACCESS_KEY)[A-Z0-9_.-]*\s*[:=]\s*)([^,\s'\"]+)", r"\1[REDACTED]", safe)
    out.append(Finding(category, name, safe[:300], rel, line, confidence, details))


def _scan_python(path: Path, rel: str, text: str, out: list[Finding], local_modules: set[str] | None = None) -> None:
    try:
        with __import__("warnings").catch_warnings():
            __import__("warnings").simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(text, filename=rel)
    except (SyntaxError, ValueError):
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name.split(".")[0]
                if module == "__future__" or module in {"dependocover", "scanner", "cli"}:
                    continue
                _add(out, "python_import", IMPORT_MAP.get(module, module), f"import {alias.name}", rel,
                     getattr(node, "lineno", None), "high", imported_module=module,
                     local_import=bool(local_modules and (alias.name in local_modules or module in local_modules)))
        elif isinstance(node, ast.ImportFrom) and node.module:
            module = node.module.split(".")[0]
            if module == "__future__" or module in {"dependocover", "scanner", "cli"}:
                continue
            _add(out, "python_import", IMPORT_MAP.get(module, module), f"from {node.module} import …", rel,
                 getattr(node, "lineno", None), "high", imported_module=module,
                 local_import=bool(local_modules and (node.module in local_modules or module in local_modules)))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        method = node.func.attr.upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "REQUEST"}:
            continue
        receiver = node.func.value
        if not isinstance(receiver, ast.Name) or receiver.id.lower() not in {"requests", "httpx", "aiohttp", "session", "client"}:
            continue
        url_node = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg in {"url", "uri"}), None)
        url = url_node.value if isinstance(url_node, ast.Constant) and isinstance(url_node.value, str) else None
        parameter_names: set[str] = set()
        for kw in node.keywords:
            if kw.arg in {"params", "json", "data", "headers"} and isinstance(kw.value, ast.Dict):
                for key_node in kw.value.keys:
                    if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                        parameter_names.add(key_node.value)
        safe_url = None
        if url:
            try:
                safe_url, host, query_params = _normalize_url(url)
                if safe_url:
                    parameter_names.update(query_params)
            except ValueError:
                pass
        _add(out, "api_call", f"{method} {safe_url or '[dynamic URL]'}",
             f"{receiver.id}.{method.lower()} call; URL={safe_url or '[dynamic]'}; parameters={','.join(sorted(parameter_names))}",
             rel, getattr(node, "lineno", None), "high" if safe_url else "medium",
             method=method, url=safe_url, parameter_names=sorted(parameter_names), receiver=receiver.id)


def _scan_manifest(path: Path, rel: str, text: str, out: list[Finding]) -> None:
    if path.name.startswith("requirements") and path.name.endswith(".txt"):
        for num, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith(("#", "-", "http://", "https://")):
                continue
            parsed = re.match(r"^([A-Za-z0-9_.-]+(?:\[[^\]]+\])?)", line)
            package = parsed.group(1) if parsed else ""
            if package:
                _add(out, "package", package, line, rel, num, "high", source="requirements")
    elif path.name == "pyproject.toml":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return
        project = data.get("project", {})
        if project.get("requires-python"):
            _add(out, "runtime_requirement", "Python", f"python {project['requires-python']}", rel,
                 confidence="high", source="pyproject.toml.project.requires-python", version=project["requires-python"])
        for group, deps in [("project.dependencies", project.get("dependencies", []))]:
            for dep in deps:
                _add(out, "package", re.split(r"[<>=!~; ]", dep, 1)[0], dep, rel,
                     confidence="high", source=group)
        for group, values in project.get("optional-dependencies", {}).items():
            for dep in values:
                _add(out, "package", re.split(r"[<>=!~; ]", dep, 1)[0], dep, rel,
                     confidence="high", source=f"optional-dependencies.{group}")
        poetry = data.get("tool", {}).get("poetry", {})
        groups = [poetry.get("dependencies", {})]
        groups.extend(g.get("dependencies", {}) for g in poetry.get("group", {}).values())
        for deps in groups:
            for dep, spec in deps.items():
                if dep.lower() != "python":
                    _add(out, "package", dep, f"{dep} = {spec}", rel, confidence="high", source="poetry")


def _scan_npm_manifest(path: Path, rel: str, text: str, out: list[Finding]) -> None:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, UnicodeError):
        return
    if path.name == "package.json":
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for package, version in data.get(section, {}).items():
                _add(out, "package", package, f"{package} {version}", rel, confidence="high",
                     source=f"npm.{section}", ecosystem="npm", version=version)
        node_version = data.get("engines", {}).get("node")
        if node_version:
            _add(out, "runtime_requirement", "Node.js", f"node {node_version}", rel, confidence="high",
                 source="package.json.engines.node", version=node_version)
        package_manager = data.get("packageManager")
        if package_manager:
            _add(out, "runtime_requirement", "Node package manager", package_manager, rel, confidence="high",
                 source="package.json.packageManager")
    elif path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
        packages = data.get("packages", {})
        for package_path, package_data in packages.items():
            if not package_path.startswith("node_modules/"):
                continue
            package = package_path.removeprefix("node_modules/")
            version = package_data.get("version")
            if version:
                _add(out, "package", package, f"{package} {version}", rel, confidence="high",
                     source="npm.lock", ecosystem="npm", version=version)
        # package-lock v1 stores a nested dependency tree.
        def walk(dependencies: dict) -> None:
            for package, package_data in dependencies.items():
                version = package_data.get("version")
                if version:
                    _add(out, "package", package, f"{package} {version}", rel, confidence="high",
                         source="npm.lock", ecosystem="npm", version=version)
                walk(package_data.get("dependencies", {}))
        if not packages:
            walk(data.get("dependencies", {}))


def _scan_javascript(path: Path, rel: str, text: str, out: list[Finding]) -> None:
    for lineno, raw in enumerate(text.splitlines(), 1):
        for match in JS_IMPORT_PATTERN.finditer(raw):
            imported = match.group(1)
            if imported.startswith((".", "/", "#", "node:")):
                continue
            if imported.startswith("@"):
                package = "/".join(imported.split("/")[:2])
            else:
                package = imported.split("/")[0]
            if package in NODE_BUILTINS:
                continue
            _add(out, "javascript_import", package, f"import/require {imported}", rel, lineno, "high",
                 imported_module=package, ecosystem="npm")

        # Recognize common literal HTTP calls; dynamic calls remain represented
        # by imports/config clues and cannot be statically resolved here.
        request_patterns = (
            (r"\bfetch\s*\(\s*['\"`]([^'\"`]+)['\"`]", "GET"),
            (r"\b(?:axios|got|request|undici)\.(get|post|put|patch|delete|head)\s*\(\s*['\"`]([^'\"`]+)['\"`]", None),
        )
        for pattern, default_method in request_patterns:
            for call in re.finditer(pattern, raw, re.I):
                method = (call.group(1).upper() if default_method is None else default_method)
                if default_method is not None:
                    options = raw[call.end():]
                    explicit_method = re.search(r"\bmethod\s*:\s*['\"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['\"]", options, re.I)
                    if explicit_method:
                        method = explicit_method.group(1).upper()
                url = call.group(2) if default_method is None else call.group(1)
                safe_url, host, params = _normalize_url(url)
                if safe_url:
                    _add(out, "api_call", f"{method} {safe_url}", f"JavaScript HTTP request: {raw.strip()}",
                         rel, lineno, "high", method=method, url=safe_url, parameter_names=params,
                         receiver="javascript", ecosystem="npm")


def _source_package(out: list[Finding], package: str, evidence: str, rel: str,
                    line: int, ecosystem: str, imported_as: str | None = None) -> None:
    package = package.strip().strip("<>").strip('"')
    if not package or package.startswith((".", "/")):
        return
    _add(out, "source_import", package, evidence.strip(), rel, line, "high",
         imported_module=imported_as or package, ecosystem=ecosystem)


def _scan_jvm(path: Path, rel: str, text: str, out: list[Finding]) -> None:
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if path.suffix.lower() == ".java":
            match = re.match(r"(?:import\s+static\s+|import\s+)([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)", line)
            if match:
                qualified = match.group(1)
                if not qualified.startswith(("java.", "javax.", "jdk.", "sun.")):
                    package = ".".join(qualified.split(".")[:3]) if qualified.count(".") >= 2 else qualified.rsplit(".", 1)[0]
                    _source_package(out, package, line, rel, lineno, "maven/gradle", qualified)
        elif path.name == "pom.xml":
            match = re.search(r"<(groupId|artifactId|version)>\s*([^<]+)\s*</\1>", line)
            # Each dependency block is processed as a whole below, keeping the
            # declared artifact and version together even when XML is formatted.
            continue
        else:
            # Gradle Groovy/Kotlin dependency declarations.
            match = re.search(r"\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|classpath|annotationProcessor)\s*\(?\s*['\"]([^:'\"]+):([^:'\"]+):([^'\"]+)['\"]", line)
            if match:
                group, artifact, version = match.groups()
                _add(out, "package", f"{group}:{artifact}", f"{group}:{artifact}:{version}", rel,
                     lineno, "high", ecosystem="maven/gradle", version=version)
    if path.name == "pom.xml":
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(text)
        except Exception:
            return
        ns = {"m": root.tag.split("}", 1)[0][1:]} if "}" in root.tag else {}
        def tag(name: str) -> str:
            return f"m:{name}" if ns else name
        for dep in root.findall(f".//{tag('dependency')}", ns):
            group = dep.findtext(tag("groupId"), default="", namespaces=ns)
            artifact = dep.findtext(tag("artifactId"), default="", namespaces=ns)
            version = dep.findtext(tag("version"), default="", namespaces=ns)
            if group and artifact:
                spec = f"{group}:{artifact}" + (f":{version}" if version else "")
                _add(out, "package", f"{group}:{artifact}", spec, rel, confidence="high",
                     ecosystem="maven/gradle", version=version or None)
    elif path.name in {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}:
        for lineno, raw in enumerate(text.splitlines(), 1):
            for match in re.finditer(r"['\"]([^:'\"]+):([^:'\"]+):([^'\"]+)['\"]", raw):
                group, artifact, version = match.groups()
                _add(out, "package", f"{group}:{artifact}", f"{group}:{artifact}:{version}", rel,
                     lineno, "high", ecosystem="maven/gradle", version=version)


def _scan_dotnet(path: Path, rel: str, text: str, out: list[Finding]) -> None:
    if path.suffix.lower() == ".cs":
        for lineno, raw in enumerate(text.splitlines(), 1):
            match = re.match(r"\s*(?:global\s+)?using\s+(?:static\s+)?([A-Za-z_][\w.]*)", raw)
            if match:
                namespace = match.group(1)
                if namespace.split(".", 1)[0] not in {"System", "Internal", "global"}:
                    _source_package(out, namespace, raw.strip(), rel, lineno, "nuget", namespace)
    if path.suffix.lower() in {".csproj", ".props", ".targets"}:
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(text)
        except Exception:
            return
        for node in root.iter():
            if node.tag.split("}")[-1] == "PackageReference":
                name = node.attrib.get("Include") or node.attrib.get("Update")
                version = node.attrib.get("Version")
                for child in node:
                    if child.tag.split("}")[-1] == "Version":
                        version = child.text or version
                if name:
                    _add(out, "package", name, f"{name} {version or '(version unspecified)'}", rel,
                         confidence="high", ecosystem="nuget", version=version)
    if path.name == "packages.config":
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(text)
        except Exception:
            return
        for node in root.iter():
            if node.tag.split("}")[-1] == "package" and node.attrib.get("id"):
                name, version = node.attrib["id"], node.attrib.get("version", "")
                _add(out, "package", name, f"{name} {version}".strip(), rel, confidence="high",
                     ecosystem="nuget", version=version or None)


def _scan_c_cpp(path: Path, rel: str, text: str, out: list[Finding]) -> None:
    for lineno, raw in enumerate(text.splitlines(), 1):
        match = re.match(r"\s*#\s*include\s*[<\"]([^>\"]+)[>\"]", raw)
        if match:
            header = match.group(1)
            if header not in {"stdio.h", "stdlib.h", "string.h", "stdint.h", "stdbool.h", "stddef.h", "assert.h", "math.h", "ctype.h", "errno.h", "limits.h", "time.h", "unistd.h", "iostream", "string", "vector", "map", "set", "memory", "utility", "algorithm", "stdexcept", "functional", "thread", "mutex", "atomic", "fstream", "sstream", "array", "optional", "variant", "tuple", "type_traits", "initializer_list", "new", "exception", "limits", "cmath", "cstring", "cstdint", "cstdio", "cstdlib"}:
                _source_package(out, header, raw.strip(), rel, lineno, "c/c++", header)
        if path.name in {"CMakeLists.txt", "Makefile", "makefile"}:
            cm = re.search(r"\bfind_package\s*\(\s*([A-Za-z0-9_.+-]+)(?:\s+([0-9][A-Za-z0-9_.+-]*))?", raw, re.I)
            if cm:
                _add(out, "package", cm.group(1), raw.strip(), rel, lineno, "high", ecosystem="cmake", version=cm.group(2))
            conan = re.search(r"\brequires\s*=\s*['\"]?([A-Za-z0-9_.+-]+)(?:/([^'\"\s]+))?", raw)
            if conan:
                _add(out, "package", conan.group(1), raw.strip(), rel, lineno, "high", ecosystem="conan", version=conan.group(2))
    if path.name in {"conanfile.txt", "conanfile.py"}:
        for lineno, raw in enumerate(text.splitlines(), 1):
            match = re.match(r"\s*([A-Za-z0-9_.+-]+)/([^\s#]+)", raw)
            if match:
                name, version = match.groups()
                _add(out, "package", name, raw.strip(), rel, lineno, "high", ecosystem="conan", version=version)
    if path.name in {"vcpkg.json", "vcpkg-configuration.json"}:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        for dep in data.get("dependencies", []):
            if isinstance(dep, str):
                _add(out, "package", dep, dep, rel, confidence="high", ecosystem="vcpkg")
            elif isinstance(dep, dict) and dep.get("name"):
                version = dep.get("version>=") or dep.get("version")
                _add(out, "package", dep["name"], f"{dep['name']} {version or ''}".strip(), rel,
                     confidence="high", ecosystem="vcpkg", version=version)


def _scan_lines(path: Path, rel: str, text: str, out: list[Finding]) -> None:
    lower = path.name.lower()
    if lower in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        service = None
        in_services = False
        current_section = None
        for num, raw in enumerate(text.splitlines(), 1):
            if re.match(r"^services:\s*$", raw):
                in_services = True
                service = None
                continue
            if in_services:
                match = re.match(r"^  ([A-Za-z0-9_.-]+):\s*(?:#.*)?$", raw)
                if match:
                    service = match.group(1)
                    current_section = None
                    continue
                if re.match(r"^[^\s#]", raw) and not raw.startswith("services:"):
                    in_services = False
                    service = None
                    continue
                prop = re.match(r"^    ([A-Za-z0-9_.-]+):(?:\s*(.*))?$", raw)
                if prop and service:
                    key, value = prop.groups()
                    value = (value or "").strip().strip("'\"")
                    current_section = key if key in {"ports", "environment", "depends_on", "volumes", "networks"} and not value else None
                    if key in {"image", "build"}:
                        _add(out, "container_service", value or service, raw.strip(), rel, num, "high", service=service)
                    elif key in {"ports", "depends_on", "volumes", "networks"} and value:
                        _add(out, "container_parameter", f"{service}.{key}", raw.strip(), rel, num, "high",
                             service=service, parameter=key, value=value)
                    continue
                if current_section and service:
                    entry = re.match(r"^\s{6}-\s*(.+?)\s*$", raw)
                    mapping = re.match(r"^\s{6}([A-Za-z0-9_.-]+):(?:\s*(.*))?$", raw)
                    if current_section == "environment":
                        if entry:
                            parameter = entry.group(1).split("=", 1)[0].strip()
                            _add(out, "container_parameter", f"{service}.environment.{parameter}", raw.strip(), rel, num, "high",
                                 service=service, parameter=f"environment.{parameter}", value="[configured]")
                        elif mapping:
                            parameter = mapping.group(1)
                            _add(out, "container_parameter", f"{service}.environment.{parameter}", raw.strip(), rel, num, "high",
                                 service=service, parameter=f"environment.{parameter}", value="[configured]")
                    elif entry:
                        value = entry.group(1).strip().strip("'\"")
                        _add(out, "container_parameter", f"{service}.{current_section}", raw.strip(), rel, num, "high",
                             service=service, parameter=current_section, value=value)
    if lower == "dockerfile" or lower.startswith("dockerfile."):
        for num, raw in enumerate(text.splitlines(), 1):
            if re.match(r"\s*(FROM|EXPOSE)\s+", raw, re.I):
                _add(out, "container", raw.strip(), raw.strip(), rel, num, "high")
    if lower in {"serverless.yml", "serverless.yaml", "template.yaml", "template.yml", "samconfig.toml"}:
        for num, raw in enumerate(text.splitlines(), 1):
            match = re.search(r"\b(AWS::[A-Za-z0-9:]+|AWS[A-Za-z0-9]+|provider:\s*aws)\b", raw)
            if match:
                _add(out, "cloud_infrastructure", match.group(1), raw.strip(), rel, num, "high")
    for num, raw in enumerate(text.splitlines(), 1):
        found_urls = URL_PATTERN.findall(raw)
        markdown_targets = re.findall(r"\]\((https?://[^)\s]+)\)", raw, re.I)
        if markdown_targets:
            found_urls = markdown_targets
        for raw_url in sorted(set(found_urls)):
            safe_url, host, param_names = _normalize_url(raw_url)
            if not safe_url:
                continue
            ref_context = None
            if markdown_targets:
                ref_context = "markdown_link"
            elif path.name.lower() == "package.json" and re.search(r"\b(homepage|repository|bugs)\b", raw, re.I):
                ref_context = "package_metadata"
            _add(out, "external_service", "External URL", f"URL literal: {raw_url}", rel, num, "medium",
                 url=safe_url, parameter_names=param_names, reference_context=ref_context)
        env_pattern = (r"(?:os\.)?environ\s*\[\s*['\"]([^'\"]+)['\"]\s*\]|"
                       r"(?:os\.)?environ\.get\(\s*['\"]([^'\"]+)['\"]|"
                       r"(?:os\.)?getenv\(\s*['\"]([^'\"]+)['\"]|"
                       r"get_env_value\(\s*['\"]([^'\"]+)['\"]|"
                       r"(?:process\.env|import\.meta\.env)\.([A-Za-z_][A-Za-z0-9_]*)")
        # Keep parameter names, never configured values.
        for match in re.finditer(env_pattern, raw):
            parameter = next((group for group in match.groups() if group), None)
            if parameter:
                _add(out, "configuration_parameter", parameter, f"Configuration key reference: {parameter}", rel, num, "medium")
        for service, pattern, description in SERVICE_PATTERNS:
            if re.search(pattern, raw, re.I):
                confidence = "high" if service in {"AWS", "AWS resource", "Google Cloud", "Microsoft Azure", "SMTP email", "Redis", "PostgreSQL", "MySQL", "MongoDB", "Celery broker"} else "medium"
                _add(out, "external_service", service, f"{description}: {raw.strip()}", rel, num, confidence)


def _github_url(value: str) -> str | None:
    """Normalize supported GitHub repository URLs; reject arbitrary remotes."""
    match = re.fullmatch(r"(?:https?://)?(?:www\.)?github\.com/([^/]+)/([^/#?]+?)(?:\.git)?/?(?:[?#].*)?", value.strip(), re.I)
    if not match:
        return None
    owner, repo = match.groups()
    if owner in {"", ".", ".."} or repo in {"", ".", ".."}:
        return None
    return f"https://github.com/{owner}/{repo}.git"


def _repository_metadata(root: Path, requested: str) -> dict:
    """Capture repository identity and revision for reproducible batch reports."""
    def git(*args: str) -> str | None:
        try:
            result = subprocess.run(["git", *args], cwd=root, check=True, capture_output=True,
                                    text=True, timeout=5)
            return result.stdout.strip() or None
        except (OSError, subprocess.SubprocessError):
            return None

    commit = git("rev-parse", "HEAD")
    tag = git("describe", "--tags", "--exact-match", "HEAD")
    describe = git("describe", "--tags", "--always")
    branch = git("branch", "--show-current")
    remote = git("remote", "get-url", "origin")
    version = None
    project_file = root / "pyproject.toml"
    try:
        project = tomllib.loads(project_file.read_text(encoding="utf-8")).get("project", {})
        version = project.get("version")
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        pass
    npm_package = None
    try:
        npm_data = json.loads((root / "package.json").read_text(encoding="utf-8"))
        npm_package = {"name": npm_data.get("name"), "version": npm_data.get("version")}
    except (OSError, UnicodeError, json.JSONDecodeError):
        pass
    dirty = None
    if commit:
        status = git("status", "--porcelain")
        dirty = bool(status)
    github_url = _github_url(requested)
    identifier = github_url.removesuffix(".git").rstrip("/").split("/")[-2:] if github_url else [root.name]
    return {"input": requested, "repository_id": "/".join(identifier), "canonical_url": github_url or remote,
            "local_path": None if github_url else str(root), "version": {"git_tag": tag, "commit": commit,
                                                   "git_describe": describe, "branch": branch,
                                                   "python_package_version": version, "npm_package": npm_package,
                                                   "working_tree_dirty": dirty},
            "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
            "dependocover_version": "0.1.0"}


def scan_repository(repository: str | Path, max_repository_size: int | None = None) -> ScanReport:
    """Scan a local Python repo or public GitHub URL without running its code."""
    raw = str(repository)
    github_url = _github_url(raw)
    if github_url:
        with tempfile.TemporaryDirectory(prefix="dependocover-") as temp_dir:
            checkout = Path(temp_dir) / "repo"
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", "--filter=blob:limit=2m", github_url, str(checkout)],
                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180,
                )
            except FileNotFoundError as exc:
                raise ValueError("Git is required to scan a GitHub URL. Install Git or use a local checkout.") from exc
            except subprocess.TimeoutExpired as exc:
                raise ValueError("GitHub checkout timed out after 180 seconds.") from exc
            except subprocess.CalledProcessError as exc:
                message = (exc.stderr or "").strip().splitlines()
                detail = message[-1] if message else "clone failed"
                raise ValueError(f"Could not clone {raw}: {detail}") from exc
            size_limit = max_repository_size or int(os.environ.get("DEPENDOCOVER_MAX_REPOSITORY_SIZE", DEFAULT_MAX_REPOSITORY_SIZE))
            size = sum(p.stat().st_size for p in checkout.rglob("*") if p.is_file() and not p.is_symlink())
            if size > size_limit:
                raise ValueError(f"Repository checkout exceeds the {size_limit // 1_000_000} MB scan limit. Set DEPENDOCOVER_MAX_REPOSITORY_SIZE or use --max-repository-size-mb to raise it.")
            report = _scan_local(checkout)
            report.repository = raw
            report.metadata = {"repository": _repository_metadata(checkout, raw)}
            return report
    root = Path(repository).expanduser().resolve()
    report = _scan_local(root)
    report.metadata = {"repository": _repository_metadata(root, raw)}
    return report


def _scan_local(root: Path) -> ScanReport:
    """Scan a checked-out/local repository path without importing its code."""
    if not root.is_dir():
        raise ValueError(f"Repository path is not a directory: {root}")
    findings: list[Finding] = []
    warnings: list[str] = []
    paths = list(_files(root))
    local_python_modules: set[str] = set()
    for candidate in paths:
        if candidate.suffix.lower() == ".py":
            relative = candidate.relative_to(root).with_suffix("")
            parts = list(relative.parts)
            if parts[-1] == "__init__":
                parts.pop()
            if parts:
                local_python_modules.add(".".join(parts))
                local_python_modules.add(parts[-1])
    scanned = py_count = js_count = ts_count = java_count = c_count = cpp_count = cs_count = 0
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        scanned += 1
        rel = path.relative_to(root).as_posix()
        if path.suffix.lower() == ".py":
            py_count += 1
            _scan_python(path, rel, text, findings, local_python_modules)
        if path.suffix.lower() in JS_EXTENSIONS:
            if path.suffix.lower() in {".ts", ".tsx"}:
                ts_count += 1
            else:
                js_count += 1
            _scan_javascript(path, rel, text, findings)
        if path.suffix.lower() in JAVA_EXTENSIONS:
            java_count += 1
            _scan_jvm(path, rel, text, findings)
        if path.suffix.lower() in C_EXTENSIONS:
            c_count += 1
            _scan_c_cpp(path, rel, text, findings)
        if path.suffix.lower() in CPP_EXTENSIONS:
            cpp_count += 1
            _scan_c_cpp(path, rel, text, findings)
        if path.suffix.lower() in CSHARP_EXTENSIONS:
            cs_count += 1
            _scan_dotnet(path, rel, text, findings)
        if path.name in {"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}:
            _scan_jvm(path, rel, text, findings)
        if path.suffix.lower() in {".csproj", ".props", ".targets"} or path.name == "packages.config":
            _scan_dotnet(path, rel, text, findings)
        if path.name in {"conanfile.txt", "conanfile.py", "CMakeLists.txt", "Makefile", "makefile", "vcpkg.json", "vcpkg-configuration.json"}:
            _scan_c_cpp(path, rel, text, findings)
        if ((path.name.startswith("requirements") and path.name.endswith(".txt")) or path.name == "pyproject.toml"):
            _scan_manifest(path, rel, text, findings)
        if path.name in {"package.json", "package-lock.json", "npm-shrinkwrap.json"}:
            _scan_npm_manifest(path, rel, text, findings)
        if path.suffix.lower() in {".py", ".yaml", ".yml", ".json", ".ini", ".cfg", ".env", ".sh", *CODE_EXTENSIONS, ".md", ".rst", ".html", ".txt", ".xml", ".gradle", ".kts", ".cmake", ".mk"} or path.name.lower().startswith("dockerfile") or path.name.lower().startswith(".env") or path.name in {"CMakeLists.txt", "Makefile", "makefile"}:
            _scan_lines(path, rel, text, findings)
    languages = (["Python"] if py_count else []) + (["JavaScript"] if js_count else []) + (["TypeScript"] if ts_count else []) + (["Java"] if java_count else []) + (["C"] if c_count else []) + (["C++"] if cpp_count else []) + (["C#"] if cs_count else [])
    if not languages:
        warnings.append("No supported Python, JavaScript, TypeScript, Java, C, C++, or C# source files were found.")
    if any(f.name == "External URL" for f in findings):
        warnings.append("URL matches can include documentation and examples; inspect the cited lines.")
    unique = {(f.category, f.name, f.file, f.line, f.evidence): f for f in findings}
    ordered = sorted(unique.values(), key=lambda f: (f.category, f.name.lower(), f.file, f.line or 0))
    return ScanReport(str(root), languages, scanned, ordered, warnings)
