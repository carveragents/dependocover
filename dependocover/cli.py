"""Command line interface."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .scanner import scan_repository


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dependocover", description="Discover dependencies in local or GitHub repositories across seven languages.")
    parser.add_argument("repository", nargs="?", default=".", help="Local repository path or GitHub URL (default: current directory)")
    parser.add_argument("--batch-file", help="File with one local path or GitHub URL per line; use with --output-dir")
    parser.add_argument("--retry-failed", action="store_true",
                        help="Retry only failed URLs recorded by the previous batch; combine with --batch-file and --output-dir")
    parser.add_argument("--format", choices=("text", "json", "both"), default="text")
    parser.add_argument("--output", "-o", help="Write output to a file")
    parser.add_argument("--output-dir", help="Write one report per repository using a repository/revision filename")
    parser.add_argument("--max-repository-size-mb", type=int, default=None,
                        help="Maximum cloned repository size in MB (default: 500; can also use DEPENDOCOVER_MAX_REPOSITORY_SIZE in bytes)")
    parser.add_argument("--version", action="version", version=f"dependocover {__version__}")
    return parser


def _render(report) -> str:
    payload = report.to_dict()
    inventory = payload["inventory"]
    counts = Counter(f["category"] for f in payload["findings"])
    lines = [f"Dependocover report: {report.repository}",
             f"Languages: {', '.join(report.languages) if report.languages else 'none detected'}",
             f"Files scanned: {report.files_scanned}", f"Findings: {len(report.findings)}"]
    repo_meta = report.metadata.get("repository", {})
    revision = repo_meta.get("version", {})
    if repo_meta:
        lines.append(f"Repository ID: {repo_meta.get('repository_id', 'unknown')}")
        npm_version = (revision.get("npm_package") or {}).get("version")
        lines.append(f"Version/revision: {revision.get('git_tag') or revision.get('git_describe') or revision.get('python_package_version') or npm_version or 'unknown'}")
    if counts:
        lines.append("Categories: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    lines.extend(("", "DEDUPLICATED ENVIRONMENT INVENTORY", "", "LIBRARIES"))
    for lib in inventory["libraries"]:
        version = "; ".join(lib["version_or_specifier"]) or "version not declared"
        lines.append(f"- {lib['name']} [{', '.join(lib['ecosystem'])}] — {version}")
        if lib["imported_as"]:
            lines.append(f"  imported as: {', '.join(lib['imported_as'])}")
        if lib["locations"]:
            lines.append(f"  found at: {', '.join(lib['locations'][:8])}")
    for group_name, title in (("internal", "INTERNAL SERVICES"), ("internal_or_managed_unknown", "DATABASES / BROKERS: HOSTING UNKNOWN"),
                              ("standard_cloud", "STANDARD CLOUD SERVICES"), ("third_party", "THIRD-PARTY SERVICES"), ("unclassified", "UNCLASSIFIED SERVICE CLUES")):
        lines.extend(("", title))
        services = inventory["services"][group_name]
        if not services:
            lines.append("- None detected")
        for service in services:
            lines.append(f"- {service['name']} [{service.get('subcategory', 'service')}]")
            if service.get("image_or_build"):
                lines.append(f"  image/build: {', '.join(service['image_or_build'])}")
            if service.get("deployment_parameters"):
                lines.append(f"  deployment parameters: {json.dumps(service['deployment_parameters'], ensure_ascii=False)}")
            if service.get("configuration_parameters"):
                names = sorted({p["name"] for p in service["configuration_parameters"]})
                lines.append(f"  configuration keys: {', '.join(names)}")
            for endpoint in service.get("endpoints", []):
                lines.append(f"  endpoint: {', '.join(endpoint['methods']) or 'HTTP'} {endpoint['url']}")
                if endpoint["parameter_names"]:
                    lines.append(f"    request keys: {', '.join(endpoint['parameter_names'])}")
            if service.get("locations"):
                lines.append(f"  found at: {', '.join(service['locations'][:8])}")
    lines.extend(("", "API ENDPOINTS (observed request calls)"))
    if not inventory["api_endpoint_candidates"]:
        lines.append("- None statically identified")
    for endpoint in inventory["api_endpoint_candidates"]:
        lines.append(f"- {', '.join(endpoint['methods']) or 'HTTP'} {endpoint['url']} [{endpoint['classification']} / {endpoint['subcategory']}]")
        if endpoint["parameter_names"]:
            lines.append(f"  parameter names: {', '.join(endpoint['parameter_names'])}")
        lines.append(f"  found at: {', '.join(endpoint['locations'][:8])}")
    lines.extend(("", "OTHER URL REFERENCES"))
    for ref in inventory["url_references"]:
        if ref in inventory["api_endpoint_candidates"]:
            continue
        lines.append(f"- {ref['url']} [{ref['classification']} / {ref['subcategory']}] — {', '.join(ref['locations'][:5])}")
    lines.extend(("", "CONFIGURATION PARAMETERS"))
    lines.extend(f"- {p['name']} — {', '.join(p['locations'][:8])}" for p in inventory["configuration_parameters"])
    lines.extend(("", "CONTAINER / ENVIRONMENT DETAILS"))
    for item in inventory["environment"]:
        lines.append(f"- {item['name']} [{item['type']}]")
        if item["versions_or_tags"]:
            lines.append(f"  versions/tags: {', '.join(item['versions_or_tags'])}")
        if item["ports"]:
            lines.append(f"  ports: {', '.join(map(str, item['ports']))}")
        lines.append(f"  found at: {', '.join(item['locations'][:8])}")
    if report.warnings:
        lines.extend(("", "Review notes:", *(f"- {warning}" for warning in report.warnings)))
    lines.extend(("", "Taxonomy version: " + inventory["taxonomy_version"],
                  "Use --format json for the full inventory, evidence, parameters and locations."))
    return "\n".join(lines) + "\n"


def _write_reports(output_dir: Path, target: str, report, output_format: str) -> list[Path]:
    repository_dir = output_dir / _report_directory_name(target, report)
    repository_dir.mkdir(parents=True, exist_ok=True)
    formats = ("text",) if output_format == "text" else ("json", "text")
    written = []
    for fmt in formats:
        suffix = "json" if fmt == "json" else "txt"
        destination = repository_dir / f"inventory.{suffix}"
        content = json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n" if fmt == "json" else _render(report)
        destination.write_text(content, encoding="utf-8")
        written.append(destination)
    return written


def _report_directory_name(repository: str, report) -> str:
    meta = report.metadata.get("repository", {})
    slug = meta.get("repository_id", Path(repository).name).replace("/", "-")
    revision = meta.get("version", {}).get("commit") or meta.get("version", {}).get("git_tag")
    if revision:
        suffix = revision[:8]
    else:
        suffix = hashlib.sha1(repository.encode("utf-8")).hexdigest()[:8]
    return f"{slug}-{suffix}"


def _retry_targets(output_dir: Path) -> list[str]:
    """Read GitHub URLs from the most recent dependocover failed-runs log."""
    failure_log = output_dir / "failed-runs.txt"
    try:
        content = failure_log.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ValueError(f"No failure log found at {failure_log}. Run a batch first; failures are recorded automatically.")
    return [line.strip() for line in content.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.batch_file:
        if not args.output_dir:
            print("dependocover: --batch-file requires --output-dir", file=sys.stderr)
            return 2
        output_dir = Path(args.output_dir).expanduser()
        try:
            targets = (_retry_targets(output_dir) if args.retry_failed else
                       [line.strip() for line in Path(args.batch_file).expanduser().read_text(encoding="utf-8").splitlines()
                        if line.strip() and not line.lstrip().startswith("#")])
        except (OSError, ValueError) as exc:
            print(f"dependocover: {exc}", file=sys.stderr)
            return 2
        if args.retry_failed and not targets:
            print("No failed repositories to retry.")
            return 0
        failures = 0
        failed_targets: list[str] = []
        if args.retry_failed:
            print(f"Retrying {len(targets)} failed repository/repositories from {output_dir / 'failed-runs.txt'}")
        for target in targets:
            try:
                batch_report = scan_repository(target, (args.max_repository_size_mb * 1_000_000) if args.max_repository_size_mb else None)
                destinations = _write_reports(output_dir, target, batch_report, args.format)
                print(f"Scanned {target} -> {', '.join(str(path) for path in destinations)}")
            except (OSError, ValueError) as exc:
                failures += 1
                failed_targets.append(target)
                print(f"Failed {target}: {exc}", file=sys.stderr)
        failure_log = output_dir / "failed-runs.txt"
        if failed_targets:
            failure_log.parent.mkdir(parents=True, exist_ok=True)
            failure_log.write_text("\n".join(failed_targets) + "\n", encoding="utf-8")
            print(f"Failed repository list written to {failure_log}")
        else:
            failure_log.unlink(missing_ok=True)
        print(f"Batch complete: {len(targets) - failures}/{len(targets)} succeeded")
        return 1 if failures else 0
    try:
        report = scan_repository(args.repository, (args.max_repository_size_mb * 1_000_000) if args.max_repository_size_mb else None)
    except (OSError, ValueError) as exc:
        print(f"dependocover: {exc}", file=sys.stderr)
        return 2
    if args.format == "both" and not (args.output_dir or args.output):
        print("dependocover: --format both requires --output-dir or --output", file=sys.stderr)
        return 2
    output = json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n" if args.format == "json" else _render(report)
    if args.output_dir:
        try:
            output_dir = Path(args.output_dir).expanduser()
            _write_reports(output_dir, args.repository, report, args.format)
        except OSError as exc:
            print(f"dependocover: cannot write report: {exc}", file=sys.stderr)
            return 2
    elif args.output:
        try:
            destination = Path(args.output).expanduser()
            destination.write_text(output, encoding="utf-8")
            if args.format in {"json", "both"}:
                json_path = destination.with_suffix(".json")
                text_path = destination.with_suffix(".txt")
                json_path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                text_path.write_text(_render(report), encoding="utf-8")
        except OSError as exc:
            print(f"dependocover: cannot write report: {exc}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
