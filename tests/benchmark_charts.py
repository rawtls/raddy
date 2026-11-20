import argparse
from collections import defaultdict
from html import escape
import json
from pathlib import Path
from statistics import median


SERVERS = {"raddy": ("Raddy", "#34d399"), "caddy": ("Caddy", "#7dd3fc"), "nginx": ("nginx", "#fbbf24")}
HTTP_CASES = {
    "http-static": "HTTP static file",
    "tls-keepalive": "HTTPS static · keep-alive",
    "tls-reconnect": "HTTPS static · new connections",
    "streaming-post": "HTTPS reverse proxy · POST",
}
LAYER4_CASES = {
    "tcp-keepalive": "TCP relay · keep-alive",
    "tcp-reconnect": "TCP relay · new connections",
    "tls-passthrough-keepalive": "TLS passthrough · keep-alive",
    "tls-passthrough-reconnect": "TLS passthrough · new connections",
}


def collect(path, cases):
    with path.open() as source:
        meta = json.loads(next(source))
        results = defaultdict(list)
        for line in source:
            run = json.loads(line)
            pair = run["case"], run["server"]
            if pair[0] in cases and pair[1] in SERVERS:
                if any(run["errors"].values()):
                    raise ValueError(f"Failed benchmark run: {pair}, run {run['run']}")
                results[pair].append(run)
    for case in cases:
        for server in SERVERS:
            rows = results[case, server]
            if sorted(row["run"] for row in rows) != list(range(1, meta["runs"] + 1)):
                raise ValueError(f"Incomplete benchmark: {case}, {server}")
    return results


def render(results, cases, metric, title, subtitle, value_label):
    def text(x, y, content, size=15, color="#dbe4f4", weight=400, anchor="start"):
        return (f'<text x="{x}" y="{y}" fill="{color}" font-size="{size}" '
                f'font-weight="{weight}" text-anchor="{anchor}">{escape(content)}</text>')

    svg = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 520" width="960" height="520" role="img" aria-labelledby="title description">',
           f'<title id="title">{escape(title)}</title>',
           f'<desc id="description">{escape(subtitle)} Numeric results are also available in the benchmark table.</desc>',
           '<rect width="960" height="520" rx="20" fill="#0f172a"/>',
           '<g font-family="system-ui, -apple-system, sans-serif">',
           text(28, 47, title, size=28, color="#f8fafc", weight=700),
           text(28, 75, subtitle, size=14, color="#b0bfd8")]
    for index, (server, (label, color)) in enumerate(SERVERS.items()):
        x = 650 + 98 * index
        svg.extend([f'<circle cx="{x}" cy="38" r="5" fill="{color}"/>', text(x + 13, 43, label)])

    for index, (case, heading) in enumerate(cases.items()):
        x, y = 24 + 464 * (index % 2), 99 + 196 * (index // 2)
        values = {server: median(row[metric] for row in results[case, server]) for server in SERVERS}
        scale = max(values.values())
        svg.extend([f'<rect x="{x}" y="{y}" width="448" height="176" rx="12" fill="#1c2941"/>',
                    text(x + 18, y + 35, heading, size=18, color="#f8fafc", weight=650)])
        for row, (server, (label, color)) in enumerate(SERVERS.items()):
            bar_y = y + 60 + 33 * row
            width = 270 * values[server] / scale if scale else 0
            svg.extend([text(x + 18, bar_y + 13, label, size=13),
                        f'<rect x="{x + 77}" y="{bar_y}" width="270" height="15" rx="4" fill="#32405a"/>',
                        f'<rect x="{x + 77}" y="{bar_y}" width="{width:.2f}" height="15" rx="4" fill="{color}"/>',
                        text(x + 427, bar_y + 13, value_label(values[server]), size=14, weight=650, anchor="end")])
    svg.extend([text(28, 502, "Independent scales by workload · see the benchmark notes for versions and methodology", size=13, color="#b0bfd8"),
                '</g>', '</svg>'])
    return '\n'.join(svg) + '\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--layer4", action="store_true")
    args = parser.parse_args()
    cases = LAYER4_CASES if args.layer4 else HTTP_CASES
    results = collect(args.results, cases)
    args.output.mkdir(parents=True, exist_ok=True)
    charts = [
        ("throughput.svg", "rps", "Throughput", "Median requests per second · higher is better", lambda value: f"{value:,.0f}"),
        ("latency-p99.svg", "p99_us", "Tail latency (p99)", "Median of run p99 values · milliseconds · lower is better", lambda value: f"{value / 1000:.2f} ms"),
    ]
    for name, metric, title, subtitle, value_label in charts:
        prefix = "layer4-" if args.layer4 else ""
        (args.output / f"{prefix}{name}").write_text(render(results, cases, metric, title, subtitle, value_label))


if __name__ == "__main__":
    main()
