#!/usr/bin/env python3
"""Build the D3FEND-AWS matrix HTML page from technique YAML files."""

import html
import json
import yaml
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
CATALOG_PATH = ROOT / "catalog" / "aws-ttc-attacks.yaml"
OUT_PATH = ROOT / "docs" / "index.html"

TACTICS = [
    ("detect", "Detect", "Identify threats using AWS-native signals"),
    ("harden", "Harden", "Preventive controls via AWS service configuration"),
    ("evict", "Evict", "Contain and remove threats during incidents"),
]

TACTIC_COLORS = {
    "detect": "#0073bb",
    "harden": "#1d8102",
    "evict": "#d13212",
}


def load_techniques():
    techniques = {"detect": [], "harden": [], "evict": []}
    for tactic_dir in DATA_DIR.iterdir():
        if not tactic_dir.is_dir() or tactic_dir.name not in techniques:
            continue
        for filepath in sorted(tactic_dir.glob("*.yaml")):
            with open(filepath) as f:
                doc = yaml.safe_load(f)
            doc["_file"] = filepath.name
            techniques[tactic_dir.name].append(doc)
    for key in techniques:
        techniques[key].sort(key=lambda t: t["id"])
    return techniques


def load_attack_catalog():
    with open(CATALOG_PATH) as f:
        catalog = yaml.safe_load(f)
    lookup = {}
    for tactic in catalog["tactics"]:
        for t in tactic["techniques"]:
            lookup[t["id"]] = {"name": t["name"], "tactic": tactic["name"]}
    return lookup


def esc(text):
    return html.escape(str(text))


def build_html(techniques, attack_lookup):
    attack_to_defenses = {}
    for tactic_key in techniques:
        for t in techniques[tactic_key]:
            for counter_id in t.get("counters", []):
                attack_to_defenses.setdefault(counter_id, []).append(t["id"])

    all_techniques = {}
    for tactic_key in techniques:
        for t in techniques[tactic_key]:
            counters_detail = []
            for c in t.get("counters", []):
                info = attack_lookup.get(c, {})
                counters_detail.append({
                    "id": c,
                    "name": info.get("name", ""),
                    "tactic": info.get("tactic", ""),
                })
            all_techniques[t["id"]] = {
                "id": t["id"],
                "name": t["name"],
                "tactic": t["tactic"],
                "category": t["category"],
                "description": t["description"].strip(),
                "aws_services": t["aws_services"],
                "counters": counters_detail,
                "d3fend_ref": t.get("d3fend_ref", ""),
            }

    columns_html = ""
    for tactic_key, tactic_name, tactic_desc in TACTICS:
        color = TACTIC_COLORS[tactic_key]
        cards = techniques[tactic_key]
        cards_html = ""
        for t in cards:
            service_tags = "".join(
                f'<span class="tag">{esc(s)}</span>' for s in t["aws_services"]
            )
            counter_count = len(t.get("counters", []))
            cards_html += f"""
        <div class="card" data-id="{esc(t['id'])}" onclick="showDetail('{esc(t['id'])}')">
          <div class="card__id">{esc(t['id'])}</div>
          <div class="card__name">{esc(t['name'])}</div>
          <div class="card__category">{esc(t['category'])}</div>
          <div class="card__services">{service_tags}</div>
          <div class="card__counter-count">{counter_count} attack technique{"s" if counter_count != 1 else ""} countered</div>
        </div>"""

        columns_html += f"""
      <div class="tactic-column">
        <div class="tactic-header" style="background: {color}">
          <h2 class="tactic-title">{esc(tactic_name)}</h2>
          <p class="tactic-desc">{esc(tactic_desc)}</p>
          <span class="tactic-count">{len(cards)} techniques</span>
        </div>
        <div class="tactic-cards">{cards_html}
        </div>
      </div>"""

    techniques_json = json.dumps(all_techniques)

    total = sum(len(techniques[k]) for k in techniques)
    total_attacks = len(attack_lookup)
    covered = len(attack_to_defenses)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>D3FEND-AWS Matrix</title>
  <meta name="description" content="AWS-scoped defensive technique mappings modeled on MITRE D3FEND" />
  <style>
    *, *::before, *::after {{ margin: 0; padding: 0; box-sizing: border-box; }}

    :root {{
      --primary-bg: #ffffff;
      --secondary-bg: #f8f9fa;
      --header-bg: #232f3e;
      --header-accent: #ff9900;
      --primary-text: #16191f;
      --secondary-text: #545b64;
      --link-color: #0073bb;
      --link-hover: #0073bb;
      --border-color: #eaeded;
      --border-dark: #d5dbdb;
      --code-bg: #f8f8f8;
      --detect: #0073bb;
      --harden: #1d8102;
      --evict: #d13212;
      --stats-bg: #dcf0ff;
      --stats-border: #b8d9f0;
    }}

    body {{
      background: var(--primary-bg);
      color: var(--primary-text);
      font-family: "Amazon Ember", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      line-height: 1.5;
    }}

    /* Site header */
    .site-header {{
      background: var(--header-bg);
      color: white;
      height: 60px;
      position: sticky;
      top: 0;
      z-index: 1000;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }}
    .header-container {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      height: 100%;
      max-width: 1800px;
      margin: 0 auto;
      padding: 0 20px;
    }}
    .header-title {{
      font-size: 1.25rem;
      font-weight: 500;
      color: white;
    }}
    .header-title span {{
      color: var(--header-accent);
    }}
    .header-nav {{
      display: flex;
      gap: 1.25rem;
      align-items: center;
    }}
    .header-nav a {{
      display: flex;
      align-items: center;
      color: rgba(255,255,255,0.7);
      text-decoration: none;
      transition: color 0.2s, opacity 0.2s;
      opacity: 0.75;
    }}
    .header-nav a:hover {{
      color: white;
      opacity: 1;
    }}
    .header-nav svg {{
      height: 24px;
      width: auto;
      fill: currentColor;
    }}
    .header-nav .aws-logo {{
      height: 28px;
    }}

    /* Landing section */
    .landing {{
      max-width: 1600px;
      margin: 0 auto;
      padding: 2.5rem 2rem 1.5rem;
    }}
    .landing h1 {{
      font-size: 2rem;
      font-weight: 700;
      color: var(--header-bg);
      margin-bottom: 0.5rem;
      letter-spacing: -0.02em;
    }}
    .landing > p {{
      color: var(--secondary-text);
      font-size: 1rem;
      margin-bottom: 1.5rem;
    }}

    /* Stats row */
    .stats-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 1rem;
      margin-bottom: 1.5rem;
    }}
    .stats-card {{
      background: var(--stats-bg);
      border: 2px solid var(--stats-border);
      border-radius: 12px;
      padding: 1.25rem 1.5rem;
      text-align: center;
      min-width: 140px;
      flex: 1;
      max-width: 200px;
    }}
    .stats-number {{
      font-size: 2rem;
      font-weight: 700;
      color: var(--header-bg);
      display: block;
      line-height: 1;
      margin-bottom: 0.375rem;
    }}
    .stats-label {{
      font-size: 0.75rem;
      color: var(--header-bg);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-weight: 600;
    }}

    /* Search */
    .search-bar {{
      padding: 0.75rem 2rem;
      border-bottom: 1px solid var(--border-color);
      position: sticky;
      top: 60px;
      background: var(--primary-bg);
      z-index: 10;
      max-width: 1600px;
      margin: 0 auto;
    }}
    .search-input {{
      width: 100%;
      max-width: 400px;
      padding: 0.5rem 0.75rem;
      background: var(--primary-bg);
      border: 1px solid var(--border-dark);
      border-radius: 4px;
      color: var(--primary-text);
      font-size: 0.875rem;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
    }}
    .search-input:focus {{
      border-color: var(--link-color);
      box-shadow: 0 0 0 3px rgba(0,115,187,0.1);
    }}
    .search-input::placeholder {{
      color: #aab7b8;
    }}

    /* Matrix layout */
    .matrix-wrapper {{
      max-width: 1600px;
      margin: 0 auto;
      padding: 0 1rem;
    }}
    .matrix-container {{
      background: white;
      border-radius: 12px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
      border: 1px solid var(--border-color);
      margin: 1rem 0 2rem;
      overflow: hidden;
    }}
    .matrix {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      min-width: 900px;
    }}

    /* Tactic column */
    .tactic-column {{
      border-right: 1px solid var(--border-color);
    }}
    .tactic-column:last-child {{
      border-right: none;
    }}
    .tactic-header {{
      padding: 14px 18px;
      color: white;
      text-align: center;
    }}
    .tactic-title {{
      font-size: 1rem;
      font-weight: 600;
      margin-bottom: 0.125rem;
      color: white;
    }}
    .tactic-desc {{
      font-size: 0.7rem;
      color: rgba(255,255,255,0.8);
      margin-bottom: 0.25rem;
    }}
    .tactic-count {{
      font-size: 0.65rem;
      color: rgba(255,255,255,0.65);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .tactic-cards {{
      padding: 8px;
      display: flex;
      flex-direction: column;
      gap: 1px;
      background: var(--secondary-bg);
    }}

    /* Cards */
    .card {{
      background: white;
      border: 1px solid var(--border-color);
      border-radius: 4px;
      padding: 10px 12px;
      cursor: pointer;
      transition: background 0.15s, border-color 0.15s, box-shadow 0.15s;
    }}
    .card:hover {{
      border-color: var(--border-dark);
      background: #fafafa;
      box-shadow: 0 1px 3px rgba(0,0,0,0.08);
    }}
    .card.hidden {{
      display: none;
    }}
    .card__id {{
      font-size: 0.65rem;
      font-family: "Amazon Mono", Menlo, Monaco, Consolas, monospace;
      color: var(--secondary-text);
      margin-bottom: 2px;
    }}
    .card__name {{
      font-size: 0.8rem;
      font-weight: 500;
      color: var(--link-color);
      margin-bottom: 2px;
    }}
    .card__category {{
      font-size: 0.65rem;
      color: var(--secondary-text);
      margin-bottom: 6px;
    }}
    .card__services {{
      display: flex;
      flex-wrap: wrap;
      gap: 3px;
      margin-bottom: 6px;
    }}
    .tag {{
      display: inline-block;
      font-size: 0.6rem;
      padding: 1px 6px;
      border-radius: 3px;
      background: #f0f8ff;
      border: 1px solid var(--stats-border);
      color: var(--header-bg);
      white-space: nowrap;
    }}
    .card__counter-count {{
      font-size: 0.6rem;
      color: #879596;
    }}

    /* Detail panel */
    .overlay {{
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.35);
      z-index: 100;
    }}
    .overlay.active {{
      display: block;
    }}
    .detail-panel {{
      display: none;
      position: fixed;
      top: 0;
      right: 0;
      bottom: 0;
      width: 540px;
      max-width: 100vw;
      background: white;
      border-left: 1px solid var(--border-color);
      z-index: 101;
      overflow-y: auto;
      padding: 0;
      box-shadow: -4px 0 16px rgba(0,0,0,0.12);
    }}
    .detail-panel.active {{
      display: block;
    }}
    .detail-panel__header {{
      background: var(--header-bg);
      color: white;
      padding: 1.25rem 1.5rem;
      position: relative;
    }}
    .detail-panel__close {{
      position: absolute;
      top: 1rem;
      right: 1rem;
      background: none;
      border: 1px solid rgba(255,255,255,0.25);
      border-radius: 4px;
      color: rgba(255,255,255,0.7);
      font-size: 1.25rem;
      cursor: pointer;
      width: 30px;
      height: 30px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: background 0.2s;
    }}
    .detail-panel__close:hover {{
      background: rgba(255,255,255,0.1);
      color: white;
    }}
    .detail-panel__body {{
      padding: 1.5rem;
    }}
    .detail__id {{
      font-family: "Amazon Mono", Menlo, Monaco, Consolas, monospace;
      font-size: 0.75rem;
      color: rgba(255,255,255,0.6);
      margin-bottom: 0.375rem;
    }}
    .detail__tactic {{
      display: inline-block;
      font-size: 0.65rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 2px 8px;
      border-radius: 3px;
      margin-bottom: 0.5rem;
    }}
    .detail__tactic--detect {{ background: rgba(0,115,187,0.25); color: #8dd8ff; }}
    .detail__tactic--harden {{ background: rgba(29,129,2,0.25); color: #a2e88e; }}
    .detail__tactic--evict {{ background: rgba(209,50,18,0.25); color: #ff9e8e; }}
    .detail__name {{
      font-size: 1.2rem;
      font-weight: 600;
      color: white;
    }}
    .detail__category {{
      font-size: 0.8rem;
      color: var(--secondary-text);
      margin-bottom: 0;
    }}
    .detail__section {{
      margin-bottom: 1.25rem;
    }}
    .detail__section-title {{
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--secondary-text);
      margin-bottom: 0.5rem;
      padding-bottom: 0.375rem;
      border-bottom: 1px solid var(--border-color);
    }}
    .detail__description {{
      font-size: 0.85rem;
      line-height: 1.6;
      color: var(--primary-text);
    }}
    .detail__services {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.375rem;
    }}
    .detail__services .tag {{
      font-size: 0.75rem;
      padding: 3px 8px;
    }}
    .detail__counters {{
      list-style: none;
    }}
    .detail__counters li {{
      padding: 0.5rem 0;
      border-bottom: 1px solid var(--border-color);
      font-size: 0.8rem;
      display: flex;
      flex-direction: column;
      gap: 1px;
    }}
    .detail__counters li:last-child {{
      border-bottom: none;
    }}
    .detail__counter-id {{
      font-family: "Amazon Mono", Menlo, Monaco, Consolas, monospace;
      color: var(--link-color);
      font-size: 0.7rem;
      font-weight: 500;
      text-decoration: none;
    }}
    .detail__counter-id:hover {{
      color: var(--link-hover);
      text-decoration: underline;
    }}
    .detail__counter-name {{
      color: var(--primary-text);
      font-weight: 500;
    }}
    .detail__counter-tactic {{
      font-size: 0.65rem;
      color: var(--secondary-text);
    }}
    .detail__d3fend {{
      font-family: "Amazon Mono", Menlo, Monaco, Consolas, monospace;
      font-size: 0.8rem;
      color: var(--link-color);
      background: var(--code-bg);
      padding: 4px 8px;
      border-radius: 3px;
      border: 1px solid var(--border-color);
    }}

    /* Footer */
    .site-footer {{
      background: var(--header-bg);
      color: #ccc;
      padding: 1.5rem 0;
    }}
    .footer-container {{
      max-width: 1600px;
      margin: 0 auto;
      padding: 0 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .footer-container p {{
      font-size: 0.8rem;
      margin: 0;
    }}
    .footer-container a {{
      color: #ccc;
      text-decoration: none;
      font-size: 0.8rem;
    }}
    .footer-container a:hover {{
      color: white;
    }}

    /* Responsive */
    @media (max-width: 1024px) {{
      .matrix {{
        min-width: 0;
      }}
      .matrix-container {{
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
      }}
    }}
    @media (max-width: 768px) {{
      .matrix {{
        grid-template-columns: 1fr;
        min-width: 0;
      }}
      .tactic-column {{
        border-right: none;
        border-bottom: 1px solid var(--border-color);
      }}
      .tactic-header {{
      }}
      .detail-panel {{
        width: 100vw;
      }}
      .header-nav {{
        display: none;
      }}
      .stats-row {{
        gap: 0.5rem;
      }}
      .stats-card {{
        min-width: 100px;
        padding: 0.75rem 1rem;
      }}
      .stats-number {{
        font-size: 1.5rem;
      }}
      .landing {{
        padding: 1.5rem 1rem 1rem;
      }}
      .landing h1 {{
        font-size: 1.5rem;
      }}
    }}
  </style>
</head>
<body>

  <header class="site-header">
    <div class="header-container">
      <div class="header-title">D3FEND<span>-AWS</span></div>
      <nav class="header-nav">
        <a href="https://github.com/mattgurr/d3fend-aws" target="_blank" rel="noopener" title="GitHub">
          <svg viewBox="0 0 16 16"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
        </a>
        <a href="https://d3fend.mitre.org/" target="_blank" rel="noopener" title="MITRE D3FEND">
          <svg viewBox="0 0 200 50" style="height: 20px"><text x="0" y="38" font-family="Arial,sans-serif" font-weight="700" font-size="42" fill="currentColor" letter-spacing="-1">MITRE</text></svg>
        </a>
        <a href="https://aws-samples.github.io/threat-technique-catalog-for-aws/matrix.html" target="_blank" rel="noopener" title="AWS Threat Technique Catalog" class="aws-logo">
          <svg viewBox="0 0 304 182"><path d="M86.4 66.4c0 3.7.4 6.7 1.1 8.9.8 2.2 1.8 4.6 3.2 7.2.5.8.7 1.6.7 2.3 0 1-.6 2-1.9 3l-6.3 4.2c-.9.6-1.8.9-2.6.9-1 0-2-.5-3-1.4-1.4-1.5-2.6-3.1-3.6-4.7-1-1.7-2-3.6-3.1-5.9-7.8 9.2-17.6 13.8-29.4 13.8-8.4 0-15.1-2.4-20-7.2-4.9-4.8-7.4-11.2-7.4-19.2 0-8.5 3-15.4 9.1-20.6 6.1-5.2 14.2-7.8 24.5-7.8 3.4 0 6.9.3 10.6.8 3.7.5 7.5 1.3 11.5 2.2v-7.3c0-7.6-1.6-12.9-4.7-16-3.2-3.1-8.6-4.6-16.3-4.6-3.5 0-7.1.4-10.8 1.3-3.7.9-7.3 2-10.8 3.4-1.6.7-2.8 1.1-3.5 1.3-.7.2-1.2.3-1.6.3-1.4 0-2.1-1-2.1-3.1v-4.9c0-1.6.2-2.8.7-3.5.5-.7 1.4-1.4 2.8-2.1 3.5-1.8 7.7-3.3 12.6-4.5C41 1.9 46.2 1.3 51.7 1.3c12.2 0 21.1 2.8 26.8 8.3 5.6 5.6 8.5 14 8.5 25.2v33.2h-.6zm-40.6 15.2c3.3 0 6.7-.6 10.3-1.8 3.6-1.2 6.8-3.4 9.5-6.4 1.6-1.9 2.8-4 3.4-6.4.6-2.4 1-5.3 1-8.7v-4.2c-2.9-.7-6-1.3-9.2-1.7-3.2-.4-6.3-.6-9.4-.6-6.7 0-11.6 1.3-14.9 4-3.3 2.7-4.9 6.5-4.9 11.5 0 4.7 1.2 8.2 3.7 10.6 2.4 2.5 5.9 3.7 10.5 3.7zm80.3 10.8c-1.8 0-3-.3-3.8-1-.8-.6-1.5-2-2.1-3.9l-23.5-77.3c-.6-2-.9-3.3-.9-4 0-1.6.8-2.5 2.4-2.5h9.8c1.9 0 3.2.3 3.9 1 .8.6 1.4 2 2 3.9l16.8 66.2 15.6-66.2c.5-2 1.1-3.3 1.9-3.9.8-.6 2.2-1 4-1h8c1.9 0 3.2.3 4 1 .8.6 1.5 2 1.9 3.9l15.8 67 17.3-67c.6-2 1.3-3.3 2-3.9.8-.6 2.1-1 3.9-1h9.3c1.6 0 2.5.8 2.5 2.5 0 .5-.1 1-.2 1.6-.1.6-.3 1.4-.7 2.5l-24.1 77.3c-.6 2-1.3 3.3-2.1 3.9-.8.6-2.1 1-3.8 1h-8.6c-1.9 0-3.2-.3-4-1-.8-.7-1.5-2-1.9-4L156 23l-15.4 64.4c-.5 2-1.1 3.3-1.9 4-.8.7-2.2 1-4 1h-8.6zm128.5 2.7c-5.2 0-10.4-.6-15.4-1.8-5-1.2-8.9-2.5-11.5-4-1.6-.9-2.7-1.9-3.1-2.8-.4-.9-.6-1.9-.6-2.8v-5.1c0-2.1.8-3.1 2.3-3.1.6 0 1.2.1 1.8.3.6.2 1.5.6 2.5 1 3.4 1.5 7.1 2.7 11 3.5 4 .8 7.9 1.2 11.9 1.2 6.3 0 11.2-1.1 14.6-3.3 3.4-2.2 5.2-5.4 5.2-9.5 0-2.8-.9-5.1-2.7-7-1.8-1.9-5.2-3.6-10.1-5.2l-14.5-4.5c-7.3-2.3-12.7-5.7-16-10.2-3.3-4.4-5-9.3-5-14.5 0-4.2.9-7.9 2.7-11.1 1.8-3.2 4.2-6 7.2-8.2 3-2.3 6.4-4 10.4-5.2 4-1.2 8.2-1.7 12.6-1.7 2.2 0 4.5.1 6.7.4 2.3.3 4.4.7 6.5 1.1 2 .5 3.9 1 5.7 1.6 1.8.6 3.2 1.2 4.2 1.8 1.4.8 2.4 1.6 3 2.5.6.8.9 1.9.9 3.3v4.7c0 2.1-.8 3.2-2.3 3.2-.8 0-2.1-.4-3.8-1.2-5.7-2.6-12.1-3.9-19.2-3.9-5.7 0-10.2.9-13.3 2.8-3.1 1.9-4.7 4.8-4.7 8.9 0 2.8 1 5.2 3 7.1 2 1.9 5.7 3.8 11 5.5l14.2 4.5c7.2 2.3 12.4 5.5 15.5 9.6 3.1 4.1 4.6 8.8 4.6 14 0 4.3-.9 8.2-2.6 11.6-1.8 3.4-4.2 6.4-7.3 8.8-3.1 2.5-6.8 4.3-11.1 5.6-4.5 1.4-9.2 2.1-14.3 2.1z" fill="currentColor"/><path d="M273.5 143.7c-32.9 24.3-80.7 37.2-121.8 37.2-57.6 0-109.5-21.3-148.7-56.7-3.1-2.8-.3-6.6 3.4-4.4 42.4 24.6 94.7 39.5 148.8 39.5 36.5 0 76.6-7.6 113.5-23.2 5.5-2.5 10.2 3.6 4.8 7.6z" fill="var(--header-accent)"/><path d="M287.2 128.1c-4.2-5.4-27.8-2.6-38.5-1.3-3.2.4-3.7-2.4-.8-4.5 18.8-13.2 49.7-9.4 53.3-5 3.6 4.5-1 35.4-18.6 50.2-2.7 2.3-5.3 1.1-4.1-1.9 4-9.9 12.9-32.2 8.7-37.5z" fill="var(--header-accent)"/></svg>
        </a>
      </nav>
    </div>
  </header>

  <div class="landing">
    <h1>Defensive Technique Matrix</h1>
    <p>AWS-native defensive techniques mapped to the AWS Threat Technique Catalog, modeled on MITRE D3FEND.</p>
    <div class="stats-row">
      <div class="stats-card">
        <span class="stats-number">{total}</span>
        <span class="stats-label">Defensive Techniques</span>
      </div>
      <div class="stats-card">
        <span class="stats-number">{covered}/{total_attacks}</span>
        <span class="stats-label">Attacks Covered</span>
      </div>
      <div class="stats-card" style="border-color: {TACTIC_COLORS['detect']}40">
        <span class="stats-number" style="color: {TACTIC_COLORS['detect']}">{len(techniques['detect'])}</span>
        <span class="stats-label">Detect</span>
      </div>
      <div class="stats-card" style="border-color: {TACTIC_COLORS['harden']}40">
        <span class="stats-number" style="color: {TACTIC_COLORS['harden']}">{len(techniques['harden'])}</span>
        <span class="stats-label">Harden</span>
      </div>
      <div class="stats-card" style="border-color: {TACTIC_COLORS['evict']}40">
        <span class="stats-number" style="color: {TACTIC_COLORS['evict']}">{len(techniques['evict'])}</span>
        <span class="stats-label">Evict</span>
      </div>
    </div>
  </div>

  <div class="search-bar">
    <input
      type="text"
      class="search-input"
      placeholder="Filter techniques by name, service, or ID..."
      oninput="filterCards(this.value)"
    />
  </div>

  <div class="matrix-wrapper">
    <div class="matrix-container">
      <div class="matrix">{columns_html}
      </div>
    </div>
  </div>

  <footer class="site-footer">
    <div class="footer-container">
      <p>D3FEND-AWS &mdash; AWS-scoped defensive technique mappings modeled on MITRE D3FEND</p>
      <div>
        <a href="https://github.com/mattgurr/d3fend-aws">GitHub</a>
      </div>
    </div>
  </footer>

  <div class="overlay" id="overlay" onclick="closeDetail()"></div>
  <div class="detail-panel" id="detail">
    <div class="detail-panel__header" id="detail-header"></div>
    <div class="detail-panel__body" id="detail-body"></div>
  </div>

  <script>
    const techniques = {techniques_json};

    function showDetail(id) {{
      const t = techniques[id];
      if (!t) return;

      const ttcBase = "https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/";
      const countersHtml = t.counters.map(c =>
        `<li>
          <a class="detail__counter-id" href="${{ttcBase}}${{c.id}}.html" target="_blank" rel="noopener">${{c.id}}</a>
          <span class="detail__counter-name">${{c.name}}</span>
          <span class="detail__counter-tactic">${{c.tactic}}</span>
        </li>`
      ).join("");

      const servicesHtml = t.aws_services.map(s =>
        `<span class="tag">${{s}}</span>`
      ).join("");

      document.getElementById("detail-header").innerHTML = `
        <button class="detail-panel__close" onclick="closeDetail()">&times;</button>
        <div class="detail__id">${{t.id}}</div>
        <div class="detail__tactic detail__tactic--${{t.tactic}}">${{t.tactic}}</div>
        <div class="detail__name">${{t.name}}</div>
      `;

      document.getElementById("detail-body").innerHTML = `
        <div class="detail__category">${{t.category}}</div>

        <div class="detail__section" style="margin-top: 1rem">
          <div class="detail__section-title">Description</div>
          <div class="detail__description">${{t.description}}</div>
        </div>

        <div class="detail__section">
          <div class="detail__section-title">AWS Services</div>
          <div class="detail__services">${{servicesHtml}}</div>
        </div>

        <div class="detail__section">
          <div class="detail__section-title">Counters (${{t.counters.length}} attack techniques)</div>
          <ul class="detail__counters">${{countersHtml}}</ul>
        </div>

        ${{t.d3fend_ref ? `
        <div class="detail__section">
          <div class="detail__section-title">D3FEND Reference</div>
          <div class="detail__d3fend">${{t.d3fend_ref}}</div>
        </div>` : ""}}
      `;
      document.getElementById("overlay").classList.add("active");
      document.getElementById("detail").classList.add("active");
    }}

    function closeDetail() {{
      document.getElementById("overlay").classList.remove("active");
      document.getElementById("detail").classList.remove("active");
    }}

    document.addEventListener("keydown", e => {{
      if (e.key === "Escape") closeDetail();
    }});

    function filterCards(query) {{
      const q = query.toLowerCase().trim();
      document.querySelectorAll(".card").forEach(card => {{
        if (!q) {{
          card.classList.remove("hidden");
          return;
        }}
        const id = card.dataset.id;
        const t = techniques[id];
        const searchable = [
          t.id, t.name, t.category,
          ...t.aws_services,
          ...t.counters.map(c => c.id + " " + c.name),
        ].join(" ").toLowerCase();
        card.classList.toggle("hidden", !searchable.includes(q));
      }});
    }}
  </script>
</body>
</html>"""


def main():
    techniques = load_techniques()
    attack_lookup = load_attack_catalog()
    page_html = build_html(techniques, attack_lookup)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(page_html)
    print(f"Built {OUT_PATH} ({sum(len(techniques[k]) for k in techniques)} techniques)")


if __name__ == "__main__":
    main()
