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
    "detect": "#3b82f6",
    "harden": "#22c55e",
    "evict": "#ef4444",
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
    # Sort each tactic by ID
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
    # Build counters reverse index: attack_id -> list of defensive technique IDs
    attack_to_defenses = {}
    for tactic_key in techniques:
        for t in techniques[tactic_key]:
            for counter_id in t.get("counters", []):
                attack_to_defenses.setdefault(counter_id, []).append(t["id"])

    # Build technique detail JSON for modal
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

    # Build tactic columns HTML
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
        <div class="tactic-header" style="border-top: 3px solid {color}">
          <h2 class="tactic-title">{esc(tactic_name)}</h2>
          <p class="tactic-desc">{esc(tactic_desc)}</p>
          <span class="tactic-count">{len(cards)} techniques</span>
        </div>
        <div class="tactic-cards">{cards_html}
        </div>
      </div>"""

    techniques_json = json.dumps(all_techniques)

    # Stats
    total = sum(len(techniques[k]) for k in techniques)
    total_attacks = len(attack_lookup)
    covered = len(attack_to_defenses)

    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>D3FEND-AWS Matrix</title>
  <meta name="description" content="AWS-scoped defensive technique mappings modeled on MITRE D3FEND" />
  <style>
    *, *::before, *::after {{ margin: 0; padding: 0; box-sizing: border-box; }}

    :root {{
      --bg: #0a0a0a;
      --surface: #141414;
      --surface-2: #1a1a1a;
      --border: #222;
      --border-hover: #444;
      --text: #e0e0e0;
      --text-muted: #888;
      --text-dim: #666;
      --detect: #3b82f6;
      --harden: #22c55e;
      --evict: #ef4444;
    }}

    body {{
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      -webkit-font-smoothing: antialiased;
      line-height: 1.5;
    }}

    /* Header */
    .header {{
      padding: 2rem 2rem 1.5rem;
      border-bottom: 1px solid var(--border);
    }}
    .header__inner {{
      max-width: 1600px;
      margin: 0 auto;
    }}
    .header h1 {{
      font-size: 1.5rem;
      font-weight: 600;
      letter-spacing: -0.02em;
      margin-bottom: 0.25rem;
    }}
    .header p {{
      color: var(--text-muted);
      font-size: 0.875rem;
    }}
    .header__stats {{
      display: flex;
      gap: 1.5rem;
      margin-top: 1rem;
    }}
    .stat {{
      display: flex;
      flex-direction: column;
      gap: 0.125rem;
    }}
    .stat__value {{
      font-size: 1.25rem;
      font-weight: 600;
    }}
    .stat__label {{
      font-size: 0.75rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}

    /* Search */
    .search-bar {{
      padding: 1rem 2rem;
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      background: var(--bg);
      z-index: 10;
    }}
    .search-bar__inner {{
      max-width: 1600px;
      margin: 0 auto;
    }}
    .search-input {{
      width: 100%;
      max-width: 400px;
      padding: 0.5rem 0.75rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-size: 0.875rem;
      outline: none;
      transition: border-color 0.2s;
    }}
    .search-input:focus {{
      border-color: var(--border-hover);
    }}
    .search-input::placeholder {{
      color: var(--text-dim);
    }}

    /* Matrix layout */
    .matrix {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 1px;
      background: var(--border);
      max-width: 1600px;
      margin: 0 auto;
    }}

    /* Tactic column */
    .tactic-column {{
      background: var(--bg);
      min-width: 0;
    }}
    .tactic-header {{
      padding: 1.25rem 1rem;
      background: var(--surface);
      position: sticky;
      top: 49px;
      z-index: 5;
    }}
    .tactic-title {{
      font-size: 1.1rem;
      font-weight: 600;
      margin-bottom: 0.25rem;
    }}
    .tactic-desc {{
      font-size: 0.75rem;
      color: var(--text-muted);
      margin-bottom: 0.5rem;
    }}
    .tactic-count {{
      font-size: 0.7rem;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .tactic-cards {{
      padding: 0.5rem;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }}

    /* Cards */
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.875rem;
      cursor: pointer;
      transition: border-color 0.2s, transform 0.15s;
    }}
    .card:hover {{
      border-color: var(--border-hover);
      transform: translateY(-1px);
    }}
    .card.hidden {{
      display: none;
    }}
    .card__id {{
      font-size: 0.7rem;
      font-family: "SF Mono", "Fira Code", "Fira Mono", Menlo, monospace;
      color: var(--text-dim);
      margin-bottom: 0.25rem;
    }}
    .card__name {{
      font-size: 0.85rem;
      font-weight: 500;
      margin-bottom: 0.25rem;
    }}
    .card__category {{
      font-size: 0.7rem;
      color: var(--text-muted);
      margin-bottom: 0.5rem;
    }}
    .card__services {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.25rem;
      margin-bottom: 0.5rem;
    }}
    .tag {{
      display: inline-block;
      font-size: 0.65rem;
      padding: 0.125rem 0.375rem;
      border-radius: 4px;
      background: var(--surface-2);
      border: 1px solid var(--border);
      color: var(--text-muted);
      white-space: nowrap;
    }}
    .card__counter-count {{
      font-size: 0.65rem;
      color: var(--text-dim);
    }}

    /* Modal / detail panel */
    .overlay {{
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.6);
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
      width: 520px;
      max-width: 100vw;
      background: var(--surface);
      border-left: 1px solid var(--border);
      z-index: 101;
      overflow-y: auto;
      padding: 2rem;
      box-shadow: -8px 0 32px rgba(0, 0, 0, 0.4);
    }}
    .detail-panel.active {{
      display: block;
    }}
    .detail-panel__close {{
      position: absolute;
      top: 1rem;
      right: 1rem;
      background: none;
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text-muted);
      font-size: 1.25rem;
      cursor: pointer;
      width: 32px;
      height: 32px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: border-color 0.2s;
    }}
    .detail-panel__close:hover {{
      border-color: var(--border-hover);
      color: var(--text);
    }}
    .detail__id {{
      font-family: "SF Mono", "Fira Code", monospace;
      font-size: 0.8rem;
      color: var(--text-dim);
      margin-bottom: 0.25rem;
    }}
    .detail__tactic {{
      display: inline-block;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      margin-bottom: 0.75rem;
    }}
    .detail__tactic--detect {{ background: rgba(59, 130, 246, 0.15); color: var(--detect); }}
    .detail__tactic--harden {{ background: rgba(34, 197, 94, 0.15); color: var(--harden); }}
    .detail__tactic--evict {{ background: rgba(239, 68, 68, 0.15); color: var(--evict); }}
    .detail__name {{
      font-size: 1.25rem;
      font-weight: 600;
      margin-bottom: 0.5rem;
    }}
    .detail__category {{
      font-size: 0.85rem;
      color: var(--text-muted);
      margin-bottom: 1rem;
    }}
    .detail__section {{
      margin-bottom: 1.25rem;
    }}
    .detail__section-title {{
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-dim);
      margin-bottom: 0.5rem;
    }}
    .detail__description {{
      font-size: 0.85rem;
      line-height: 1.6;
      color: var(--text);
    }}
    .detail__services {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.375rem;
    }}
    .detail__services .tag {{
      font-size: 0.75rem;
      padding: 0.2rem 0.5rem;
    }}
    .detail__counters {{
      list-style: none;
    }}
    .detail__counters li {{
      padding: 0.375rem 0;
      border-bottom: 1px solid var(--border);
      font-size: 0.8rem;
    }}
    .detail__counters li:last-child {{
      border-bottom: none;
    }}
    .detail__counter-id {{
      font-family: "SF Mono", "Fira Code", monospace;
      color: var(--text-muted);
      font-size: 0.75rem;
    }}
    .detail__counter-name {{
      color: var(--text);
    }}
    .detail__counter-tactic {{
      font-size: 0.65rem;
      color: var(--text-dim);
    }}
    .detail__d3fend {{
      font-family: "SF Mono", "Fira Code", monospace;
      font-size: 0.8rem;
      color: var(--text-muted);
    }}

    /* Responsive */
    @media (max-width: 900px) {{
      .matrix {{
        grid-template-columns: 1fr;
      }}
      .tactic-header {{
        position: static;
      }}
      .detail-panel {{
        width: 100vw;
      }}
    }}
    @media (max-width: 600px) {{
      .header {{
        padding: 1.5rem 1rem 1rem;
      }}
      .search-bar {{
        padding: 0.75rem 1rem;
      }}
      .header__stats {{
        flex-wrap: wrap;
        gap: 1rem;
      }}
    }}
  </style>
</head>
<body>

  <div class="header">
    <div class="header__inner">
      <h1>D3FEND-AWS Matrix</h1>
      <p>AWS-native defensive techniques mapped to the AWS Threat Technique Catalog</p>
      <div class="header__stats">
        <div class="stat">
          <span class="stat__value">{total}</span>
          <span class="stat__label">Defensive Techniques</span>
        </div>
        <div class="stat">
          <span class="stat__value">{covered}/{total_attacks}</span>
          <span class="stat__label">Attack Techniques Covered</span>
        </div>
        <div class="stat">
          <span class="stat__value">{len(techniques['detect'])}</span>
          <span class="stat__label" style="color: var(--detect)">Detect</span>
        </div>
        <div class="stat">
          <span class="stat__value">{len(techniques['harden'])}</span>
          <span class="stat__label" style="color: var(--harden)">Harden</span>
        </div>
        <div class="stat">
          <span class="stat__value">{len(techniques['evict'])}</span>
          <span class="stat__label" style="color: var(--evict)">Evict</span>
        </div>
      </div>
    </div>
  </div>

  <div class="search-bar">
    <div class="search-bar__inner">
      <input
        type="text"
        class="search-input"
        placeholder="Filter techniques... (name, service, ID)"
        oninput="filterCards(this.value)"
      />
    </div>
  </div>

  <div class="matrix">{columns_html}
  </div>

  <div class="overlay" id="overlay" onclick="closeDetail()"></div>
  <div class="detail-panel" id="detail">
    <button class="detail-panel__close" onclick="closeDetail()">&times;</button>
    <div id="detail-content"></div>
  </div>

  <script>
    const techniques = {techniques_json};

    function showDetail(id) {{
      const t = techniques[id];
      if (!t) return;

      const countersHtml = t.counters.map(c =>
        `<li>
          <span class="detail__counter-id">${{c.id}}</span>
          <span class="detail__counter-name">${{c.name}}</span>
          <span class="detail__counter-tactic">${{c.tactic}}</span>
        </li>`
      ).join("");

      const servicesHtml = t.aws_services.map(s =>
        `<span class="tag">${{s}}</span>`
      ).join("");

      document.getElementById("detail-content").innerHTML = `
        <div class="detail__id">${{t.id}}</div>
        <div class="detail__tactic detail__tactic--${{t.tactic}}">${{t.tactic}}</div>
        <div class="detail__name">${{t.name}}</div>
        <div class="detail__category">${{t.category}}</div>

        <div class="detail__section">
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
