"""Industry Link-Analysis & Knowledge-Graph Exporters (Gephi GEXF, GraphML, Neo4j Cypher, Obsidian).

100% pure Python stdlib with strict XML / Cypher / filename escaping so generated
artifacts open directly in Gephi, yEd, Cytoscape, Neo4j, and Obsidian without errors.
"""

from __future__ import annotations

import re
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

TYPE_RGB: dict[str, tuple[int, int, int]] = {
    "username": (56, 189, 248),
    "person_name": (244, 114, 182),
    "email": (167, 139, 250),
    "phone": (52, 211, 153),
    "domain": (251, 191, 36),
    "ip": (248, 113, 113),
    "company": (96, 165, 250),
    "crypto_address": (250, 204, 21),
    "url": (148, 163, 184),
    "coordinates": (16, 185, 129),
}


def render_gexf(report: dict) -> str:
    """Render Gephi GEXF 1.3 XML with stage, selector_type, confidence weights, and RGB colors."""
    meta = report.get("meta", {})
    nodes = report.get("graph", {}).get("nodes", [])
    edges = report.get("graph", {}).get("edges", [])

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<gexf xmlns="http://gexf.net/1.3" xmlns:viz="http://gexf.net/1.3/viz" version="1.3">',
        f'  <meta lastmodifieddate="{escape(str(meta.get("timestamp_utc", ""))[:10])}">',
        '    <creator>OSINT Monster Autonomous Hunter</creator>',
        f'    <description>{escape(str(meta.get("case_id", "")))} — {escape(str(meta.get("raw_input", "")))}</description>',
        '  </meta>',
        '  <graph mode="static" defaultedgetype="directed">',
        '    <attributes class="node">',
        '      <attribute id="0" title="selector_type" type="string"/>',
        '      <attribute id="1" title="stage" type="integer"/>',
        '      <attribute id="2" title="value" type="string"/>',
        '    </attributes>',
        '    <attributes class="edge">',
        '      <attribute id="0" title="via" type="string"/>',
        '      <attribute id="1" title="evidence_tier" type="string"/>',
        '    </attributes>',
        '    <nodes>',
    ]
    for n in nodes:
        nid = str(n["id"])
        ntype = str(n.get("type", "entity"))
        nval = str(n.get("value", nid))
        wave = int(n.get("wave", 1))
        r, g, b = TYPE_RGB.get(ntype, (148, 163, 184))
        lines.extend(
            [
                f'      <node id={quoteattr(nid)} label={quoteattr(f"[{ntype}] {nval}")}>',
                f'        <viz:color r="{r}" g="{g}" b="{b}" a="1.0"/>',
                f'        <viz:size value="{22.0 if wave == 1 else 14.0}"/>',
                '        <attvalues>',
                f'          <attvalue for="0" value={quoteattr(ntype)}/>',
                f'          <attvalue for="1" value="{wave}"/>',
                f'          <attvalue for="2" value={quoteattr(nval)}/>',
                '        </attvalues>',
                '      </node>',
            ]
        )
    lines.extend(['    </nodes>', '    <edges>'])
    for idx, e in enumerate(edges):
        conf = float(e.get("confidence", 0.8))
        via = str(e.get("via", "pivot"))
        tier = str(e.get("evidence_tier", "CORRELATED_LEAD"))
        lines.extend(
            [
                f'      <edge id="{idx}" source={quoteattr(str(e["source"]))} target={quoteattr(str(e["target"]))} weight="{conf:.2f}" label={quoteattr(via)}>',
                '        <attvalues>',
                f'          <attvalue for="0" value={quoteattr(via)}/>',
                f'          <attvalue for="1" value={quoteattr(tier)}/>',
                '        </attvalues>',
                '      </edge>',
            ]
        )
    lines.extend(['    </edges>', '  </graph>', '</gexf>', ''])
    return "\n".join(lines)


def render_graphml(report: dict) -> str:
    """Render standard GraphML 1.0 XML compatible with yEd, Cytoscape, Gephi, and NetworkX."""
    nodes = report.get("graph", {}).get("nodes", [])
    edges = report.get("graph", {}).get("edges", [])

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
        '  <key id="d0" for="node" attr.name="label" attr.type="string"/>',
        '  <key id="d1" for="node" attr.name="selector_type" attr.type="string"/>',
        '  <key id="d2" for="node" attr.name="stage" attr.type="int"/>',
        '  <key id="d3" for="node" attr.name="value" attr.type="string"/>',
        '  <key id="e0" for="edge" attr.name="via" attr.type="string"/>',
        '  <key id="e1" for="edge" attr.name="confidence" attr.type="double"/>',
        '  <graph id="OSINTGraph" edgedefault="directed">',
    ]
    for n in nodes:
        nid = str(n["id"])
        ntype = str(n.get("type", "entity"))
        nval = str(n.get("value", nid))
        wave = int(n.get("wave", 1))
        lines.extend(
            [
                f'    <node id={quoteattr(nid)}>',
                f'      <data key="d0">{escape(f"[{ntype}] {nval}")}</data>',
                f'      <data key="d1">{escape(ntype)}</data>',
                f'      <data key="d2">{wave}</data>',
                f'      <data key="d3">{escape(nval)}</data>',
                '    </node>',
            ]
        )
    for idx, e in enumerate(edges):
        conf = float(e.get("confidence", 0.8))
        via = str(e.get("via", "pivot"))
        lines.extend(
            [
                f'    <edge id="e{idx}" source={quoteattr(str(e["source"]))} target={quoteattr(str(e["target"]))}>',
                f'      <data key="e0">{escape(via)}</data>',
                f'      <data key="e1">{conf:.2f}</data>',
                '    </edge>',
            ]
        )
    lines.extend(['  </graph>', '</graphml>', ''])
    return "\n".join(lines)


def _cypher_str(val: str) -> str:
    escaped = str(val).replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ")
    return f"'{escaped}'"


def render_neo4j_cypher(report: dict) -> str:
    """Render idempotent Neo4j Cypher MERGE statements for instant graph DB import."""
    case_id = str(report.get("meta", {}).get("case_id", "CASE"))
    nodes = report.get("graph", {}).get("nodes", [])
    edges = report.get("graph", {}).get("edges", [])

    lines = [
        f"// OSINT Monster Neo4j Cypher Import — {case_id}",
        "CREATE CONSTRAINT osint_entity_id IF NOT EXISTS FOR (e:OSINTEntity) REQUIRE e.id IS UNIQUE;",
        f"MERGE (c:OSINTCase {{case_id: {_cypher_str(case_id)}}}) SET c.raw_input = {_cypher_str(report.get('meta', {}).get('raw_input', ''))}, c.timestamp_utc = {_cypher_str(report.get('meta', {}).get('timestamp_utc', ''))};",
        "",
    ]
    for n in nodes:
        nid = str(n["id"])
        ntype = str(n.get("type", "entity"))
        nval = str(n.get("value", ""))
        wave = int(n.get("wave", 1))
        label_extra = re.sub(r"[^A-Za-z0-9_]", "_", ntype.title())
        lines.append(
            f"MERGE (n:OSINTEntity:{label_extra} {{id: {_cypher_str(nid)}}}) "
            f"SET n.type = {_cypher_str(ntype)}, n.value = {_cypher_str(nval)}, n.stage = {wave};"
        )
        lines.append(
            f"MATCH (c:OSINTCase {{case_id: {_cypher_str(case_id)}}}), (n:OSINTEntity {{id: {_cypher_str(nid)}}}) MERGE (c)-[:OBSERVED {{stage: {wave}}}]->(n);"
        )

    lines.append("")
    for e in edges:
        s = str(e["source"])
        t = str(e["target"])
        via = str(e.get("via", "pivot"))
        conf = float(e.get("confidence", 0.8))
        lines.append(
            f"MATCH (a:OSINTEntity {{id: {_cypher_str(s)}}}), (b:OSINTEntity {{id: {_cypher_str(t)}}}) "
            f"MERGE (a)-[r:PIVOTED_TO {{via: {_cypher_str(via)}}}]->(b) SET r.confidence = {conf:.2f}, r.case_id = {_cypher_str(case_id)};"
        )
    lines.append("")
    return "\n".join(lines)


def _obsidian_note_name(node_id: str) -> str:
    safe = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", node_id).strip(". ")
    return safe[:95] or "entity"


def write_obsidian_vault(case_dir: Path, report: dict) -> int:
    """Write interlinked Markdown notes (`[[Entity]]`) into `cases/<CASE_ID>/obsidian/`."""
    vault_dir = case_dir / "obsidian"
    vault_dir.mkdir(parents=True, exist_ok=True)

    meta = report.get("meta", {})
    syn = report.get("intelligence_synthesis") or {}
    nodes = report.get("graph", {}).get("nodes", [])
    edges = report.get("graph", {}).get("edges", [])

    note_map = {n["id"]: _obsidian_note_name(n["id"]) for n in nodes}
    outbound: dict[str, list[dict]] = {}
    inbound: dict[str, list[dict]] = {}
    for e in edges:
        outbound.setdefault(e["source"], []).append(e)
        inbound.setdefault(e["target"], []).append(e)

    # Collect collector summaries per entity
    summaries_by_id: dict[str, list[str]] = {}
    for w in report.get("wave_results", []):
        nid = f"{w.get('type')}:{w.get('value')}"
        for col in w.get("collector_outputs", []):
            if col.get("status") == "ok":
                summaries_by_id.setdefault(nid, []).append(f"- `{col.get('module')}`: {col.get('summary')}")

    idx_lines = [
        "---",
        f"case_id: {meta.get('case_id')}",
        f"timestamp_utc: {meta.get('timestamp_utc')}",
        f"exposure_score: {syn.get('exposure_score', 0)}",
        "tags: [osint-case, index]",
        "---",
        f"# 🛰️ {meta.get('case_id')} — Obsidian Investigation Graph",
        "",
        f"- **Target**: `{meta.get('raw_input')}`",
        f"- **Exposure Score**: **{syn.get('exposure_score', 0)}/100 ({syn.get('exposure_rating', 'MINIMAL')})**",
        f"- **Entities**: `{len(nodes)}` · **Edges**: `{len(edges)}`",
        "",
        "## Discovered Entities",
    ]
    for n in nodes:
        idx_lines.append(f"- [[{note_map[n['id']]}]] (`Stage {n.get('wave', 1)}` · `{n.get('type')}`)")
    (vault_dir / "00_Case_Index.md").write_text("\n".join(idx_lines) + "\n", encoding="utf-8")

    written = 1
    for n in nodes[:150]:
        nid = n["id"]
        nname = note_map[nid]
        e_lines = [
            "---",
            f"entity_id: \"{nid}\"",
            f"selector_type: {n.get('type')}",
            f"stage: {n.get('wave', 1)}",
            f"tags: [osint-entity, {n.get('type')}]",
            "---",
            f"# `{n.get('type')}`: {n.get('value')}",
            "",
            "Back to [[00_Case_Index]]",
            "",
        ]
        if inbound.get(nid):
            e_lines.append("## Discovered From (Inbound Pivots)")
            for ie in inbound[nid]:
                src_note = note_map.get(ie["source"], _obsidian_note_name(ie["source"]))
                conf_pct = int(round(float(ie.get("confidence", 0.8)) * 100))
                e_lines.append(f"- [[{src_note}]] via `{ie.get('via')}` (**{conf_pct}%** confidence)")
            e_lines.append("")
        if outbound.get(nid):
            e_lines.append("## Pivoted To (Outbound Leads)")
            for oe in outbound[nid]:
                dst_note = note_map.get(oe["target"], _obsidian_note_name(oe["target"]))
                conf_pct = int(round(float(oe.get("confidence", 0.8)) * 100))
                e_lines.append(f"- [[{dst_note}]] via `{oe.get('via')}` (**{conf_pct}%** confidence)")
            e_lines.append("")
        if summaries_by_id.get(nid):
            e_lines.append("## Collector Findings")
            e_lines.extend(summaries_by_id[nid])
            e_lines.append("")
        (vault_dir / f"{nname}.md").write_text("\n".join(e_lines), encoding="utf-8")
        written += 1

    return written
