"""Deep Financial, Crypto (`TRC-20` USDT / ENS / BTC Clustering) & Sister-Domain / Mail-Stack OSINT (Upgrade #6).

100% Keyless Passive Collectors using Python 3 stdlib:
  1. Tron (`T...`) & `TRC-20` USDT (`TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`) balance, exchange tags, timestamps & counterparties
  2. Ethereum (`0x...`) & ENS (`*.eth`) forward/reverse Web3 identity + ENS/Farcaster/Lens profile & avatar resolution
  3. Bitcoin (`bc1...`/`1...`/`3...`) common-input-ownership co-spend clustering, counterparties & first/last-seen UTC
  4. Domain `SPF` + `_dmarc` SaaS stack fingerprinter, `SPF ip4:` origin-IP leak detector & `DMARC rua=` parent-org attribution
  5. Certificate Transparency (`crt.sh`) tightly-scoped multi-SAN **Sister-Domain Co-Ownership** attribution
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from .classify import DOMAIN_RE, EMAIL_RE, NOISE_DOMAINS

API_UA = "OSINT-Monster-Hunter/2026.10 (+https://github.com/mafk21/OSINT)"
TRON_USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

SPF_SAAS_SIGNATURES: list[tuple[str, str]] = [
    ("_spf.google.com", "Google Workspace"),
    ("google-site-verification=", "Google Workspace / Search Console"),
    ("spf.protection.outlook.com", "Microsoft 365 / Exchange Online"),
    ("ms=ms", "Microsoft 365 Verified Domain"),
    ("_spf.protonmail.ch", "ProtonMail Custom Domain"),
    ("protonmail-verification=", "ProtonMail Custom Domain"),
    ("zoho.com", "Zoho Mail"),
    ("zohomail.com", "Zoho Mail"),
    ("messagingengine.com", "Fastmail"),
    ("_spf.mx.cloudflare.net", "Cloudflare Email Routing"),
    ("sendgrid.net", "Twilio SendGrid"),
    ("mailgun.org", "Mailgun"),
    ("amazonses.com", "Amazon SES"),
    ("spf.mtasv.net", "Postmark"),
    ("mail.zendesk.com", "Zendesk Support"),
    ("hubspotemail.net", "HubSpot CRM"),
    ("_spf.salesforce.com", "Salesforce"),
    ("servers.mcsv.net", "Mailchimp"),
    ("klaviyo.com", "Klaviyo"),
    ("spf.brevo.com", "Brevo (Sendinblue)"),
    ("atlassian-domain-verification=", "Atlassian Cloud"),
    ("slack-domain-verification=", "Slack Workspace"),
    ("apple-domain-verification=", "Apple Business Manager"),
    ("openai-domain-verification=", "OpenAI Enterprise"),
]

DMARC_THIRD_PARTY_AGGREGATORS: set[str] = {
    "dmarcian.com", "agari.com", "valimail.com", "proofpoint.com", "mimecast.com",
    "easydmarc.us", "easydmarc.com", "uriports.com", "postmarkapp.com", "dmarc.postmarkapp.com",
    "ondmarc.com", "redsift.io", "barracuda.com", "cloudflare.com", "dmarc-reports.cloudflare.com",
    "mxtoolbox.com", "powerdmarc.com", "fraudmarc.com", "sendgrid.net",
}

MULTI_PART_PUBLIC_SUFFIXES: set[str] = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.sa", "org.sa", "gov.sa", "edu.sa", "med.sa", "net.sa",
    "com.au", "net.au", "org.au", "co.jp", "com.br", "com.eg", "com.tr", "co.in", "com.sg", "ae.org",
}


def _res(module: str, status: str, summary: str, data: dict[str, Any], pivots: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {
        "module": module,
        "opsec": "Passive",
        "status": status,
        "summary": summary,
        "data": data,
        "pivots": pivots or [],
    }


def _http_json(url: str, *, headers: dict[str, str] | None = None, timeout: float = 3.8) -> tuple[int, Any, str]:
    hdrs = {"User-Agent": API_UA, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(524_288).decode("utf-8", errors="replace")
            return resp.status, json.loads(raw), ""
    except urllib.error.HTTPError as e:
        return e.code, None, f"HTTP {e.code}"
    except Exception as e:
        return 0, None, str(e)


def extract_registered_root_domain(host: str) -> str:
    """Reduce `sub.api.example.com.sa` -> `example.com.sa` or `app.foo.io` -> `foo.io`."""
    h = (host or "").strip().lower().rstrip(".").removeprefix("*.").removeprefix("www.")
    parts = [p for p in h.split(".") if p]
    if len(parts) <= 2:
        return h
    tail2 = ".".join(parts[-2:])
    if tail2 in MULTI_PART_PUBLIC_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return tail2


# ============================================================================
# 1. TRON (`T...`) & TRC-20 USDT PASSIVE BLOCKCHAIN ATTRIBUTION
# ============================================================================

def collect_tron_trc20_intel(address: str) -> list[dict[str, Any]]:
    """Query keyless Tronscan APIs for TRX, TRC-20 USDT, exchange tags, timestamps & counterparties."""
    addr = address.strip()
    a_enc = urllib.parse.quote(addr)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f_acc = pool.submit(_http_json, f"https://apilist.tronscanapi.com/api/accountv2?address={a_enc}", timeout=4.0)
        f_trc = pool.submit(
            _http_json,
            f"https://apilist.tronscanapi.com/api/transfer/trc20?address={a_enc}&limit=15&start=0&direction=0",
            timeout=4.0,
        )
        st_a, acc_obj, err_a = f_acc.result()
        st_t, trc_obj, _ = f_trc.result()

    if st_a == 0 and st_t == 0:
        return [_res("tron_trc20_usdt_explorer", "restricted_or_offline", f"Tronscan unreachable ({err_a})", {})]
    if st_a != 200 or not isinstance(acc_obj, dict):
        return []

    trx_bal = round((acc_obj.get("balance") or 0) / 1e6, 6)
    tx_total = acc_obj.get("totalTransactionCount") or acc_obj.get("transactions") or 0
    created_ms = acc_obj.get("date_created") or 0
    latest_ms = acc_obj.get("latest_operation_time") or 0
    created_iso = datetime.fromtimestamp(created_ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if created_ms > 1_000_000_000_000 else None
    latest_iso = datetime.fromtimestamp(latest_ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if latest_ms > 1_000_000_000_000 else None
    acc_tag = acc_obj.get("publicTag") or acc_obj.get("accountTag") or acc_obj.get("name") or None

    usdt_balance = 0.0
    trc20_tokens: list[dict[str, Any]] = []
    for tk in (acc_obj.get("withPriceTokens") or acc_obj.get("trc20token_balances") or [])[:12]:
        if not isinstance(tk, dict):
            continue
        sym = str(tk.get("tokenAbbr") or tk.get("symbol") or "").upper()
        tid = str(tk.get("tokenId") or tk.get("contract_address") or "")
        dec = int(tk.get("tokenDecimal") or tk.get("decimals") or 6)
        raw_b = float(tk.get("balance") or 0)
        amt = round(raw_b / (10 ** max(0, min(dec, 18))), 4)
        if amt > 0:
            trc20_tokens.append({"symbol": sym, "amount": amt, "contract": tid})
        if tid == TRON_USDT_CONTRACT or sym == "USDT":
            usdt_balance = max(usdt_balance, amt)

    counterparties: list[str] = []
    seen_cp: set[str] = {addr}
    if st_t == 200 and isinstance(trc_obj, dict):
        for tx in (trc_obj.get("data") or trc_obj.get("token_transfers") or [])[:15]:
            if not isinstance(tx, dict):
                continue
            for k in ("from", "to", "from_address", "to_address"):
                cp = str(tx.get(k) or "").strip()
                if cp.startswith("T") and len(cp) == 34 and cp not in seen_cp:
                    seen_cp.add(cp)
                    counterparties.append(cp)

    tag_str = f" · Tag: '{acc_tag}'" if acc_tag else ""
    return [
        _res(
            "tron_trc20_usdt_explorer",
            "ok",
            f"Tron TRX={trx_bal:,.2f} · TRC-20 USDT={usdt_balance:,.2f} · Txs={tx_total}{tag_str}",
            {
                "address": addr,
                "public_tag": acc_tag,
                "trx_balance": trx_bal,
                "usdt_trc20_balance": usdt_balance,
                "trc20_balances": trc20_tokens,
                "total_transactions": tx_total,
                "created_at": created_iso,
                "pushed_at": latest_iso,
                "recent_trc20_counterparties": counterparties[:8],
            },
        )
    ]


# ============================================================================
# 2. ETHEREUM (`0x...`) & ENS (`*.eth`) / WEB3 IDENTITY RESOLVER
# ============================================================================

def collect_evm_and_ens_intel(addr_or_ens: str) -> list[dict[str, Any]]:
    """Resolve `0x...` <-> `*.eth` ENS + Farcaster/Lens social profiles & avatars via Web3.bio & ENSData."""
    q = addr_or_ens.strip()
    q_enc = urllib.parse.quote(q)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f_ens = pool.submit(_http_json, f"https://api.ensdata.net/{q_enc}", timeout=3.8)
        f_w3b = pool.submit(_http_json, f"https://api.web3.bio/profile/{q_enc}", timeout=3.8)
        st_e, ens_obj, err_e = f_ens.result()
        st_w, w3_arr, _ = f_w3b.result()

    if st_e == 0 and st_w == 0:
        return [_res("ens_and_web3_identity", "restricted_or_offline", f"ENS/Web3 resolvers unreachable ({err_e})", {})]

    out: list[dict[str, Any]] = []
    pivots: list[dict[str, str]] = []
    combined: dict[str, Any] = {"query": q, "profiles": []}

    if st_e == 200 and isinstance(ens_obj, dict) and (ens_obj.get("address") or ens_obj.get("ens")):
        w_addr = ens_obj.get("address")
        ens_name = ens_obj.get("ens") or ens_obj.get("ens_primary")
        combined["resolved_address"] = w_addr
        combined["ens_primary"] = ens_name
        if ens_obj.get("avatar_url") or ens_obj.get("avatar"):
            combined["avatar_url"] = ens_obj.get("avatar_url") or ens_obj.get("avatar")
        if w_addr and w_addr.lower() != q.lower():
            pivots.append({"type": "crypto_address", "value": w_addr})
        if ens_name and ens_name.lower() != q.lower():
            pivots.append({"type": "crypto_address", "value": ens_name})
        for h_key in ("twitter", "github", "telegram", "discord"):
            hv = str(ens_obj.get(h_key) or "").strip().lstrip("@")
            if hv and " " not in hv and len(hv) >= 2:
                combined[h_key] = hv
                if h_key in ("twitter", "github", "telegram"):
                    pivots.append({"type": "username", "value": hv})
        em = str(ens_obj.get("email") or "").strip().lower()
        if EMAIL_RE.fullmatch(em):
            combined["email"] = em
            pivots.append({"type": "email", "value": em})
        url_v = str(ens_obj.get("url") or ens_obj.get("website") or "").strip()
        if url_v.startswith(("http://", "https://")):
            combined["website"] = url_v
            pivots.append({"type": "url", "value": url_v})

    if st_w == 200 and isinstance(w3_arr, list) and w3_arr:
        for item in w3_arr[:8]:
            if not isinstance(item, dict):
                continue
            plat = item.get("platform")
            ident = item.get("identity")
            addr_w = item.get("address")
            av_w = item.get("avatar")
            if av_w and not combined.get("avatar_url"):
                combined["avatar_url"] = av_w
            if addr_w and str(addr_w).startswith("0x") and str(addr_w).lower() != q.lower():
                pivots.append({"type": "crypto_address", "value": str(addr_w)})
            combined["profiles"].append(
                {
                    "platform": plat,
                    "identity": ident,
                    "display_name": item.get("displayName"),
                    "description": item.get("description"),
                    "address": addr_w,
                }
            )
            links_d = item.get("links") or {}
            if isinstance(links_d, dict):
                for lk_name, lk_obj in links_d.items():
                    h_val = (lk_obj.get("handle") if isinstance(lk_obj, dict) else None)
                    if h_val and isinstance(h_val, str) and len(h_val) >= 2 and " " not in h_val:
                        pivots.append({"type": "username", "value": h_val.lstrip("@")})

    if combined.get("resolved_address") or combined.get("ens_primary") or combined["profiles"]:
        ens_lbl = combined.get("ens_primary") or q
        addr_lbl = combined.get("resolved_address") or ""
        out.append(
            _res(
                "ens_and_web3_identity",
                "ok",
                f"Web3 Identity: {ens_lbl}" + (f" -> {addr_lbl}" if addr_lbl else "") + f" ({len(combined['profiles'])} linked Web3 profile(s))",
                combined,
                pivots,
            )
        )
    return out


# ============================================================================
# 3. BITCOIN CO-INPUT OWNERSHIP CLUSTERING & COUNTERPARTY SUMMARY
# ============================================================================

def parse_btc_transactions_cluster(address: str, txs: list[dict[str, Any]]) -> dict[str, Any]:
    """Apply Common-Input-Ownership Heuristic (co-spent inputs) & counterparty analysis on BTC txs."""
    co_input_mates: set[str] = set()
    counterparties: set[str] = set()
    block_times: list[int] = []

    for tx in txs[:25]:
        if not isinstance(tx, dict):
            continue
        bt = ((tx.get("status") or {}).get("block_time"))
        if isinstance(bt, int) and bt > 1_230_000_000:
            block_times.append(bt)

        in_addrs = {
            ((vin.get("prevout") or {}).get("scriptpubkey_address"))
            for vin in (tx.get("vin") or [])
            if isinstance(vin, dict) and ((vin.get("prevout") or {}).get("scriptpubkey_address"))
        }
        out_addrs = {
            vout.get("scriptpubkey_address")
            for vout in (tx.get("vout") or [])
            if isinstance(vout, dict) and vout.get("scriptpubkey_address")
        }

        if address in in_addrs:
            # All other inputs in the same spend transaction are co-signed -> likely same wallet cluster!
            for mate in in_addrs:
                if mate != address:
                    co_input_mates.add(mate)
            for out_a in out_addrs:
                if out_a != address:
                    counterparties.add(out_a)
        elif address in out_addrs:
            for in_a in in_addrs:
                if in_a != address:
                    counterparties.add(in_a)

    first_iso = datetime.fromtimestamp(min(block_times), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if block_times else None
    last_iso = datetime.fromtimestamp(max(block_times), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if block_times else None
    return {
        "sampled_tx_count": len(txs[:25]),
        "created_at": first_iso,
        "pushed_at": last_iso,
        "co_spent_wallet_cluster_mates": sorted(co_input_mates)[:12],
        "recent_counterparties": sorted(counterparties)[:12],
    }


def collect_btc_counterparty_intel(address: str) -> list[dict[str, Any]]:
    st, arr, _ = _http_json(f"https://mempool.space/api/address/{urllib.parse.quote(address)}/txs", timeout=4.0)
    if st != 200 or not isinstance(arr, list) or not arr:
        return []
    parsed = parse_btc_transactions_cluster(address, arr)
    pivots = [{"type": "crypto_address", "value": m} for m in parsed["co_spent_wallet_cluster_mates"][:2]]
    return [
        _res(
            "bitcoin_coinput_cluster_and_counterparties",
            "ok",
            f"BTC Cluster: {len(parsed['co_spent_wallet_cluster_mates'])} co-spent wallet mate(s), {len(parsed['recent_counterparties'])} counterparty address(es)"
            + (f" · Active {parsed['created_at'][:10]}..{parsed['pushed_at'][:10]}" if parsed["created_at"] else ""),
            parsed,
            pivots,
        )
    ]


# ============================================================================
# 4. DOMAIN SPF / DMARC MAIL-STACK FINGERPRINTER & SISTER-DOMAIN SAN PIVOTING
# ============================================================================

def analyze_spf_and_dmarc_records(domain: str, root_txt: list[str], dmarc_txt: list[str]) -> dict[str, Any]:
    """Decode SPF `ip4:` origin leaks, SaaS stack vendors & DMARC `rua=`/`ruf=` parent-org emails."""
    d_root = extract_registered_root_domain(domain)
    saas_stack: set[str] = set()
    spf_origin_ips: set[str] = set()
    spf_included_domains: set[str] = set()
    dmarc_policy: str | None = None
    dmarc_reporting_emails: list[str] = []
    pivots: list[dict[str, str]] = []

    all_txt = [t.strip('" ') for t in root_txt + dmarc_txt if isinstance(t, str)]
    for txt in all_txt:
        low = txt.lower()
        for needle, vendor in SPF_SAAS_SIGNATURES:
            if needle in low:
                saas_stack.add(vendor)

        if "v=spf1" in low:
            # Extract explicit ip4: addresses (classic origin-server IP leak behind Cloudflare!)
            for m_ip in re.findall(r"\bip4:(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?\b", low):
                ip_s, prefix_s = m_ip[0], m_ip[1]
                # Only pivot single hosts or /31-/32 (avoid pivoting a massive /16 ESP netblock!)
                if not prefix_s or int(prefix_s) >= 30:
                    try:
                        ip_obj = ipaddress.ip_address(ip_s)
                        if ip_obj.is_global:
                            spf_origin_ips.add(ip_s)
                            pivots.append({"type": "ip", "value": ip_s})
                    except ValueError:
                        pass
            for inc in re.findall(r"\b(?:include|redirect)[:=]([a-z0-9._-]+)\b", low):
                spf_included_domains.add(inc)

        if "v=dmarc1" in low:
            pm = re.search(r"\bp\s*=\s*([a-zA-Z]+)", low)
            if pm:
                dmarc_policy = pm.group(1).lower()
            for mailto in re.findall(r"mailto:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24})", txt, re.I):
                em_clean = mailto.lower()
                if em_clean not in dmarc_reporting_emails:
                    dmarc_reporting_emails.append(em_clean)
                em_dom = em_clean.split("@", 1)[1]
                em_root = extract_registered_root_domain(em_dom)
                if em_root not in DMARC_THIRD_PARTY_AGGREGATORS and em_dom not in DMARC_THIRD_PARTY_AGGREGATORS:
                    pivots.append({"type": "email", "value": em_clean})
                    if em_root and em_root != d_root and em_root not in NOISE_DOMAINS:
                        pivots.append({"type": "domain", "value": em_root})

    return {
        "saas_and_mail_providers": sorted(saas_stack),
        "spf_explicit_origin_ips": sorted(spf_origin_ips),
        "spf_includes": sorted(spf_included_domains)[:15],
        "dmarc_policy": dmarc_policy,
        "dmarc_reporting_emails": dmarc_reporting_emails,
        "pivots": pivots,
    }


def extract_coowned_sister_domains_from_ct(domain: str, crt_rows: list[dict[str, Any]]) -> list[str]:
    """Identify co-owned sister root domains sharing tightly-scoped multi-SAN TLS certificates (2..15 roots)."""
    target_root = extract_registered_root_domain(domain)
    sister_counts: dict[str, int] = {}

    for row in crt_rows[:120]:
        if not isinstance(row, dict):
            continue
        nv = str(row.get("name_value") or "")
        if "\n" not in nv:
            continue
        roots_in_cert: set[str] = set()
        for raw_h in nv.splitlines():
            h = raw_h.strip().lower().removeprefix("*.")
            if DOMAIN_RE.fullmatch(h):
                rt = extract_registered_root_domain(h)
                if rt and rt not in NOISE_DOMAINS:
                    roots_in_cert.add(rt)
        # Tightly-scoped multi-domain cert (2..15 root domains) -> operator co-ownership signal!
        if target_root in roots_in_cert and 2 <= len(roots_in_cert) <= 15:
            for rt in roots_in_cert:
                if rt != target_root:
                    sister_counts[rt] = sister_counts.get(rt, 0) + 1

    ranked = sorted(sister_counts.keys(), key=lambda k: (-sister_counts[k], k))
    return ranked[:12]


def collect_domain_mail_stack_and_sister_domains(domain: str) -> list[dict[str, Any]]:
    """Passive DoH SPF/DMARC SaaS + Origin-IP un-masking + CT SAN sister-domain attribution."""
    d = domain.strip().lower().removeprefix("www.")
    if d.endswith(".onion"):
        return []

    doh_hdr = {"Accept": "application/dns-json"}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        f_txt = pool.submit(_http_json, f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(d)}&type=TXT", headers=doh_hdr, timeout=3.5)
        f_dm = pool.submit(_http_json, f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote('_dmarc.' + d)}&type=TXT", headers=doh_hdr, timeout=3.5)
        f_ct = pool.submit(_http_json, f"https://crt.sh/?q={urllib.parse.quote(d)}&output=json", timeout=4.2)
        st_t, obj_t, _ = f_txt.result()
        st_d, obj_d, _ = f_dm.result()
        st_c, arr_c, _ = f_ct.result()

    out: list[dict[str, Any]] = []
    if st_t == 200 or st_d == 200:
        root_txts = [a.get("data", "") for a in ((obj_t or {}).get("Answer") or []) if isinstance(a, dict)] if isinstance(obj_t, dict) else []
        dm_txts = [a.get("data", "") for a in ((obj_d or {}).get("Answer") or []) if isinstance(a, dict)] if isinstance(obj_d, dict) else []
        mail_info = analyze_spf_and_dmarc_records(d, root_txts, dm_txts)
        pivs_m = mail_info.pop("pivots", [])
        if mail_info["saas_and_mail_providers"] or mail_info["spf_explicit_origin_ips"] or mail_info["dmarc_policy"]:
            parts = []
            if mail_info["saas_and_mail_providers"]:
                parts.append(f"Stack: {', '.join(mail_info['saas_and_mail_providers'][:5])}")
            if mail_info["dmarc_policy"]:
                parts.append(f"DMARC={mail_info['dmarc_policy']}")
            if mail_info["spf_explicit_origin_ips"]:
                parts.append(f"SPF Origin IP(s)={', '.join(mail_info['spf_explicit_origin_ips'][:3])}")
            out.append(_res("spf_dmarc_saas_and_origin_intel", "ok", " · ".join(parts), mail_info, pivs_m))

    if st_c == 200 and isinstance(arr_c, list) and arr_c:
        sisters = extract_coowned_sister_domains_from_ct(d, arr_c)
        if sisters:
            out.append(
                _res(
                    "ct_san_sister_domains",
                    "ok",
                    f"Discovered {len(sisters)} co-owned sister domain(s) sharing multi-SAN TLS cert(s): {', '.join(sisters[:5])}",
                    {"sister_domains": sisters},
                    [{"type": "domain", "value": s} for s in sisters[:6]],
                )
            )

    return out
