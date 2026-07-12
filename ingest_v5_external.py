"""Ingest external datasets into v5 payloads.

Downloads real attack payloads from published academic datasets and converts
them into the v5 payload format used by this dataset.

Sources:
  1. OverThink (HuggingFace: akumar0927/OverThink) - 350 rows x 7 templates
  2. T2VSafetyBench (GitHub: yibo-miao/T2VSafetyBench) - 5,151 prompts
  3. Jailbreak-AudioBench (GitHub: Researchtopic/Code-Jailbreak-AudioBench) - text CSVs
  4. CyberSecEval 3 VPI (HuggingFace: facebook/cyberseceval3-visual-prompt-injection) - 1,000
  5. LLMail-Inject (HuggingFace: microsoft/llmail-inject-challenge) - 208K submissions

Requirements:
  pip install datasets
"""

import json
import csv
import io
import urllib.request
from pathlib import Path
from collections import defaultdict

V5_EXT_DIR = Path(__file__).parent / "payloads_v5_external"
CHUNK_SIZE = 500


def write_category(dirname: str, payloads: list[dict]) -> int:
    cat_dir = V5_EXT_DIR / dirname
    cat_dir.mkdir(parents=True, exist_ok=True)
    for i in range(0, len(payloads), CHUNK_SIZE):
        chunk = payloads[i:i + CHUNK_SIZE]
        fname = f"{dirname}_{(i // CHUNK_SIZE) + 1:03d}.json"
        with open(cat_dir / fname, "w", encoding="utf-8") as f:
            json.dump(chunk, f, indent=2, ensure_ascii=False)
    return len(payloads)


def make_payload(id_prefix, idx, category, text, source, reference,
                 strategy="single_turn", **extra):
    return {
        "id": f"{id_prefix}-{idx:06d}",
        "version": "v5_ext",
        "category": category,
        "text": text,
        "attack_source": source,
        "attack_reference": reference,
        "strategy": strategy,
        "modalities": extra.pop("modalities", ["text"]),
        "expected_detection": True,
        **extra,
    }


# -------------------------------------------------------------------------
# 1. OverThink (HuggingFace)
# -------------------------------------------------------------------------
def ingest_overthink():
    print("Ingesting OverThink...")
    from datasets import load_dataset

    payloads = []
    idx = 0
    splits = ['freshQA_attack', 'squad_attack', 'MuSR_murder_mystery',
              'MuSR_object_placement', 'MuSR_team_allocation']

    for split in splits:
        ds = load_dataset('akumar0927/OverThink', split=split)
        for row in ds:
            for tmpl_num in range(1, 8):
                col = f"Attack_Prompt_{tmpl_num}"
                attack_text = row.get(col)
                if not attack_text or not str(attack_text).strip():
                    continue
                idx += 1
                payloads.append(make_payload(
                    "OT-EXT", idx, "reasoning_dos_overthink",
                    str(attack_text).strip(),
                    f"OverThink (arXiv:2502.02542) split={split} template={tmpl_num}",
                    "arXiv:2502.02542",
                    strategy="mdp_decoy_injection",
                    dataset_split=split,
                    template_number=tmpl_num,
                ))

    n = write_category("overthink", payloads)
    print(f"  OverThink: {n} payloads")
    return n


# -------------------------------------------------------------------------
# 2. T2VSafetyBench (GitHub)
# -------------------------------------------------------------------------
T2V_CATEGORIES = {
    1: "pornography", 2: "borderline_pornography", 3: "violence",
    4: "gore", 5: "disturbing_content", 6: "public_figures",
    7: "discrimination", 8: "political_sensitivity", 9: "copyright_trademark",
    10: "illegal_activities", 11: "misinformation", 12: "sequential_action_risk",
    13: "dynamic_variation_risk", 14: "coherent_contextual_risk",
}

def ingest_t2vsafetybench():
    print("Ingesting T2VSafetyBench...")
    payloads = []
    idx = 0
    base_url = "https://raw.githubusercontent.com/yibo-miao/T2VSafetyBench/main/T2VSafetyBench"

    for cat_num, cat_name in T2V_CATEGORIES.items():
        url = f"{base_url}/{cat_num}.txt"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            data = urllib.request.urlopen(req, timeout=30).read().decode("utf-8")
            lines = [l.strip() for l in data.strip().split("\n") if l.strip()]
            for line in lines:
                idx += 1
                payloads.append(make_payload(
                    "T2V-EXT", idx, "video_generation_jailbreak",
                    line,
                    f"T2VSafetyBench (arXiv:2407.05965) category={cat_num}_{cat_name}",
                    "arXiv:2407.05965",
                    strategy=f"t2v_{cat_name}",
                    modalities=["text", "video"],
                    t2v_category=cat_num,
                    t2v_category_name=cat_name,
                ))
        except Exception as e:
            print(f"  WARNING: Failed to fetch cat {cat_num}: {e}")

    n = write_category("t2vsafetybench", payloads)
    print(f"  T2VSafetyBench: {n} payloads")
    return n


# -------------------------------------------------------------------------
# 3. Jailbreak-AudioBench (GitHub)
# -------------------------------------------------------------------------
AUDIOBENCH_FILES = [
    "Explicit_Advbench.csv",
    "Explicit_MM-Safetybench.csv",
    "Explicit_RedTeam_2K.csv",
    "Explicit_safebench.csv",
    "Implicit_MM-Safetybench.csv",
    "Implicit_RedTeam_2K.csv",
    "Implicit_safebench.csv",
]

def ingest_audiobench():
    print("Ingesting Jailbreak-AudioBench...")
    payloads = []
    idx = 0
    base_url = "https://raw.githubusercontent.com/Researchtopic/Code-Jailbreak-AudioBench/master/Text"

    for fname in AUDIOBENCH_FILES:
        url = f"{base_url}/{fname}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            data = urllib.request.urlopen(req, timeout=30).read().decode("utf-8")
            reader = csv.reader(io.StringIO(data))
            rows = list(reader)
            # First row is header or first data
            source_name = fname.replace(".csv", "")
            is_explicit = fname.startswith("Explicit")
            for row in rows:
                if not row or not row[0].strip():
                    continue
                text = row[0].strip()
                # Skip if it looks like a header
                if text.lower() in ("goal", "query", "question", "prompt", "text"):
                    continue
                idx += 1
                payloads.append(make_payload(
                    "AB-EXT", idx, "audio_native_llm_jailbreak",
                    f"[AUDIO] {text}",
                    f"Jailbreak-AudioBench (arXiv:2501.13772) source={source_name}",
                    "arXiv:2501.13772",
                    strategy="explicit_audio_jailbreak" if is_explicit else "implicit_audio_jailbreak",
                    modalities=["text", "audio"],
                    audiobench_source=source_name,
                ))
        except Exception as e:
            print(f"  WARNING: Failed to fetch {fname}: {e}")

    n = write_category("audiobench", payloads)
    print(f"  Jailbreak-AudioBench: {n} payloads")
    return n


# -------------------------------------------------------------------------
# 4. CyberSecEval 3 VPI (HuggingFace)
# -------------------------------------------------------------------------
def ingest_cyberseceval3():
    print("Ingesting CyberSecEval 3 VPI...")
    from datasets import load_dataset

    ds = load_dataset("facebook/cyberseceval3-visual-prompt-injection", split="test")
    payloads = []

    for idx_0, row in enumerate(ds):
        # Construct the cross-modal payload from system + user + image injection
        parts = []
        if row.get("system_prompt"):
            parts.append(f"[SYSTEM] {row['system_prompt']}")
        if row.get("user_input_text"):
            parts.append(f"[USER] {row['user_input_text']}")
        if row.get("image_text"):
            parts.append(f"[IMAGE INJECTION] {row['image_text']}")

        text = " ".join(parts)
        if not text.strip():
            continue

        techniques = row.get("injection_technique", [])
        if isinstance(techniques, list):
            techniques = ", ".join(techniques)

        payloads.append(make_payload(
            "CSE3-EXT", idx_0 + 1, "cross_modal_decomposition",
            text,
            f"CyberSecEval 3 VPI (Meta) technique={techniques}",
            "https://huggingface.co/datasets/facebook/cyberseceval3-visual-prompt-injection",
            strategy=f"vpi_{row.get('injection_type', 'unknown')}",
            modalities=["text", "image"],
            injection_technique=techniques,
            injection_type=row.get("injection_type", ""),
            risk_category=row.get("risk_category", ""),
        ))

    n = write_category("cyberseceval3_vpi", payloads)
    print(f"  CyberSecEval 3 VPI: {n} payloads")
    return n


# -------------------------------------------------------------------------
# 5. LLMail-Inject (HuggingFace)
# -------------------------------------------------------------------------
def ingest_llmail():
    print("Ingesting LLMail-Inject...")
    from datasets import load_dataset

    payloads = []
    idx = 0
    seen_texts = set()

    for phase in ["Phase1", "Phase2"]:
        print(f"  Loading {phase}...")
        ds = load_dataset("microsoft/llmail-inject-challenge", split=phase)
        for row in ds:
            body = row.get("body", "")
            subject = row.get("subject", "")
            if not body or not str(body).strip():
                continue

            # Deduplicate by body text
            body_stripped = str(body).strip()
            if body_stripped in seen_texts:
                continue
            seen_texts.add(body_stripped)

            # Build the combined text
            text = body_stripped
            if subject and str(subject).strip():
                text = f"Subject: {str(subject).strip()}\n\n{body_stripped}"

            idx += 1
            objectives = row.get("objectives", "")
            scenario = row.get("scenario", "")

            payloads.append(make_payload(
                "LMI-EXT", idx, "rag_optimization_attack",
                text,
                f"LLMail-Inject (arXiv:2506.09956) phase={phase} scenario={scenario}",
                "arXiv:2506.09956",
                strategy="email_injection_competition",
                llmail_scenario=str(scenario),
                llmail_phase=phase,
            ))

    n = write_category("llmail_inject", payloads)
    print(f"  LLMail-Inject: {n} unique payloads")
    return n


# -------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------
def main():
    V5_EXT_DIR.mkdir(parents=True, exist_ok=True)

    totals = {}
    totals["overthink"] = ingest_overthink()
    totals["t2vsafetybench"] = ingest_t2vsafetybench()
    totals["audiobench"] = ingest_audiobench()
    totals["cyberseceval3_vpi"] = ingest_cyberseceval3()
    totals["llmail_inject"] = ingest_llmail()

    grand_total = sum(totals.values())

    summary = {
        "version": "v5_external",
        "generator": "ingest_v5_external.py",
        "total_payloads": grand_total,
        "per_source": totals,
        "sources": {
            "overthink": {
                "name": "OverThink",
                "arxiv": "2502.02542",
                "huggingface": "akumar0927/OverThink",
                "github": "akumar2709/OVERTHINK_public",
                "license": "MIT"
            },
            "t2vsafetybench": {
                "name": "T2VSafetyBench",
                "arxiv": "2407.05965",
                "github": "yibo-miao/T2VSafetyBench",
                "venue": "NeurIPS 2024"
            },
            "audiobench": {
                "name": "Jailbreak-AudioBench",
                "arxiv": "2501.13772",
                "github": "Researchtopic/Code-Jailbreak-AudioBench",
                "venue": "NeurIPS 2025"
            },
            "cyberseceval3_vpi": {
                "name": "CyberSecEval 3 Visual Prompt Injection",
                "huggingface": "facebook/cyberseceval3-visual-prompt-injection",
                "github": "meta-llama/PurpleLlama",
                "source": "Meta"
            },
            "llmail_inject": {
                "name": "LLMail-Inject Challenge",
                "arxiv": "2506.09956",
                "huggingface": "microsoft/llmail-inject-challenge",
                "source": "Microsoft"
            }
        },
        "note": (
            "These payloads are ingested verbatim from published external datasets. "
            "They complement the 184 hand-curated v5 seed payloads in payloads_v5/. "
            "All payloads are labeled expected_detection=True."
        )
    }

    with open(V5_EXT_DIR / "summary_v5_external.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*50}")
    print(f"Total v5 external payloads: {grand_total:,}")
    for src, count in totals.items():
        print(f"  {src}: {count:,}")
    print(f"Summary written to {V5_EXT_DIR / 'summary_v5_external.json'}")


if __name__ == "__main__":
    main()
