"""Present YARA rule counts and byte evidence; analytical calls stay in SQL."""

import matplotlib.pyplot as plt
import pandas as pd
from IPython.display import display
from vgi_notebooks import finish as finish_chart, prose


def finish(fig, title, subtitle, name):
    finish_chart(
        fig,
        title,
        subtitle,
        "Authored inert byte samples · VGI YARA v0.4.0 · No real-system observations",
        name=name,
    )


def plot_audit(audit, require_both):
    fig, ax = plt.subplots(figsize=(12, 7.8))
    for i, r in enumerate(audit.itertuples()):
        if pd.isna(r.matching_rules):
            ax.scatter(0, i, marker="x", s=70, color="#6b7b88")
            label = "Unknown · missing input"
        else:
            ax.barh(
                i,
                r.matching_rules,
                color="#267358" if r.matching_rules > 0 else "#8d9690",
                height=0.55,
            )
            label = f"{int(r.matching_rules)} · {r.result_state}"
        ax.text(
            (0 if pd.isna(r.matching_rules) else r.matching_rules) + 0.07,
            i,
            label,
            va="center",
            fontsize=11,
        )
    ax.set_yticks(range(len(audit)), audit.sample_id)
    ax.invert_yaxis()
    ax.set_xlim(-0.05, max(1, float(audit.matching_rules.max())) + 1.5)
    ax.xaxis.set_major_locator(plt.MaxNLocator(integer=True))
    ax.set_xlabel("Matching rules · Count")
    ax.grid(axis="y", visible=False)
    finish(
        fig,
        "Keep the sample denominator beside the matches",
        f"Text rule requires {'both markers' if require_both else 'either marker'} · Binary rule unchanged",
        "sample-matches",
    )
    matched = int(audit.any_match.eq(True).sum())
    present = int(audit.supplied_bytes.notna().sum())
    prose(
        f"**{matched} of {present} supplied inputs** report at least one matching rule; one missing input remains unknown. "
        "The repeated-marker sample demonstrates that repeating one text pattern does not increase the count of matching rules. A zero is only a no-match report for this ruleset and scan scope."
    )


def plot_spans(hits, detail_hex, rule_count):
    display(hits)
    # Known fixture pattern lengths make spans exact. The worker does not return a
    # general-purpose match-length field, and its rendered text must not be used as one.
    pattern_bytes = {"$orbit": b"ORBIT", "$lander": b"LANDER", "$bin": bytes.fromhex("deadbeef")}
    data = bytes.fromhex(detail_hex)
    fig, ax = plt.subplots(figsize=(12, 6.8))
    for i, r in enumerate(hits.itertuples()):
        # Address the exported offset column by name.
        start = int(hits.iloc[i]["offset"])
        length = len(pattern_bytes[r.identifier])
        assert data[start : start + length] == pattern_bytes[r.identifier]
        color = "#c57b40" if r.identifier == "$bin" else "#267358"
        ax.barh(i, length, left=start, height=0.5, color=color)
        ax.text(
            start + length / 2,
            i,
            f"{start}–{start + length}",
            va="center",
            ha="center",
            color="white",
            fontsize=10,
            weight="bold",
        )
    ax.set_yticks(range(len(hits)), [f"{r.identifier} · {r.matched}" for r in hits.itertuples()])
    ax.invert_yaxis()
    ax.set_xlim(0, len(data))
    ax.set_xticks(sorted({0, len(data), *[int(x) for x in hits["offset"]]}))
    ax.set_xlabel("Byte offset in mixed.bin · Zero-based, end-exclusive spans")
    ax.grid(axis="y", visible=False)
    finish(
        fig,
        "Four occurrences support two matching rules",
        "UTF-8 π takes two bytes · Binary match is rendered as hex",
        "pattern-offsets",
    )
    prose(
        f"The mixed sample has **{rule_count} matching rules and {len(hits)} string occurrences**. "
        f"Its first ORBIT begins at byte **{int(hits['offset'].min())}**, after the two-byte π and a space. "
        "The binary occurrence occupies four bytes although its hex rendering has eight characters. "
        "The chart uses independently checked fixture pattern lengths, not rendered-string length."
    )
