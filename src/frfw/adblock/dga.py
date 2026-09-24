""""Does this domain look machine-generated?" -- a cheap, stdlib-only
heuristic for spotting domain generation algorithm (DGA) traffic.

Malware that uses a DGA derives hundreds of pseudo-random domain names
per day from a seed, and its operator registers only a few of them; the
infected host tries them in turn, so it produces a burst of lookups for
random-looking names that mostly come back NXDOMAIN. This module only
answers the per-name half ("is this label random-looking?"); the "burst
of such NXDOMAINs from one host" half is frfw.ai_ids.engine's job, and
only the combination ever leads to a verdict.

Which label is scored: the *registered* one (just left of the public
suffix), not the longest. A DGA has to register the random part, while
CDNs and cloud services randomize *subdomains* of an ordinary registered
name (`d1a2b3c4d5.cloudfront.net`). Never scored: single-label names
(Chromium sends random 7-15 letter single-label probes at startup to
detect DNS hijacking, and those NXDOMAIN by design) and punycode IDN
labels (`xn--...`, random-looking by construction).

No Public Suffix List is bundled (a data file this project would have to
keep current); a few common second-level public suffixes (`co.uk`,
`com.au`, ...) cover the usual cases, and getting one wrong only means
scoring a neighbouring label, not a verdict by itself.

The rule -- at least 10 characters, character entropy of at least 3.0
bits, and fewer than 40% of its letter pairs among frequent English
bigrams -- was picked against real data to keep false positives low
rather than catch everything; ARCHITECTURE.md's phase 15 section has the
measured rates. Known blind spot: dictionary DGAs (concatenated real
words) look like ordinary names and are not caught.
"""

from __future__ import annotations

import math
import re
from collections import Counter

#: Second-level labels that are part of a public suffix in many ccTLDs.
_SLD_PUBLIC = frozenset(
    {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "nic", "ltd", "plc"}
)

#: Frequent English letter pairs -- real words and brand names are full of
#: them, a pseudo-random string mostly isn't.
_COMMON_BIGRAMS = frozenset(
    """th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le
    ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no
    ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo
    ow pa im mi ai sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa ay
    ex ke fr oo av ag if ap gr od bo sp rd do uc bu ei ov by rm ep tt oc fa ef cu rn sc gi da yo cr
    cl du ga qu ue ff ba ey ls va um pp ua up lu go ht ru ug ds lt pi rc rr eg au ck ew mu br bi pt
    ak pu ui rg ib tl ny ki rk ys ob mm fu ph og ms ye ud mb ip ub oi rl gu dr hr cc tw ft wn nu af
    hu nn eo vo rv nf xp gn sm fl iz ok nl my gl aw ju oa eq sy sl ps jo""".split()
)

MIN_LENGTH = 10
MIN_ENTROPY = 3.0
MAX_COMMON_BIGRAM_RATIO = 0.40

_LABEL_RE = re.compile(r"^[a-z0-9-]+$")


def registered_label(name: str) -> str | None:
    """The label a registrant chose, e.g. `example` for
    `www.example.co.uk`; None for single-label or malformed names."""
    labels = name.lower().rstrip(".").split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return None
    labels = labels[:-1]  # drop the TLD
    if len(labels) >= 2 and labels[-1] in _SLD_PUBLIC:
        labels = labels[:-1]
    label = labels[-1]
    return label if _LABEL_RE.match(label) else None


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def common_bigram_ratio(text: str) -> float:
    pairs = [text[i:i + 2] for i in range(len(text) - 1) if text[i:i + 2].isalpha()]
    if not pairs:
        return 0.0
    return sum(1 for p in pairs if p in _COMMON_BIGRAMS) / len(pairs)


def looks_generated(name: str) -> bool:
    label = registered_label(name)
    if label is None or label.startswith("xn--"):
        return False
    compact = label.replace("-", "")
    return (
        len(compact) >= MIN_LENGTH
        and shannon_entropy(compact) >= MIN_ENTROPY
        and common_bigram_ratio(compact) < MAX_COMMON_BIGRAM_RATIO
    )
