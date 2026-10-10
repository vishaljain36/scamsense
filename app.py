"""ScamSense: paste a suspicious message, email, link or screenshot and get a verdict.

How it works
  1. Rule-based checks (checks.py) inspect links and wording instantly.
  2. Gemini reads the text and/or screenshot and returns a structured JSON verdict.
  3. The two are blended: rules can raise the risk score but never lower it.
  If the AI is unavailable, the app still returns a result from the rule-based checks.
"""

import html
import json
import os
import re

import streamlit as st
from dotenv import load_dotenv
from google import genai
from google.genai import types
from PIL import Image

from checks import run_checks
from prompts import EXAMPLES, FAMILY_PROMPT, LANGUAGES, SYSTEM_PROMPT

load_dotenv()

# Change the model without touching code: set GEMINI_MODEL in .env or Streamlit secrets.
MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
LEVELS = ["Safe", "Suspicious", "Dangerous"]

st.set_page_config(page_title="ScamSense", page_icon="🛡️", layout="centered",
                   initial_sidebar_state="collapsed")

# --------------------------------------------------------------------------- #
# Look and feel
# --------------------------------------------------------------------------- #
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700&family=DM+Sans:wght@400;500;700&display=swap');

:root { --ink:#121A24; --slate:#5A6675; --rule:#DCE2EA; --teal:#0B5C63; }

.stApp, .stApp p, .stApp li, .stApp label, .stApp textarea, .stApp input,
.stApp button, .stApp [data-baseweb="select"] {
    font-family: 'DM Sans', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif !important;
}
[data-testid="stMainBlockContainer"], .block-container { max-width: 760px; padding-top: 2.2rem; padding-bottom: 4rem; }
#MainMenu, footer, [data-testid="stDecoration"] { visibility: hidden; }

/* Header */
.ss-hero { display: flex; align-items: center; gap: .9rem; margin-bottom: .2rem; }
.ss-mark { width: 46px; height: 46px; flex: none; }
.ss-word, .ss-h, .ss-level, .ss-ring-num {
    font-family: 'Bricolage Grotesque', 'DM Sans', system-ui, sans-serif; font-weight: 700; color: var(--ink);
}
.ss-word { font-size: 2.1rem; letter-spacing: -.02em; line-height: 1.05; }
.ss-tag { color: var(--slate); font-size: 1.02rem; margin-top: .2rem; }
.ss-lead { color: var(--slate); margin: .6rem 0 1.2rem 0; }

/* Primary button */
[data-testid="stColumn"] [data-testid="stButton"] { width: 100%; }
[data-testid="stBaseButton-primary"] { width: 100%; font-weight: 600; border-radius: 10px; min-height: 2.6rem; }

/* Verdict card: the one memorable element */
.ss-v-Safe      { --c:#17703E; --tint:#E8F4EC; --bd:#BFE0CB; }
.ss-v-Suspicious{ --c:#A65500; --tint:#FCF0DF; --bd:#EFD2A6; }
.ss-v-Dangerous { --c:#C0262D; --tint:#FBE9EA; --bd:#F1BFC2; }
.ss-verdict { display: flex; align-items: center; gap: 1.5rem; flex-wrap: wrap; padding: 1.3rem 1.5rem;
    border-radius: 16px; border: 1px solid var(--bd); background: var(--tint); margin: 1.2rem 0 .4rem 0; }
.ss-ring { width: 124px; height: 124px; flex: none; }
.ss-ring-bg { fill: none; stroke: rgba(18,26,36,.10); stroke-width: 10; }
.ss-ring-fg { fill: none; stroke: var(--c); stroke-width: 10; stroke-linecap: round; }
.ss-ring-num { font-size: 36px; fill: var(--ink); }
.ss-ring-of { font-size: 10px; fill: var(--slate); }
.ss-verdict-body { flex: 1; min-width: 220px; }
.ss-level { font-size: 2.2rem; color: var(--c); line-height: 1.05; letter-spacing: -.01em; }
.ss-summary { font-size: 1.05rem; color: var(--ink); margin: .4rem 0 .5rem 0; }
.ss-meta { font-size: .9rem; color: var(--slate); }

/* Sections */
.ss-h { font-size: 1.3rem; margin: 1.8rem 0 .6rem 0; letter-spacing: -.01em; }
.ss-flag { background: #fff; border: 1px solid var(--rule); border-left: 4px solid var(--c);
    border-radius: 10px; padding: .8rem 1rem; margin-bottom: .6rem; }
.ss-flag-title { font-weight: 700; color: var(--ink); }
.ss-flag-quote { margin: .4rem 0; padding: .4rem .7rem; background: #F4F6F9; border-radius: 6px; color: var(--ink); font-size: .95rem; }
.ss-flag-why { font-size: .9rem; color: var(--slate); }
.ss-link { background: #fff; border: 1px solid var(--rule); border-radius: 10px; padding: .8rem 1rem; margin-bottom: .6rem; }
.ss-url { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .88rem; word-break: break-all; color: var(--ink); }
.ss-age { color: var(--slate); font-size: .85rem; display: block; margin-top: .2rem; }
.ss-chips { display: flex; flex-wrap: wrap; gap: .4rem; margin-top: .6rem; }
.ss-chip { font-size: .83rem; padding: .22rem .65rem; border-radius: 999px; background: #FCF0DF; color: #7A3F00; border: 1px solid #EFD2A6; }
.ss-chip-ok { background: #E8F4EC; color: #14602F; border-color: #BFE0CB; }
.ss-msg { background: #fff; border: 1px solid var(--rule); border-radius: 10px; padding: .8rem 1rem; line-height: 1.6; }
mark { background: #FFD54F; color: #111; padding: 0 .15rem; border-radius: 3px; }
.ss-note { color: var(--slate); font-size: .85rem; margin-top: 1.2rem; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

SHIELD = (
    '<svg class="ss-mark" viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">'
    '<path d="M24 3 L42 9.5 V22 C42 33.5 34.5 41.5 24 45 C13.5 41.5 6 33.5 6 22 V9.5 Z" fill="#0B5C63"/>'
    '<path d="M15.5 23.5 L21.5 29.5 L33 17" fill="none" stroke="#fff" stroke-width="4.2" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)


def ring_html(score: int) -> str:
    circumference = 2 * 3.14159265 * 50
    filled = circumference * score / 100
    return (
        '<svg class="ss-ring" viewBox="0 0 120 120" xmlns="http://www.w3.org/2000/svg" role="img" '
        f'aria-label="Risk score {score} out of 100">'
        '<circle class="ss-ring-bg" cx="60" cy="60" r="50"/>'
        f'<circle class="ss-ring-fg" cx="60" cy="60" r="50" stroke-dasharray="{filled:.1f} {circumference:.1f}" '
        'transform="rotate(-90 60 60)"/>'
        f'<text class="ss-ring-num" x="60" y="56" text-anchor="middle" dominant-baseline="central">{score}</text>'
        '<text class="ss-ring-of" x="60" y="80" text-anchor="middle">out of 100</text></svg>'
    )


# --------------------------------------------------------------------------- #
# Gemini helpers
# --------------------------------------------------------------------------- #
def get_api_key():
    key = os.getenv("GEMINI_API_KEY")
    if key:
        return key
    try:
        return st.secrets["GEMINI_API_KEY"]
    except Exception:
        return None


@st.cache_resource
def get_client(key: str):
    return genai.Client(api_key=key)


def _client():
    key = get_api_key()
    if not key:
        raise RuntimeError("Gemini API key is missing")
    return get_client(key)


def parse_json(raw: str) -> dict:
    """Parse the model's reply, tolerating stray markdown fences or extra text."""
    raw = (raw or "").strip()
    raw = re.sub(r"^```(?:json)?|```$", "", raw, flags=re.I | re.M).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw, re.S)
        if match:
            return json.loads(match.group(0))
        raise


def ask_gemini(text: str, image, language: str) -> dict:
    parts = [f"<content>\n{text.strip() or 'The content is in the attached screenshot.'}\n</content>"]
    if image is not None:
        parts.append(image)
    response = _client().models.generate_content(
        model=MODEL,
        contents=parts,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT.replace("{language}", language),
            response_mime_type="application/json",
            temperature=0.2,
        ),
    )
    return parse_json(response.text)


def ask_family_warning(scam_type: str, language: str) -> str:
    prompt = FAMILY_PROMPT.replace("{scam_type}", scam_type).replace("{language}", language)
    response = _client().models.generate_content(model=MODEL, contents=prompt)
    return (response.text or "").strip()


def friendly_error(e: Exception) -> str:
    msg, low = str(e), str(e).lower()
    if "api key" in low or "api_key" in low or "401" in msg or "403" in msg or "permission" in low:
        return "The Gemini API key is missing or invalid. Check your .env file or Streamlit secrets."
    if "429" in msg or "resource_exhausted" in low or "quota" in low:
        return "Gemini's rate limit was reached. Wait about a minute and try again."
    if "404" in msg or "not_found" in low:
        return f"Model '{MODEL}' was not found. Set GEMINI_MODEL to a current model name from AI Studio."
    if "503" in msg or "unavailable" in low or "overloaded" in low:
        return "The AI service is busy right now. Try again in a moment."
    return f"AI analysis failed ({type(e).__name__})."


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
def level_from_score(score: int) -> str:
    return "Safe" if score < 35 else "Suspicious" if score < 70 else "Dangerous"


def normalize(ai: dict) -> dict:
    """Fill in defaults so the UI never breaks on a malformed reply."""
    try:
        score = max(0, min(100, int(float(ai.get("risk_score", 50)))))
    except (TypeError, ValueError):
        score = 50
    level = ai.get("risk_level") if ai.get("risk_level") in LEVELS else level_from_score(score)
    return {
        "risk_level": level,
        "risk_score": score,
        "scam_type": ai.get("scam_type") or "Unknown",
        "summary": ai.get("summary") or "",
        "red_flags": [f for f in ai.get("red_flags", []) if isinstance(f, dict)],
        "safe_signals": [str(s) for s in ai.get("safe_signals", []) if s],
        "what_to_do": [str(s) for s in ai.get("what_to_do", []) if s]
        or ["Do not click links or reply.", "Contact the organisation using its official website or number."],
        "report_to": [str(s) for s in ai.get("report_to", []) if s],
        "confidence": ai.get("confidence") or "Medium",
    }


def combine(ai, heur: dict):
    """Blend AI and rule-based scores. Rules can raise the score, never lower it."""
    if ai is None:
        score = heur["score"]
        return score, level_from_score(score)
    score = ai["risk_score"]
    if heur["has_findings"]:
        score = max(score, round(0.6 * score + 0.4 * heur["score"]))
    level = max(level_from_score(score), ai["risk_level"], key=LEVELS.index)
    return score, level


# --------------------------------------------------------------------------- #
# Display helpers
# --------------------------------------------------------------------------- #
def esc(value) -> str:
    return html.escape(str(value))


def highlight(text: str, evidence: list[str]) -> str:
    out = html.escape(text)
    for ev in sorted({e.strip() for e in evidence if len(e.strip()) >= 3}, key=len, reverse=True):
        out = re.sub(re.escape(html.escape(ev)), lambda m: f"<mark>{m.group(0)}</mark>", out, flags=re.I)
    return out.replace("\n", "<br>")


def heading(text: str):
    st.markdown(f'<div class="ss-h">{esc(text)}</div>', unsafe_allow_html=True)


def show_result(res: dict):
    ai, heur = res["ai"], res["heur"]
    level, score = res["level"], res["score"]

    if res["ai_error"]:
        st.warning(f"{res['ai_error']} Showing the rule-based link and wording checks only.")

    # Verdict
    summary = ai["summary"] if ai else "Result based on link and wording checks only."
    meta = f"Scam type: {esc(ai['scam_type'])} &nbsp;·&nbsp; AI confidence: {esc(ai['confidence'])}" if ai else ""
    st.markdown(
        f'<div class="ss-verdict ss-v-{level}">{ring_html(score)}'
        f'<div class="ss-verdict-body"><div class="ss-level">{level}</div>'
        f'<div class="ss-summary">{esc(summary)}</div><div class="ss-meta">{meta}</div></div></div>',
        unsafe_allow_html=True,
    )

    # What to do now comes first: it is the most useful part for a worried person
    steps = ai["what_to_do"] if ai else [
        "Do not click links, call numbers or reply.",
        "Contact the organisation using its official website or the number on your card or bill.",
        "Never share OTPs, PINs or passwords with anyone.",
    ]
    heading("What to do now")
    for i, step in enumerate(steps):
        st.checkbox(step, key=f"todo_{i}")
    if ai and ai["report_to"]:
        st.caption("Report it: " + "; ".join(ai["report_to"]))

    # Red flags with exact evidence
    if ai and ai["red_flags"]:
        heading("Red flags")
        cards = []
        for f in ai["red_flags"]:
            quote = f'<div class="ss-flag-quote">&ldquo;{esc(f["evidence"])}&rdquo;</div>' if f.get("evidence") else ""
            why = f'<div class="ss-flag-why">{esc(f["why_it_matters"])}</div>' if f.get("why_it_matters") else ""
            cards.append(
                f'<div class="ss-flag ss-v-{level}"><div class="ss-flag-title">{esc(f.get("flag", "Warning sign"))}</div>'
                f"{quote}{why}</div>"
            )
        st.markdown("".join(cards), unsafe_allow_html=True)

    # Rule-based checks
    if heur["has_findings"] or heur["urls"]:
        heading("Link and wording checks")
        cards = []
        for u in heur["urls"]:
            age = f'<span class="ss-age">Website registered {u["age_days"]} days ago</span>' if u["age_days"] is not None else ""
            if u["findings"]:
                chips = "".join(f'<span class="ss-chip">{esc(x)}</span>' for x in u["findings"])
            else:
                chips = '<span class="ss-chip ss-chip-ok">No warning signs found in this link</span>'
            cards.append(f'<div class="ss-link"><div class="ss-url">{esc(u["url"])}</div>{age}<div class="ss-chips">{chips}</div></div>')
        if heur["text_hits"]:
            chips = "".join(f'<span class="ss-chip">{esc(x)}</span>' for x in heur["text_hits"])
            cards.append(f'<div class="ss-link"><div class="ss-flag-title">Wording in the message</div><div class="ss-chips">{chips}</div></div>')
        st.markdown("".join(cards), unsafe_allow_html=True)

    if ai and ai["safe_signals"]:
        with st.expander("Reassuring signs"):
            for s in ai["safe_signals"]:
                st.markdown(f"- {s}")

    # Message with suspicious parts marked
    evidence = [str(f.get("evidence", "")) for f in ai["red_flags"]] if ai else []
    if any(e.strip() for e in evidence) and res["text"].strip():
        with st.expander("Your message, with suspicious parts marked"):
            st.markdown(f'<div class="ss-msg">{highlight(res["text"], evidence)}</div>', unsafe_allow_html=True)

    # Family warning (only useful when the message is a scam)
    if level != "Safe":
        heading("Protect the people around you")
        if st.button("Write a warning for my family"):
            try:
                with st.spinner("Writing..."):
                    st.session_state["family"] = ask_family_warning(
                        ai["scam_type"] if ai else "online scam", res["language"]
                    )
            except Exception as e:
                st.session_state["family"] = None
                st.error(friendly_error(e))
        if st.session_state.get("family"):
            st.caption("Copy this and send it to family or friends:")
            st.code(st.session_state["family"], language=None)

    st.markdown(
        '<div class="ss-note">ScamSense is a decision aid, not a guarantee. When in doubt, contact the '
        "organisation directly using details from its official website.</div>",
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------- #
# Page
# --------------------------------------------------------------------------- #
def load_example(name: str):
    st.session_state["msg"] = EXAMPLES[name]


def pick_example():
    name = st.session_state.get("ex_pick")
    if name:
        load_example(name)
        st.session_state["ex_pick"] = None  # lets the same example be picked again


def analyze(text: str, image, language: str, check_age: bool):
    for k in [k for k in st.session_state if k.startswith("todo_")]:
        del st.session_state[k]
    st.session_state["family"] = None

    heur = run_checks(text, check_age) if text.strip() else {
        "score": 0, "urls": [], "text_hits": [], "has_findings": False,
    }
    ai, ai_error = None, None
    try:
        ai = normalize(ask_gemini(text, image, language))
    except Exception as e:
        ai_error = friendly_error(e)

    score, level = combine(ai, heur)
    st.session_state["result"] = {
        "ai": ai, "ai_error": ai_error, "heur": heur, "score": score,
        "level": level, "text": text, "language": language,
    }


st.markdown(
    f'<div class="ss-hero">{SHIELD}<div><div class="ss-word">ScamSense</div>'
    '<div class="ss-tag">Check a suspicious message before you click, reply or pay.</div></div></div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="ss-lead">Paste a text, email or link, or upload a screenshot. You get a clear verdict, '
    "the evidence behind it, and what to do next.</div>",
    unsafe_allow_html=True,
)

# Example messages
if hasattr(st, "pills"):
    st.pills("Try an example", list(EXAMPLES), key="ex_pick", on_change=pick_example)
else:  # older Streamlit versions
    st.caption("Try an example:")
    cols = st.columns(len(EXAMPLES))
    for col, name in zip(cols, EXAMPLES):
        col.button(name, key=f"ex_{name}", on_click=load_example, args=(name,))

text = st.text_area("Message, email text or link", key="msg", height=150,
                    placeholder="Paste the suspicious message here...")
upload = st.file_uploader("Or upload a screenshot", type=["png", "jpg", "jpeg", "webp"])

image = None
if upload is not None:
    image = Image.open(upload).convert("RGB")
    image.thumbnail((1600, 1600))
    st.image(image, caption="Screenshot to analyze", width=320)

col_lang, col_go = st.columns([3, 2])
language = col_lang.selectbox("Language", LANGUAGES, label_visibility="collapsed",
                              format_func=lambda lang: f"Explain in {lang}")
try:
    go = col_go.button("Check it", type="primary", width="stretch")
except TypeError:  # older Streamlit versions
    go = col_go.button("Check it", type="primary", use_container_width=True)

with st.expander("Options and privacy"):
    check_age = st.checkbox("Check how old a website is", value=True, key="check_age",
                            help="Slower and needs internet. Newly registered websites are riskier.")
    st.caption(
        "ScamSense does not store your messages. They are sent to the Gemini API for analysis, "
        "so never paste real passwords or OTPs."
    )

if go:
    if not text.strip() and image is None:
        st.warning("Paste a message or upload a screenshot first.")
    else:
        with st.spinner("Checking..."):
            analyze(text, image, language, check_age)

if st.session_state.get("result"):
    show_result(st.session_state["result"])
