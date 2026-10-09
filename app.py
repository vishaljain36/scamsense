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

st.set_page_config(page_title="ScamSense", page_icon="🛡️", layout="centered")

st.markdown(
    """
    <style>
    .ss-banner { padding: 1.1rem 1.3rem; border-radius: 12px; margin: .5rem 0 1rem 0; }
    .ss-title { font-size: 1.7rem; font-weight: 700; color: #fff; margin-bottom: .25rem; }
    .ss-sub { font-size: 1.02rem; color: #fff; }
    .ss-Safe { background: #1b7f46; }
    .ss-Suspicious { background: #b45f06; }
    .ss-Dangerous { background: #c0262d; }
    mark { background: #ffd54f; color: #111; padding: 0 .15rem; border-radius: 3px; }
    </style>
    """,
    unsafe_allow_html=True,
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
def highlight(text: str, evidence: list[str]) -> str:
    out = html.escape(text)
    for ev in sorted({e.strip() for e in evidence if len(e.strip()) >= 3}, key=len, reverse=True):
        out = re.sub(re.escape(html.escape(ev)), lambda m: f"<mark>{m.group(0)}</mark>", out, flags=re.I)
    return out.replace("\n", "<br>")


def show_result(res: dict):
    ai, heur = res["ai"], res["heur"]
    level, score = res["level"], res["score"]

    if res["ai_error"]:
        st.warning(f"{res['ai_error']} Showing the rule-based link and wording checks only.")

    summary = ai["summary"] if ai else "Result based on link and wording checks only."
    st.markdown(
        f"""<div class="ss-banner ss-{level}">
        <div class="ss-title">{level}</div>
        <div class="ss-sub">{html.escape(summary)}</div></div>""",
        unsafe_allow_html=True,
    )
    st.progress(score / 100, text=f"Risk score: {score} / 100")

    if ai:
        st.markdown(
            f"**Scam type:** {ai['scam_type']}  \n**AI confidence:** {ai['confidence']}"
        )

    # Message with suspicious parts marked
    if ai and res["text"].strip():
        evidence = [str(f.get("evidence", "")) for f in ai["red_flags"]]
        with st.expander("Your message, with suspicious parts marked"):
            st.markdown(highlight(res["text"], evidence), unsafe_allow_html=True)

    # Red flags
    if ai and ai["red_flags"]:
        st.subheader("Red flags")
        for f in ai["red_flags"]:
            st.markdown(f"**{f.get('flag', 'Warning sign')}**")
            if f.get("evidence"):
                st.markdown(f"> {f['evidence']}")
            if f.get("why_it_matters"):
                st.caption(f["why_it_matters"])

    # Rule-based checks
    if heur["has_findings"] or heur["urls"]:
        st.subheader("Link and wording checks")
        for u in heur["urls"]:
            age = f" · registered {u['age_days']} days ago" if u["age_days"] is not None else ""
            st.markdown(f"`{u['url']}`{age}")
            if u["findings"]:
                for finding in u["findings"]:
                    st.markdown(f"- {finding}")
            else:
                st.markdown("- No warning signs found in this link")
        for hit in heur["text_hits"]:
            st.markdown(f"- {hit}")

    if ai and ai["safe_signals"]:
        with st.expander("Reassuring signs"):
            for s in ai["safe_signals"]:
                st.markdown(f"- {s}")

    # What to do
    steps = ai["what_to_do"] if ai else [
        "Do not click links, call numbers or reply.",
        "Contact the organisation using its official website or the number on your card or bill.",
        "Never share OTPs, PINs or passwords with anyone.",
    ]
    st.subheader("What to do now")
    for i, step in enumerate(steps):
        st.checkbox(step, key=f"todo_{i}")

    if ai and ai["report_to"]:
        st.markdown("**Report it:** " + "; ".join(ai["report_to"]))

    # Family warning
    st.divider()
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

    st.caption(
        "ScamSense is a decision aid, not a guarantee. When in doubt, contact the organisation "
        "directly using details from its official website."
    )


# --------------------------------------------------------------------------- #
# Page
# --------------------------------------------------------------------------- #
def load_example(name: str):
    st.session_state["msg"] = EXAMPLES[name]


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


with st.sidebar:
    st.header("Settings")
    language = st.selectbox("Explain in", LANGUAGES)
    check_age = st.checkbox("Check how old a website is", value=True, help="Slower, needs internet. New websites are riskier.")
    st.divider()
    st.caption(
        "Your messages are not stored by ScamSense. They are sent to the Gemini API for analysis, "
        "so never paste real passwords or OTPs."
    )

st.title("🛡️ ScamSense")
st.write("Got a strange SMS, email or link? Paste it or upload a screenshot and find out if it's a scam.")

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

if st.button("Check it", type="primary"):
    if not text.strip() and image is None:
        st.warning("Paste a message or upload a screenshot first.")
    else:
        with st.spinner("Checking..."):
            analyze(text, image, language, check_age)

if st.session_state.get("result"):
    show_result(st.session_state["result"])
