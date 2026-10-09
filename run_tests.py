"""Run ScamSense on test_cases.json and report how well it does.

Usage:
    python run_tests.py             # AI + rule-based checks (needs your API key)
    python run_tests.py --no-ai     # rule-based checks only (instant, no key needed)
    python run_tests.py --age       # also look up domain age (slower)

Results are saved to test_results.json so you can quote the numbers in your README.
"""

import json
import os
import re
import sys
import time

from dotenv import load_dotenv

from checks import run_checks
from prompts import SYSTEM_PROMPT

load_dotenv()

MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
LEVELS = ["Safe", "Suspicious", "Dangerous"]
USE_AI = "--no-ai" not in sys.argv
CHECK_AGE = "--age" in sys.argv
PAUSE_SECONDS = 5  # keeps you under the free-tier rate limit


def level_from_score(score: int) -> str:
    return "Safe" if score < 35 else "Suspicious" if score < 70 else "Dangerous"


def parse_json(raw: str) -> dict:
    raw = re.sub(r"^```(?:json)?|```$", "", (raw or "").strip(), flags=re.I | re.M).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return json.loads(re.search(r"\{.*\}", raw, re.S).group(0))


def ask_ai(client, types, text: str) -> dict:
    for attempt in range(4):
        try:
            response = client.models.generate_content(
                model=MODEL,
                contents=[f"<content>\n{text}\n</content>"],
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT.replace("{language}", "English"),
                    response_mime_type="application/json",
                    temperature=0.2,
                ),
            )
            return parse_json(response.text)
        except Exception as e:
            msg = str(e)
            if attempt < 3 and ("429" in msg or "503" in msg or "RESOURCE_EXHAUSTED" in msg):
                wait = 30 if "429" in msg or "RESOURCE_EXHAUSTED" in msg else 10
                print(f"    busy, waiting {wait}s and retrying...")
                time.sleep(wait)
                continue
            raise


def combine(ai, heur):
    """Same blending rule as app.py: rules can raise the score, never lower it."""
    if ai is None:
        score = heur["score"]
        return score, level_from_score(score)
    score = max(0, min(100, int(float(ai.get("risk_score", 50)))))
    if heur["has_findings"]:
        score = max(score, round(0.6 * score + 0.4 * heur["score"]))
    ai_level = ai.get("risk_level") if ai.get("risk_level") in LEVELS else level_from_score(score)
    return score, max(level_from_score(score), ai_level, key=LEVELS.index)


def main():
    cases = json.load(open("test_cases.json", encoding="utf-8"))

    client = types = None
    if USE_AI:
        from google import genai
        from google.genai import types as genai_types

        key = os.getenv("GEMINI_API_KEY")
        if not key:
            sys.exit("GEMINI_API_KEY not found. Check your .env file, or run with --no-ai.")
        client, types = genai.Client(api_key=key), genai_types

    print(f"Mode: {'AI + rules' if USE_AI else 'rules only'}"
          f"{' (model ' + MODEL + ')' if USE_AI else ''}\n")
    print(f"{'#':>2}  {'Category':<26} {'Expected':<11} {'Got':<11} {'AI':>3} {'Rules':>5} {'Final':>5}  Result")
    print("-" * 82)

    results = []
    for case in cases:
        heur = run_checks(case["text"], check_age=CHECK_AGE)
        ai, error = None, None
        if USE_AI:
            try:
                ai = ask_ai(client, types, case["text"])
            except Exception as e:
                error = f"{type(e).__name__}: {str(e)[:80]}"
            time.sleep(PAUSE_SECONDS)

        score, level = combine(ai, heur)
        scam = case["expected"] != "Safe"
        flagged = level != "Safe"
        exact = level == case["expected"]
        ok = flagged if scam else not flagged  # a miss is a scam marked Safe, or a real message flagged
        results.append({**case, "got": level, "final_score": score, "rule_score": heur["score"],
                        "ai_score": ai.get("risk_score") if ai else None,
                        "ai_summary": ai.get("summary") if ai else None,
                        "correct": ok, "exact": exact, "error": error})
        mark = "ok" if ok else ("MISSED SCAM" if scam else "FALSE ALARM")
        ai_score = "-" if not ai else ai.get("risk_score", "?")
        print(f"{case['id']:>2}  {case['category']:<26} {case['expected']:<11} {level:<11} "
              f"{ai_score!s:>3} {heur['score']:>5} {score:>5}  {mark}{'  [' + error + ']' if error else ''}")

    scams = [r for r in results if r["expected"] != "Safe"]
    legit = [r for r in results if r["expected"] == "Safe"]
    caught = sum(r["correct"] for r in scams)
    false_alarms = sum(not r["correct"] for r in legit)
    exact = sum(r["exact"] for r in results)

    print("\n" + "=" * 82)
    print(f"Scams caught:        {caught}/{len(scams)}")
    print(f"False alarms:        {false_alarms}/{len(legit)}  (genuine messages wrongly flagged)")
    print(f"Exact level match:   {exact}/{len(results)}")
    print("=" * 82)

    json.dump({"mode": "ai+rules" if USE_AI else "rules-only", "model": MODEL if USE_AI else None,
               "scams_caught": caught, "scams_total": len(scams),
               "false_alarms": false_alarms, "legit_total": len(legit),
               "exact_matches": exact, "results": results},
              open("test_results.json", "w", encoding="utf-8"), indent=2)
    print("Saved to test_results.json")


if __name__ == "__main__":
    main()
