# ScamSense: Submission Kit

Fill every `__` and `YOUR-...` placeholder before you submit.

---

## 1. Project description (paste into the submission for)

**Title:** ScamSense: Your pocket scam checker

**Track:** Digital Safety & Cybersecurity

**One-line pitch:** Paste a suspicious message or upload a screenshot and ScamSense tells you in seconds whether it's a scam, shows the evidence, and explains what to do next, in your own language.

**Problem**
Scams arrive as ordinary texts, emails and chat messages, and they look more convincing every year. The US Federal Trade Commission reported $15.9 billion in consumer fraud losses in 2025, up from over $12 billion the year before. Most people have no fast, trustworthy way to check a message before they click, reply or pay, and the people most at risk (older adults, first-time digital payment users, non-English speakers) are the least served by expert security tools.

**Solution**
ScamSense accepts pasted text, links or screenshots and returns a Safe / Suspicious / Dangerous verdict with a 0-100 risk score. Every red flag is backed by an exact quote from the message, suspicious phrases are highlighted, and a checklist explains what to do next and where to report it. Explanations are available in nine languages, and one tap generates a ready-to-send warning for family and friends, so one person's near-miss protects others.

**How it works**
A hybrid approach combines two layers. Rule-based checks instantly analyse links (look-alike domains, shortened URLs, unusual endings, hidden `@` tricks, raw IP addresses, website age) and scam wording (fake urgency, OTP/PIN requests, unusual fees). Google's Gemini API, using vision for screenshots, reads the content and returns a structured JSON verdict with evidence. The two scores are blended, and rules can raise the score but never lower it. If the AI is unavailable, the app still returns a result from the rules. Message content is treated strictly as data to defend against prompt injection, and the prompt explicitly protects genuine OTP alerts, order updates and appointment reminders from false alarms.

**Who it helps**
Anyone who receives messages they're unsure about, especially older adults, people new to digital payments, and speakers of languages other than English.

**Results**
Tested on 20 labelled messages (14 different scam types, 6 genuine but alarming-looking messages): caught __ of 14 scams with __ of 6 false alarms. The test suite is included in the repo and reproducible.

**Tech stack**
Python, Streamlit, Google Gemini API (google-genai), Pillow, tldextract, python-whois, Streamlit Community Cloud.

**Limitations**
ScamSense is a decision aid, not a guarantee. It doesn't store messages, but content is sent to the Gemini API for analysis. The AI can err on very short messages, and website-age lookups can time out.

**Future scope**
Browser extension and WhatsApp/SMS integration, link reputation lookups, voice-note analysis, anonymous community reporting to spot new scam waves, region-specific reporting links.

**Links**
- Live demo: https://scamsenseai.streamlit.app/
- GitHub: https://github.com/vishaljain36/scamsense
- Demo video: YOUR-VIDEO-LINK

---

## 2. Short version (if the form has a character limit)

ScamSense checks suspicious messages, links and screenshots. It combines rule-based link and wording analysis with Gemini AI to give a Safe/Suspicious/Dangerous verdict, evidence-backed red flags, next steps and a family warning message, in nine languages. Live demo and open-source code included.

---

## 3. Demo video script (target 2:30, max 3:00)

Record in one take per section. Keep your mouse movements slow.

| Time | Screen | What you say |
|---|---|---|
| 0:00-0:20 | Title slide or the app home page | "In 2025, people in the US alone reported losing $15.9 billion to fraud, according to the FTC. Most scams start with a simple message. And most people have nowhere quick to check one. I built ScamSense to fix that." |
| 0:20-0:50 | Click **Fake bank KYC**, press **Check it** | "Here's a classic fake bank message. ScamSense returns a Dangerous verdict in seconds. Look at the highlighted phrases: the fake deadline, the threat to close the account. Each red flag is tied to an exact quote, so you can see why." |
| 0:50-1:10 | Scroll to **Link and wording checks** | "It also inspects the link itself, without sending you there: an unusual domain ending, hyphen-stuffed name, a brand name that isn't the real site. These rules run instantly, alongside the AI." |
| 1:10-1:30 | Upload a scam screenshot | "Most scams arrive as screenshots forwarded in family chats. ScamSense reads the image directly." |
| 1:30-1:50 | Switch language to Hindi, press **Check it** | "Scam victims are often more comfortable in their own language, so the explanation is available in nine languages." |
| 1:50-2:05 | Click **Real OTP alert**, press **Check it** | "A good detector must not cry wolf. This is a genuine OTP message, and ScamSense correctly marks it Safe." |
| 2:05-2:20 | Click **Write a warning for my family** | "One tap writes a short warning you can forward to family, so one person's close call protects others." |
| 2:20-2:40 | Show README test table or the terminal result | "I tested it on 20 messages: caught __ of 14 scam types with __ false alarms out of 6 genuine messages. It's a hybrid design: rules plus AI, so it keeps working even if the AI is unavailable." |
| 2:40-3:00 | Back to the home page with the live URL visible | "ScamSense is live now, free to try, and the code is on GitHub. Next: a browser extension and WhatsApp integration, so you get a warning at the moment a scam arrives. Thank you." |

**Before you record**
- Set the app to a clean state (refresh the page).
- Use a scam screenshot you made yourself or one with all personal details blanked out.
- Close other tabs and turn on Do Not Disturb.
- Record at 1080p with a quiet room, and read the script once out loud first.
- Don't wait for results on screen: if the AI takes a few seconds, keep talking.

**Tools:** OBS Studio or the screen recorder built into your phone or PC. Trim with CapCut. Upload to YouTube as **Unlisted** and test the link while logged out.

---

## 4. Final submission checklist

**GitHub**
- [ ] Repo is **Public**
- [ ] `.env` is NOT in the repo (search the repo page to be sure)
- [ ] README placeholders filled (`__ / 14`, `__ / 6`, your username)
- [ ] 2-3 screenshots added in `/screenshots` and uncommented in the README
- [ ] Latest code pushed (`git status` shows clean)

**Live demo**
- [ ] https://scamsenseai.streamlit.app/ opens (wake it up a few minutes before the deadline)
- [ ] Fake bank KYC → Dangerous, Real OTP alert → Safe
- [ ] Tested once on your phone

**Video**
- [ ] Under 3 minutes
- [ ] Link works when you're logged out

**Form**
- [ ] Description pasted and placeholders removed
- [ ] GitHub, live demo and video links added
- [ ] Submitted at least a few hours before the deadline
