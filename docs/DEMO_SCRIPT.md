# 2-minute demo: recording script

**Goal:** show what works today, honestly. Do not oversell. Say "simulated" out loud.
**Length:** about 2 minutes. Speak slowly; it is fine to go over by 20 seconds.

## Before recording
1. Open a terminal in the project folder. Font size large (at least 16 pt), dark background.
2. Clear the screen (`cls`), close notifications (Windows: Focus assist / Do not disturb).
3. Record **only the terminal window**, not the whole screen (Windows Game Bar: `Win + Alt + R` while the terminal is
   focused). This keeps tabs, e-mail and personal files out of the video.
4. Type `py demo.py --step` and press Enter. After each scene, press Enter to continue.

## Script (read, do not memorise)

**Intro (10 s)**
"This is a prototype of an over-the-air update hub for IoT devices. Everything you will see runs on 200
*simulated* devices on my laptop, not on real hardware yet."

**Scene 0 - baseline (10 s)**
"Each device enrolled with its own key. A library with a known flaw is running on all 200. The hub can answer:
who is exposed?"

**Scene 1 - good release (15 s)**
"I publish a signed fix and roll it out in stages, 5 percent, 25, then 100. All 200 updated, and the exposed
count goes to zero."

**Scene 2 - buggy release (20 s)**
"Now a release that crashes on one hardware revision. The canary catches it: the rollout halts automatically,
only two of 200 devices ever tried it, and the one that updated is pulled back."

**Scene 3 - compromised hub (15 s)**
"Even if the hub is breached and the firmware image is swapped after signing, devices check the signed hash
themselves and refuse it. The hub never holds the signing key."

**Scene 4 - restart (10 s)**
"I restart the hub. Same devices, same history, and the audit chain still verifies."

**Scene 5 - identity (20 s)**
"An impostor with the wrong key is refused. An old request replayed is refused. A used enrollment token is
refused. A revoked device is blocked. Every refusal is logged."

**Scene 6 - audit (10 s)**
"The log is hash-chained: if I edit one entry afterwards, verification fails at exactly that entry."

**Close (10 s)**
"This is early. No TLS yet, the ESP32 agent does not talk to the hub yet, and established tools like Mender
and balena exist. I am looking for feedback from teams that ship connected devices: how do you update them
today, and what hurts? Link below."

## After recording
- Upload as **unlisted** (for example on YouTube) and put the link in the README. Do not commit the video to Git.
- Watch it once with sound off: the terminal text alone should still make sense.
