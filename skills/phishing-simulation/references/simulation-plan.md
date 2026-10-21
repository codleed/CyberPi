# Simulation plan reference

Everything the `phishing-simulation` skill needs to plan, build, measure and
report a training exercise. Paths are relative to the engagement root; the
engagement state directory is `.cyberpi/`.

---

## 1. Simulation plan template

Copy into `.cyberpi/notes/simulation-<campaign>.md` and fill it in. Section 2
of the skill (legal prerequisites) is the sign-off block.

```markdown
# Simulation plan — <campaign name>

Engagement:      <engagement name>
Client:          <client>
Operator:        <name of the person running the simulation>
Mode:            sandbox | live pilot
Campaign id:     <GoPhish campaign id, filled after creation>

## Objective
<The decision this simulation supports. One sentence.>

## Population
Size:            <n>
Sampling:        <how the list was drawn>
Roles mix:       <roles and counts>
Exclusions:      <who is deliberately not included and why>
Source of list:  <where the addresses came from>

## Metric (fixed before the run)
Primary:         <metric name>
Denominator:     <delivered | clicked | population>
Secondary:       <other metrics>
Alert threshold: <value above which the metric is raised as low severity>

## Message
Theme:           <the lure, e.g. internal payroll notice>
Sender:          <from address and display name, both client-owned>
Link count:      1
Attachment:      none | <inert description>
Branding:        <generic wording, no third-party brand>

## Infrastructure
GoPhish:         <host:port, admin:port, landing port>
Sending profile: <name, host:port, TLS mode>
Sending domain:  <domain, SPF/DKIM/DMARC status>
Landing URL:     <url>
Scope rules:     <the scope.json rules added for the simulation>

## Data handling
Retention:       <date>
Access:          <who may read the population list and click log>
Restricted set:  <who may read per-person results, if authorized>
Destruction:     <date and method>

## Kill switch
Stop procedure:  <command and operator>
Auto-stop:       <conditions>
Escalation:      <names and contacts>

## Sign-off
[ ] Authorization attached
[ ] Privacy basis agreed
[ ] Notification sent (HR / comms / service desk)
[ ] Abuse handling ready
[ ] Approved by: <name, role, date>
```

---

## 2. GoPhish cookbook

### 2.1 Install and run

```bash
# Kali package, if the distribution ships it:
sudo apt install -y gophish

# otherwise fetch the upstream release and unpack it:
#   https://github.com/gophish/gophish/releases -> gophish_v<version>.zip
unzip gophish_v*.zip && cd gophish

# run it, bound to loopback only
./gophish
```

GoPhish writes its configuration to `~/.config/gophish/config.json` and prints
the admin URL on start-up (by default `https://127.0.0.1:3333/`). The file
also holds the admin API key.

### 2.2 The admin API

```bash
export GOPHISH_HOME="${HOME}/.config/gophish"
export GOPHISH_API_KEY="$(python3 -c "import json,os;print(json.load(open(os.path.join(os.environ['GOPHISH_HOME'],'config.json')))['api_key'])")"
export GOPHISH_ADMIN="https://127.0.0.1:3333"

# list campaigns (the admin key travels in the Authorization header)
curl -sk -H "Authorization: ${GOPHISH_API_KEY}" "${GOPHISH_ADMIN}/api/v1/campaigns/"
```

Notes:

- The admin server uses a self-signed certificate, so `curl -k` is required.
- The API key is a secret. It is read into a shell variable and never echoed,
  never written to the transcript and never pasted into a report. The shell
  commands above print only the campaign list.
- GoPhish has shipped two API generations (`/api/v1/...`, and `/api/v2/...` in
  the 0.12 series). The resource names and the field names are the same in
  both; if one prefix answers with a 404, try the other.
- The admin UI at `${GOPHISH_ADMIN}/` is the fallback for anything the API
  rejects.

| Resource | Endpoint |
|---|---|
| Campaigns | `GET/POST /api/v1/campaigns/`, `GET /api/v1/campaigns/<id>/` |
| Campaign results | `GET /api/v1/campaigns/<id>/results/` |
| Campaign status | `PUT /api/v1/campaigns/<id>/status` with `{"status":"Stopped"}` |
| Sending profiles | `GET/POST /api/v1/sending_profiles/` |
| Landing pages | `GET/POST /api/v1/landing_pages/` |
| Recipient groups | `GET/POST /api/v1/groups/` |
| Captured credentials | `GET /api/v1/credentials/`, `DELETE /api/v1/credentials/<id>` |
| Admin settings | `GET /api/v1/admin/settings/` |

### 2.3 Create the objects

Field names are stable across the 0.11/0.12 releases; a rejected field name
means the release names it differently — read the API's error and adjust.

Sending profile (sandbox example, pointed at the local sink in section 3):

```bash
curl -sk -X POST "${GOPHISH_ADMIN}/api/v1/sending_profiles/" \
  -H "Authorization: ${GOPHISH_API_KEY}" -H "Content-Type: application/json" \
  -d '{
    "name": "training-sink",
    "host": "127.0.0.1",
    "port": 2525,
    "username": "",
    "password": "",
    "from_address": "it-training@training.internal.example",
    "headers": {},
    "ignore_tls": true
  }'
```

Landing page (`capture_credentials` is what records a submission; the form
field names in the HTML must match the campaign's `credentialConfig`, or
GoPhish records no submission at all):

```bash
curl -sk -X POST "${GOPHISH_ADMIN}/api/v1/landing_pages/" \
  -H "Authorization: ${GOPHISH_API_KEY}" -H "Content-Type: application/json" \
  -d @.cyberpi/artifacts/gophish/landing-page.json
```

Recipient group (sandbox: the addresses are synthetic and only ever reach the
local sink):

```bash
curl -sk -X POST "${GOPHISH_ADMIN}/api/v1/groups/" \
  -H "Authorization: ${GOPHISH_API_KEY}" -H "Content-Type: application/json" \
  -d @.cyberpi/artifacts/gophish/group.json
```

Campaign:

```bash
curl -sk -X POST "${GOPHISH_ADMIN}/api/v1/campaigns/" \
  -H "Authorization: ${GOPHISH_API_KEY}" -H "Content-Type: application/json" \
  -d @.cyberpi/artifacts/gophish/campaign.json
```

A typical payload (`.cyberpi/artifacts/gophish/campaign.json`):

```json
{
  "name": "payroll-lure-2025-03",
  "subject": "Payroll update required for the March cycle",
  "fromName": "IT Training",
  "fromAddress": "it-training@training.internal.example",
  "template": "<html>...the message body from section 6...</html>",
  "recipients": [{ "email": "user001@staff.example.internal", "first_name": "user001", "last_name": "surname001" }],
  "group": "synthetic-population",
  "sendingProfile": "training-sink",
  "landingPage": "training-capture",
  "url": "http://127.0.0.1:8080",
  "credentialConfig": {
    "capture": true,
    "url": "http://127.0.0.1:8080",
    "usernameField": "username",
    "passwordField": "password",
    "customFields": []
  },
  "completed": false
}
```

Read the created objects back (`GET /api/v1/campaigns/<id>/`) and confirm the
names, the URL and the recipients before starting it. A campaign created with
the wrong sending profile is the one that reaches a real mailbox.

### 2.4 The URL that GoPhish tracks

When GoPhish sends a message it appends the campaign id and the recipient
address to the campaign URL, so the link in the message becomes:

```
http://127.0.0.1:8080/<campaign_id>/<recipient-address>
```

Each click is therefore attributable to one recipient, which is what makes the
per-recipient `results` map meaningful. The harness in section 4 uses the link
found in the captured message, and only falls back to constructing this form.

---

## 3. Local SMTP sink (sandbox mode)

Nothing may reach a real mailbox, so the sending profile points at a sink that
accepts messages and writes them to disk. Standard library only, no delivery
whatsoever.

Save as `.cyberpi/notes/smtp-sink.py`:

```python
#!/usr/bin/env python3
"""Local SMTP sink for phishing simulations.

Accepts messages on 127.0.0.1 and writes each one to disk as an .eml file.
Standard library only. Nothing is forwarded, nothing leaves the machine.
"""
import argparse
import os
import socketserver
import threading


class SMTPSink(socketserver.StreamRequestHandler):
    counter = 0
    lock = threading.Lock()

    def reply(self, text):
        self.wfile.write((text + "\r\n").encode("utf-8"))
        self.wfile.flush()

    def handle(self):
        self.reply("220 cyberpi-sink ESMTP")
        sender = ""
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode("utf-8", "replace").strip()
            upper = line.upper()
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                self.reply("250 cyberpi-sink")
            elif upper.startswith("MAIL FROM"):
                sender = line[len("MAIL FROM:"):].strip()
                self.reply("250 2.1.0 Ok")
            elif upper.startswith("RCPT TO"):
                self.reply("250 2.1.5 Ok")
            elif upper.startswith("DATA"):
                self.reply("354 End data with <CR><LF>.<CR><LF>")
                body = self.read_data()
                self.store(sender, body)
                self.reply("250 2.0.0 Ok: queued")
            elif upper == "RSET":
                self.reply("250 2.0.0 Ok")
            elif upper == "NOOP":
                self.reply("250 2.0.0 Ok")
            elif upper == "QUIT":
                self.reply("221 2.0.0 Bye")
                return
            else:
                self.reply("250 2.0.0 Ok")

    def read_data(self):
        chunks = []
        while True:
            raw = self.rfile.readline()
            if not raw or raw.strip() == b".":
                break
            if raw.startswith(b".."):
                raw = raw[1:]
            chunks.append(raw)
        return b"".join(chunks)

    def store(self, sender, body):
        with SMTPSink.lock:
            SMTPSink.counter += 1
            index = SMTPSink.counter
        path = os.path.join(self.server.out_dir, "message-%04d.eml" % index)
        with open(path, "wb") as handle:
            handle.write(b"X-Sink-Envelope-From: " + sender.encode("utf-8") + b"\r\n")
            handle.write(body)
        print("stored %s (%d bytes)" % (path, len(body)), flush=True)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2525)
    parser.add_argument("--out", default=".")
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)
    server = Server((args.host, args.port), SMTPSink)
    server.out_dir = args.out
    print("smtp sink listening on %s:%d -> %s" % (args.host, args.port, args.out), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
```

Run it, and point the sending profile at it:

```bash
mkdir -p .cyberpi/artifacts/gophish/mail
python3 .cyberpi/notes/smtp-sink.py --port 2525 --out .cyberpi/artifacts/gophish/mail
```

In live mode the sink is not used: the sending profile points at the client's
own relay, and the authorization's send window governs when the campaign is
started.

---

## 4. Synthetic population and the click harness (sandbox mode)

### 4.1 Generate the population

Deterministic, synthetic, and stored inside the engagement directory. The
addresses use a reserved internal domain so a misconfiguration can never
deliver to a real mailbox.

```bash
python3 - <<'PY'
import csv, random
random.seed(20250301)
roles = ["accounts payable", "engineering", "helpdesk", "finance", "executive assistant", "warehouse"]
path = ".cyberpi/artifacts/gophish/population.csv"
with open(path, "w", newline="", encoding="utf-8") as handle:
    writer = csv.writer(handle)
    writer.writerow(["email", "first_name", "last_name", "role"])
    for index in range(200):
        first = "user%03d" % index
        writer.writerow([
            "%s@staff.example.internal" % first,
            first,
            "surname%03d" % index,
            roles[index % len(roles)],
        ])
print(path)
PY
```

### 4.2 Drive clicks and submissions

The harness reads the messages the sink captured, clicks the tracked link and
submits a clearly synthetic value on a seeded fraction of the clickers. It
prints aggregate counts only — no captured value is ever printed.

```bash
python3 - <<'PY'
import glob, os, random, re, ssl, urllib.parse, urllib.request
from email import policy
from email.parser import BytesParser

random.seed(7)
MAIL_DIR = ".cyberpi/artifacts/gophish/mail"
CLICK_PROBABILITY = 0.35     # share of recipients that click the link
SUBMIT_PROBABILITY = 0.30    # share of clickers that submit the training form
CONTEXT = ssl.create_default_context()
CONTEXT.check_hostname = False
CONTEXT.verify_mode = ssl.CERT_NONE
USER_AGENT = "CyberPi-Training-Harness/1.0"

def first_link(html):
    match = re.search(r'href="(https?://[^"]+)"', html)
    return match.group(1) if match else None

def fetch(url, data=None):
    request = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=20, context=CONTEXT) as response:
        return response.status, response.read().decode("utf-8", "replace")

delivered = clicked = submitted = 0
for path in sorted(glob.glob(os.path.join(MAIL_DIR, "*.eml"))):
    with open(path, "rb") as handle:
        message = BytesParser(policy=policy.default).parse(handle)
    body = message.get_body(preferencelist=("html", "plain"))
    html = body.get_content() if body else ""
    link = first_link(html)
    if not link:
        continue
    delivered += 1
    if random.random() >= CLICK_PROBABILITY:
        continue
    clicked += 1
    try:
        fetch(link)
    except Exception:
        continue
    if random.random() >= SUBMIT_PROBABILITY:
        continue
    payload = urllib.parse.urlencode({
        "username": "training-user@example.invalid",
        "password": "training-value-%06d" % random.randrange(1000000),
    }).encode()
    try:
        fetch(link, data=payload)
        submitted += 1
    except Exception:
        continue

print("delivered=%d clicked=%d submitted=%d" % (delivered, clicked, submitted))
PY
```

The submitted username and password are throwaway values from a reserved
domain; they exist only to exercise the capture path. GoPhish stores them in
its credentials table, which is deleted at teardown (section 8).

If the harness reports `clicked=0`, the landing page is not recording results:
the campaign must have been sent (the sink proves it was), the campaign URL
must point at the landing server, and the harness must be reading the tracked
link from the message rather than from a stale copy.

### 4.3 Read the results back

```bash
export GOPHISH_CAMPAIGN_ID=1

curl -sk -H "Authorization: ${GOPHISH_API_KEY}" \
  "${GOPHISH_ADMIN}/api/v1/campaigns/${GOPHISH_CAMPAIGN_ID}/results/" \
  -o ".cyberpi/artifacts/gophish/results-${GOPHISH_CAMPAIGN_ID}.json"

python3 - <<'PY'
import json, os
path = ".cyberpi/artifacts/gophish/results-%s.json" % os.environ["GOPHISH_CAMPAIGN_ID"]
data = json.load(open(path, encoding="utf-8"))
results = data.get("results", {})
counts = {"Opened": 0, "Clicked": 0, "Submitted": 0}
for record in results.values():
    for key in counts:
        if record.get(key):
            counts[key] += 1
print("recipients=%d opened=%d clicked=%d submitted=%d sent_count=%s" % (
    len(results), counts["Opened"], counts["Clicked"], counts["Submitted"], data.get("sent_count")))
PY
```

The `results` map is keyed by recipient address and each record carries
`Opened`, `Clicked`, `Submitted`, `IP` and `UserAgent`. Count the map rather
than trusting the `num_*` counters, which can drift when a campaign is
re-rendered. Keep the file as the evidence artifact; the per-recipient rows
are personal data in a live pilot and are not reproduced in the report.

---

## 5. Metrics

### 5.1 Definitions

Let:

- `D` = delivered (messages accepted by the mail path — GoPhish's `sent_count`
  in sandbox mode, the sink's message count in sandbox mode, the relay's
  delivery log in live mode);
- `O` = unique recipients whose tracking pixel was fetched (opened);
- `C` = unique recipients who clicked the tracked link;
- `S` = unique recipients who submitted the training form;
- `N` = population size (messages handed to the mail path).

| Metric | Formula | Reading |
|---|---|---|
| Delivery rate | `D / N` | how much of the population actually received it |
| Open rate | `O / D` | weak signal; proxies and image blocking distort it |
| Click rate | `C / D` | the headline number of most campaigns |
| Credential-submission rate (population) | `S / D` | the primary training metric |
| Credential-submission rate (clickers) | `S / C` | how convincing the lure was |
| Abandon rate | `1 - S / C` | clicked but did not submit |

Always print the numerator and the denominator with the rate. "42% clicked"
without "42 of 200" is not a measurement.

### 5.2 Denominator traps

- **`sent` is not `delivered`.** GoPhish's `sent_count` means the message was
  handed to the SMTP path. A bounce, a spam filter or a full mailbox turns a
  sent message into an undelivered one. Use the relay's or the sink's count.
- **`opened` is not `read`.** A corporate proxy prefetching the tracking
  pixel inflates the open rate, and blocking the pixel deflates it. Treat
  open rate as decorative.
- **`submitted` over `clicked` is the only honest behaviour metric.** A
  submission is a deliberate act; a click is often a reflex.
- **A sandbox population is not a workforce.** The sandbox numbers validate
  the harness and give a baseline; only a live pilot measures the staff.

### 5.3 Worked example

Sandbox run, 200 synthetic recipients, 100% delivered:

| Number | Value | Rate |
|---|---|---|
| Delivered `D` | 200 / 200 | 100% |
| Opened `O` | 96 | 48.0% of delivered |
| Clicked `C` | 41 | 20.5% of delivered |
| Submitted `S` | 12 | 6.0% of delivered, 29.3% of clickers |

Reported as: *"Credential-submission rate 6.0% (12/200 delivered); click rate
20.5% (41/200); 29.3% of clickers submitted the training form (12/41). Sandbox
population — no staff contacted."*

The training recommendation follows the data: 29% of clickers went on to
submit, so the training targets the second click (the form), not the first one
(the lure).

---

## 6. Message and landing page templates

### 6.1 Email body (GoPhish template)

`{{.URL}}` is the tracked link; GoPhish replaces it per recipient. One link,
no attachments.

```html
<html>
  <body style="font-family: Arial, sans-serif; font-size: 15px; color: #1c1c1c;">
    <p>Hello {{.FirstName}},</p>
    <p>
      This is an <strong>IT security awareness training simulation</strong>.
      No action is required and no account will be affected.
    </p>
    <p>
      A March payroll update is waiting for you. Review the training
      simulation page to complete the exercise.
    </p>
    <p>
      <a href="{{.URL}}">Open the payroll update</a>
    </p>
    <p style="color: #555555; font-size: 13px;">
      Training simulation run by the IT Security team. Report suspicious
      messages to <a href="mailto:security@training.internal.example">security@training.internal.example</a>.
    </p>
  </body>
</html>
```

Rules that the template above follows and any rewrite must keep: it says it
is a simulation, it uses no third-party brand, it carries exactly one link, it
has no attachment, it has no hidden payload, and it gives a working
"report this" address that is monitored before the send.

### 6.2 Landing page

The form is labelled so that nobody enters a real password, and the field
names match the campaign's `credentialConfig` (`username`, `password`).

```html
<html>
  <body style="font-family: Arial, sans-serif; background: #f4f5f7; padding: 24px;">
    <div style="max-width: 460px; margin: 0 auto; background: #ffffff; border: 1px solid #d8dbe0; padding: 24px;">
      <h1 style="font-size: 20px;">Payroll update — training simulation</h1>
      <p style="color: #444444;">
        You are completing an IT security awareness exercise. Nothing you
        type here is stored beyond the end of the exercise.
      </p>
      <form method="post" action="">
        <p>
          <label for="username">Employee ID</label><br />
          <input id="username" name="username" type="text" style="width: 100%; padding: 8px;" />
        </p>
        <p>
          <label for="password">Training password — do not enter your real password</label><br />
          <input id="password" name="password" type="password" style="width: 100%; padding: 8px;" />
        </p>
        <p><button type="submit" style="padding: 8px 18px;">Sign in</button></p>
      </form>
      <p style="color: #555555; font-size: 13px;">
        Training simulation run by the IT Security team.
      </p>
    </div>
  </body>
</html>
```

Keep the landing page free of anything that resembles a real login: no
third-party logo, no SSO box, no password-reset link, no "your account is
locked" pressure. The page explains itself as training.

---

## 7. Live pilot differences

| | Sandbox | Live pilot |
|---|---|---|
| Population | synthetic, seeded | real subset, authorized and documented |
| Mail path | local SMTP sink | the client's own relay, inside the send window |
| Clicks | scripted harness | real recipients |
| Personal data | none | population list and click log, restricted and retained |
| Landing URL | `http://127.0.0.1:8080` | client-owned domain, in `scope.json`, TLS |
| Results | harness counts | GoPhish `results` map after the campaign finishes |
| Credentials stored | synthetic throwaway values | still never real — the form says so |
| Reporting | baseline and harness validation | the awareness metric the client acts on |

Live-mode requirements that are not optional: a real domain with SPF and DKIM
aligned, a landing host in `scope.json`, a send window in the authorization
and enforced (a campaign started outside the window is an incident), a
monitored report address live before the send, and per-person results handled
as restricted data.

---

## 8. Teardown checklist

- [ ] Campaign stopped if it was still sending
      (`PUT /api/v1/campaigns/<id>/status` with `{"status":"Stopped"}`).
- [ ] GoPhish stopped.
- [ ] Captured credentials deleted from GoPhish
      (`GET /api/v1/credentials/` then `DELETE /api/v1/credentials/<id>` for
      each one). Report the count deleted, never the values.
- [ ] Population list and click log either deleted or moved to the restricted
      store with the agreed retention date.
- [ ] The local sink stopped and its captured `.eml` files destroyed.
- [ ] Aggregate artifacts kept as evidence (campaign JSON, results JSON, the
      message source).
- [ ] Teardown recorded in `.cyberpi/notes/simulation-<campaign>.md`: what was
      destroyed, when, and by whom.
- [ ] The client's report includes the teardown confirmation and the
      destruction date.
