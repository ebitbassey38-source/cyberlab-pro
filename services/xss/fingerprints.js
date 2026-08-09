/*
|--------------------------------------------------------------------------
| XSS Fingerprints
|--------------------------------------------------------------------------
*/

const fingerprints = {
  reflected: [
    "<script",
    "</script>",
    "onerror=",
    "onload=",
    "onmouseover="
  ],

  html: [
    "<img",
    "<svg",
    "<iframe",
    "<body"
  ]
};

function detect(body, payload) {
  const text = JSON.stringify(body || {}).toLowerCase();
  const matches = [];

  if (
    payload &&
    text.includes(payload.toLowerCase())
  ) {
    matches.push({
      type: "payload_reflected",
      signature: payload
    });
  }

  for (const [group, rules] of Object.entries(fingerprints)) {
    for (const rule of rules) {
      if (text.includes(rule.toLowerCase())) {
        matches.push({
          type: group,
          signature: rule
        });
      }
    }
  }

  return matches;
}

module.exports = {
  detect
};
