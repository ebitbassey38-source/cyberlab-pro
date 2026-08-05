/*
|--------------------------------------------------------------------------
| CSRF Fingerprints
|--------------------------------------------------------------------------
*/

const fingerprints = {

  protection: [

    "csrf",

    "xsrf",

    "csrf-token",

    "_csrf",

    "x-csrf-token",

    "x-xsrf-token"

  ],

  cookies: [

    "samesite",

    "secure",

    "httponly"

  ]

};

function detect(headers = {}, body = {}) {

  const text = (

    JSON.stringify(headers) +

    JSON.stringify(body)

  ).toLowerCase();

  const matches = [];

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
