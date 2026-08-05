/*
|--------------------------------------------------------------------------
| Path Traversal Fingerprints
|--------------------------------------------------------------------------
*/

const fingerprints = {

  unix: [

    "root:x:",

    "/bin/bash",

    "/bin/sh",

    "daemon:",

    "nobody:"

  ],

  windows: [

    "[extensions]",

    "[fonts]",

    "for 16-bit app support",

    "mci extensions",

    "windows"

  ],

  traversalErrors: [

    "permission denied",

    "access denied",

    "no such file",

    "cannot find",

    "failed to open"

  ]

};

function detect(body) {

  const text =
    JSON.stringify(body || {}).toLowerCase();

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
