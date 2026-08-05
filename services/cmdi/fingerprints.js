/*
|--------------------------------------------------------------------------
| Command Injection Fingerprints
|--------------------------------------------------------------------------
*/

const fingerprints = {

  unix: [

    "uid=",

    "gid=",

    "groups=",

    "root:x:",

    "/bin/bash"

  ],

  windows: [

    "volume serial number",

    "directory of",

    "windows\\system32",

    "nt authority",

    "administrator"

  ],

  commandOutput: [

    "whoami",

    "root",

    "administrator"

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
