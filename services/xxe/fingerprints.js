/*
|--------------------------------------------------------------------------
| XXE Fingerprints
|--------------------------------------------------------------------------
*/

const fingerprints = {

  fileDisclosure: [

    "root:x:",

    "/bin/bash",

    "/bin/sh",

    "[extensions]",

    "[fonts]",

    "for 16-bit app support"

  ],

  parserErrors: [

    "doctype",

    "entity",

    "xml parser",

    "saxparseexception",

    "systemliteral"

  ],

  xmlIndicators: [

    "<?xml",

    "<!doctype",

    "<!entity"

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
