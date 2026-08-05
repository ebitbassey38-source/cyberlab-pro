/*
|--------------------------------------------------------------------------
| SSRF Fingerprints
|--------------------------------------------------------------------------
*/

const fingerprints = {

  metadata: [

    "ami-id",

    "instance-id",

    "identity-credentials",

    "latest/meta-data"

  ],

  localhost: [

    "127.0.0.1",

    "localhost"

  ],

  internal: [

    "192.168.",

    "10.0.",

    "172.16."

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
