/*
|--------------------------------------------------------------------------
| SQL Error Fingerprints
|--------------------------------------------------------------------------
*/

const fingerprints = {

  mysql: [
    "sql syntax",
    "mysql",
    "mysqli",
    "mysql_fetch",
    "mariadb"
  ],

  postgresql: [
    "postgresql",
    "pg_query",
    "pg_fetch",
    "sqlstate"
  ],

  mssql: [
    "odbc driver",
    "microsoft ole db",
    "unclosed quotation mark",
    "sql server"
  ],

  oracle: [
    "ora-",
    "oracle error"
  ],

  sqlite: [
    "sqlite",
    "sqlite.exception",
    "near syntax error"
  ]

};

function detect(body) {

  const text =
    JSON.stringify(body || {}).toLowerCase();

  const matches = [];

  for (const [db, rules] of Object.entries(fingerprints)) {

    for (const rule of rules) {

      if (text.includes(rule)) {

        matches.push({
          database: db,
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
