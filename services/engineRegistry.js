const idorEngine = require('./idorEngine');
const sqliEngine = require('./sqliEngine');
const xssEngine = require('./xssEngine');
module.exports = [
  {
    name: "idor",
    engine: idorEngine
  },
  {
    name: "sqli",
    engine: sqliEngine
  }
,
  {
    name: "xss",
    engine: xssEngine
  }

  // Future engines:
  // xssEngine
  // ssrfEngine
  // csrfEngine
];
