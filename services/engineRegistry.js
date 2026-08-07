const idorEngine = require('./idorEngine');
const sqliEngine = require('./sqliEngine');
const xssEngine = require('./xssEngine');
const ssrfEngine = require('./ssrfEngine');
const csrfEngine = require('./csrfEngine');
const cmdiEngine = require('./cmdiEngine');
const xxeEngine = require('./xxeEngine');
const pathTraversalEngine = require('./pathTraversalEngine');

module.exports = [

  {
    name: "idor",
    engine: idorEngine
  },

  {
    name: "sqli",
    engine: sqliEngine
  },

  {
    name: "xss",
    engine: xssEngine
  },

  {
    name: "ssrf",
    engine: ssrfEngine
  },

  {
    name: "csrf",
    engine: csrfEngine
  },

  {
    name: "cmdi",
    engine: cmdiEngine
  },

  {
    name: "xxe",
    engine: xxeEngine
  },

  {
  name: "path_traversal",
  engine: pathTraversalEngine
}

];
