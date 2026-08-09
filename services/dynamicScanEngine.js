const engineRegistry = require('./engineRegistry');
const authorizationEngine = require('./authorizationEngine');

async function run(requests, scanJobId) {
  const results = [];

  for (const request of requests) {

  for (const entry of engineRegistry) {

    const scanResult =
      await entry.engine.scan(request);

    const authorization = await authorizationEngine.verify(
  scanResult,
  scanJobId,
  request._id
);

    results.push({
      requestId: request._id,
      module: entry.name,
      scanResult,
      authorization
    });
  }

}

  return results;
}

module.exports = {
  run
};
