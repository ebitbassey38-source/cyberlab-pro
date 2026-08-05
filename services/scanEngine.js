const ScanJob = require('../models/ScanJob');
const Asset = require('../models/Asset');
const HTTPRequest = require('../models/HTTPRequest');
const AuthorizationContext = require('../models/AuthorizationContext');
const analysisEngine = require('./analysisEngine');
const findingEngine = require('./findingEngine');
const dynamicScanEngine = require('./dynamicScanEngine');
async function run(scanJobId) {
  // Load Scan Job
  const scanJob = await ScanJob.findById(scanJobId);

  if (!scanJob) {
    throw new Error('Scan Job not found');
  }

  // Mark scan as running
  scanJob.status = 'running';
  scanJob.startedAt = new Date();
  await scanJob.save();

  // Load Asset
  const asset = await Asset.findById(scanJob.asset);

  if (!asset) {
    throw new Error('Asset not found');
  }

  // Load imported HTTP requests
  const requests = await HTTPRequest.find({
    asset: asset._id
  });

for (const request of requests) {
  await AuthorizationContext.create({
    scanJob: scanJob._id,
    httpRequest: request._id,
    authenticationType: request.authentication
  });
}
  // Placeholder for API Recon
  const apiRecon = {
    target: asset.value,
    endpoints: requests.map(r => ({
      method: r.method,
      url: r.url,
      authentication: r.authentication
    }))
  };

  // Finish scan
  scanJob.status = 'completed';
  scanJob.finishedAt = new Date();
  await scanJob.save();

 const analysis = await analysisEngine.analyzeEndpoints(
  apiRecon,
  requests
);
const dynamicResults =
  await dynamicScanEngine.run(
    requests,
    scanJob._id
  );
const findings = await findingEngine.saveConfirmedFindings({
  asset,
  analysis,
  dynamicResults
});
return {
  scanJob,
  asset,
  apiRecon,
  analysis,
  findings
};
}

module.exports = {
  run
};
