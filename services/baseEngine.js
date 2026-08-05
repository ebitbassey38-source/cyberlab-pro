function createResult(moduleName) {
  return {
    module: moduleName,
    tested: false,
    verdict: null,
    evidence: [],
    metadata: {},
    errors: []
  };
}

module.exports = {
  createResult
};
