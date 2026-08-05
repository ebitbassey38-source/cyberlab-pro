const axios = require("axios");

async function replay(httpRequest) {
  const response = await axios({
    method: httpRequest.method,
    url: httpRequest.url,
    headers: httpRequest.headers || {},
    data: httpRequest.body || {},
    validateStatus: () => true,
    timeout: 8000
  });

  return {
    status: response.status,
    headers: response.headers,
    body: response.data
  };
}

module.exports = {
  replay
};
