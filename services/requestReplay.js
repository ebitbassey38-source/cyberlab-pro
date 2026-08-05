const axios = require("axios");

async function replay(httpRequest) {
  try {
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
      body: response.data,
      error: null
    };

  } catch (err) {

    return {
      status: 0,
      headers: {},
      body: "",
      error: err.message
    };

  }
}

module.exports = {
  replay
};
