/*
|--------------------------------------------------------------------------
| Request Helpers
|--------------------------------------------------------------------------
*/

function discoverParameters(httpRequest) {

  const parameters = [];

  try {

    const url = new URL(httpRequest.url);

    for (const [key, value] of url.searchParams.entries()) {

      parameters.push({

        location: "query",
        name: key,
        value

      });

    }

  } catch (_) {}

  if (
    httpRequest.body &&
    typeof httpRequest.body === "object"
  ) {

    for (const [key, value] of Object.entries(httpRequest.body)) {

      parameters.push({

        location: "body",
        name: key,
        value

      });

    }

  }

  return parameters;

}

function cloneRequest(httpRequest) {

  const source =
    typeof httpRequest.toObject === "function"
      ? httpRequest.toObject()
      : httpRequest;

  return {

    ...source,

    headers: {
      ...(source.headers || {})
    },

    body:
      source.body &&
      typeof source.body === "object"
        ? { ...source.body }
        : source.body

  };

}

function injectParameter(request, parameter, payload) {

  const modified =
    cloneRequest(request);

  if (parameter.location === "query") {

    const url =
      new URL(modified.url);

    url.searchParams.set(
      parameter.name,
      payload
    );

    modified.url =
      url.toString();

  }

  if (parameter.location === "body") {

    modified.body = {

      ...(modified.body || {}),

      [parameter.name]:
        payload

    };

  }

  return modified;

}

module.exports = {

  discoverParameters,

  cloneRequest,

  injectParameter

};
