/*
|--------------------------------------------------------------------------
| XSS Response Comparator
|--------------------------------------------------------------------------
*/

function getContentType(response) {
  const headers = response.headers || {};

  return (
    headers["content-type"] ||
    headers["Content-Type"] ||
    ""
  ).toLowerCase();
}

function compare(original, mutated) {
  const originalBody =
    JSON.stringify(original.body || {});

  const mutatedBody =
    JSON.stringify(mutated.body || {});

  return {
    sameStatus:
      original.status === mutated.status,

    statusChanged:
      original.status !== mutated.status,

    originalLength:
      originalBody.length,

    mutatedLength:
      mutatedBody.length,

    bodyChanged:
      originalBody !== mutatedBody,

    lengthDifference:
      Math.abs(
        originalBody.length -
        mutatedBody.length
      ),

    originalContentType:
      getContentType(original),

    mutatedContentType:
      getContentType(mutated),

    isHtmlResponse:
      getContentType(mutated).includes("text/html")
  };
}

module.exports = {
  compare
};
