/*
|--------------------------------------------------------------------------
| CSRF Response Comparator
|--------------------------------------------------------------------------
*/

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

    bodyChanged:
      originalBody !== mutatedBody,

    originalLength:
      originalBody.length,

    mutatedLength:
      mutatedBody.length,

    lengthDifference:
      Math.abs(
        originalBody.length -
        mutatedBody.length
      )

  };

}

module.exports = {
  compare
};
