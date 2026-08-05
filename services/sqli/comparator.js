/*
|--------------------------------------------------------------------------
| SQLi Response Comparator
|--------------------------------------------------------------------------
| Compares original and mutated responses.
*/

function compare(original, mutated) {

  const originalBody =
    JSON.stringify(original.body || {});

  const mutatedBody =
    JSON.stringify(mutated.body || {});

  const result = {

    sameStatus:
      original.status === mutated.status,

    statusChanged:
      original.status !== mutated.status,

    originalStatus:
      original.status,

    mutatedStatus:
      mutated.status,

    originalLength:
      originalBody.length,

    mutatedLength:
      mutatedBody.length,

    sameLength:
      originalBody.length === mutatedBody.length,

    bodyChanged:
      originalBody !== mutatedBody,

    headerChanged:
      JSON.stringify(original.headers || {}) !==
      JSON.stringify(mutated.headers || {})

  };

  return result;

}

module.exports = {
  compare
};
