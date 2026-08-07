const express = require("express");

const router = express.Router();

/*
|--------------------------------------------------------------------------
| CyberLab Training Lab
|--------------------------------------------------------------------------
| Intentionally vulnerable endpoints
| Used ONLY for testing CyberLab engines.
|--------------------------------------------------------------------------
*/

router.get("/ping", (req, res) => {
  res.json({
    message: "CyberLab Training Lab is running."
  });
});
router.get("/sqli", (req, res) => {

  const id = req.query.id || "";

  if (
    id.includes("'") ||
    id.includes("--") ||
    id.toLowerCase().includes("or 1=1")
  ) {

    return res.status(500).send(`
      SQLSTATE[42000]:
      You have an error in your SQL syntax
      near '${id}'
    `);

  }

  res.json({
    id,
    name: "Demo User"
  });

});
router.get("/xss", (req, res) => {

  const input = req.query.id || "";

  res.type("html").send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>CyberLab XSS Training Lab</title>
      </head>
      <body>
        <h1>Demo User</h1>
        <div id="result">${input}</div>
      </body>
    </html>
  `);

});
module.exports = router;
