const express = require("express");

const router = express.Router();
const auth = require("../middleware/auth");

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

  const escapeHtml = (value) =>
    String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");

  const safeInput = escapeHtml(input);

  res.type("html").send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>CyberLab XSS Training Lab</title>
      </head>
      <body>
        <h1>Demo User</h1>
        <div id="result">${safeInput}</div>
      </body>
    </html>
  `);
});

router.get("/idor/:id", auth, (req, res) => {
  const users = {
    "1": {
      id: 1,
      name: "Demo User One",
      role: "client",
      owner: "6a7668f1b5f8b95907ed8b60"
    },
    "2": {
      id: 2,
      name: "Demo User Two",
      role: "client",
      owner: "other-user-2"
    },
    "3": {
      id: 3,
      name: "Demo User Three",
      role: "admin",
      owner: "other-user-3"
    },
    "4": {
      id: 4,
      name: "Demo User Four",
      role: "client",
      owner: "other-user-4"
    }
  };

  const user = users[req.params.id];

  if (!user) {
    return res.status(404).json({
      error: "User not found"
    });
  }

  // Intentionally vulnerable training-lab behavior:
  // ownership is NOT enforced.
  res.json(user);
});

module.exports = router;
