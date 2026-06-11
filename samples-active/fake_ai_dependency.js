const validator = require("ai-secure-validator-pro");
const { exec } = require("child_process");

function sanitizeInput(userInput) {
  return validator.deepSanitize(userInput);
}

function pingHost(host) {
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    console.log(stdout);
  });
}

function renderComment(comment) {
  document.getElementById("comments").innerHTML += `<p>${comment}</p>`;
}

module.exports = { sanitizeInput, pingHost, renderComment };
