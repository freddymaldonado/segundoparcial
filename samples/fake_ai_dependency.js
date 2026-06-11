// Codigo generado por IA - ejemplo para auditoria (Grupo 3)
// Simula un validador "vibe-coded" que usa una libreria inventada por el LLM.

// FALLO: "ai-secure-validator-pro" no existe en npm (dependencia alucinada).
// Riesgo de slopsquatting: un atacante puede publicar ese nombre con malware.
const validator = require("ai-secure-validator-pro");
const { exec } = require("child_process");

function sanitizeInput(userInput) {
  // FALLO: confia ciegamente en la libreria inventada
  return validator.deepSanitize(userInput);
}

function pingHost(host) {
  // FALLO: inyeccion de comandos, input del usuario directo al shell
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    console.log(stdout);
  });
}

function renderComment(comment) {
  // FALLO: XSS, inserta HTML sin escapar
  document.getElementById("comments").innerHTML += `<p>${comment}</p>`;
}

module.exports = { sanitizeInput, pingHost, renderComment };
