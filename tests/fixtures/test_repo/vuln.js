function processData(userInput) {
    // XSS vulnerability
    document.getElementById('output').innerHTML = userInput;  // VULNERABLE
}

function unsafeJsonParse(jsonStr) {
    // Dangerous eval-like operation
    return eval('(' + jsonStr + ')');  // VULNERABLE
}
