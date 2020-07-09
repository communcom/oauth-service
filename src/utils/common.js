function getRequestId(req) {
    return req.headers['cf-ray'] || '-';
}

function log(...args) {
    console.log(new Date().toISOString(), ...args);
}

function logError(...args) {
    log('[err ]', ...args);
}

function logRequest(req, ...args) {
    log(getRequestId(req), ...args);
}

module.exports = { getRequestId, log, logError, logRequest };
