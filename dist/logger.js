"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
function createLogger(name, level) {
    var result = {
        info: function (value) { },
        warn: function (value) { },
        error: function (value) { }
    };
    if (level >= 0) {
        result.error = function (value) { return console.error("[" + name + "] " + value); };
    }
    if (level >= 1) {
        result.warn = function (value) { return console.warn("[" + name + "] " + value); };
    }
    if (level >= 2) {
        result.info = function (value) { return console.log("[" + name + "] " + value); };
    }
    return result;
}
exports.default = createLogger;
