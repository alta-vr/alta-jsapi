"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
function createLogger(name, level) {
    var result = {
        info: (value) => { },
        warn: (value) => { },
        error: (value) => { }
    };
    if (level >= 0) {
        result.error = (value) => console.error(`[${name}] ${value}`);
    }
    if (level >= 1) {
        result.warn = (value) => console.warn(`[${name}] ${value}`);
    }
    if (level >= 2) {
        result.info = (value) => console.log(`[${name}] ${value}`);
    }
    return result;
}
exports.default = createLogger;
