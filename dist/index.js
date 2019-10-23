"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __await = (this && this.__await) || function (v) { return this instanceof __await ? (this.v = v, this) : new __await(v); }
var __asyncGenerator = (this && this.__asyncGenerator) || function (thisArg, _arguments, generator) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var g = generator.apply(thisArg, _arguments || []), i, q = [];
    return i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i;
    function verb(n) { if (g[n]) i[n] = function (v) { return new Promise(function (a, b) { q.push([n, v, a, b]) > 1 || resume(n, v); }); }; }
    function resume(n, v) { try { step(g[n](v)); } catch (e) { settle(q[0][3], e); } }
    function step(r) { r.value instanceof __await ? Promise.resolve(r.value.v).then(fulfill, reject) : settle(q[0][2], r); }
    function fulfill(value) { resume("next", value); }
    function reject(value) { resume("throw", value); }
    function settle(f, v) { if (f(v), q.shift(), q.length) resume(q[0][0], q[0][1]); }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var request_promise_native_1 = __importDefault(require("request-promise-native"));
var path_1 = __importDefault(require("path"));
var fs_1 = __importDefault(require("fs"));
var jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
var memoizee_1 = __importDefault(require("memoizee"));
var sha512_1 = __importDefault(require("crypto-js/sha512"));
var logger_1 = __importDefault(require("./logger"));
var appdata = path_1.default.join(process.env.APPDATA || "./", 'Alta Launcher');
var publicBaseUrl = function (name) { return "https://967phuchye.execute-api.ap-southeast-2.amazonaws.com/" + name + "/api/"; };
var localEndpoint = "http://localhost:13490/api/";
function getEndpoint(name) {
    switch (name) {
        case 'dev':
        case 'prod':
        case 'test':
        case 'latest':
            return publicBaseUrl(name);
        case 'local':
            return localEndpoint;
    }
}
var DEV = 'dev';
var PROD = 'prod';
var TEST = 'test';
var LATEST = 'latest';
var LOCAL = 'local';
//Change here
var currentEndpoint = getEndpoint(PROD);
//Reject Unauthorized Setting
var rejectUnauthorized = true;
var loggingLevel = 0;
var refreshPromise;
exports.getRejectUnauthorized = function () { return rejectUnauthorized; };
if (process.env.APPDATA != undefined) {
    var settingsFile = path_1.default.join(process.env.APPDATA, 'Alta Launcher', 'Settings.json');
    console.log("Couldn't find Settings file to check rejectUnauthorized");
    if (fs_1.default.existsSync(settingsFile)) {
        var settings = JSON.parse(fs_1.default.readFileSync(settingsFile, "utf8"));
        rejectUnauthorized = !!settings.rejectUnauthorized;
        loggingLevel = settings.jsapiLoggingLevel;
        if (!!settings.apiEndpoint) {
            currentEndpoint = getEndpoint(settings.apiEndpoint);
        }
        console.log("rejectUnauthorized: " + rejectUnauthorized);
        console.log("jsapi logging level: " + loggingLevel);
    }
}
else {
    console.info("Couldn't find APPDATA to check rejectUnauthorized");
}
console.log("jsapi endpoint: " + currentEndpoint);
var logger = logger_1.default('WEBAPI', loggingLevel);
var isOffline = false;
var accessToken;
var refreshToken;
var identityToken;
var accessString;
var refreshString;
var identityString;
var cookies;
var headers = {
    "Content-Type": "application/json",
    'x-api-key': '2l6aQGoNes8EHb94qMhqQ5m2iaiOM9666oDTPORf',
    'Authorization': '',
    'User-Agent': 'Launcher'
};
function setVersion(version) {
    headers['User-Agent'] = 'Launcher/' + version;
}
exports.setVersion = setVersion;
function setUserAgent(userAgent) {
    headers['User-Agent'] = userAgent;
}
exports.setUserAgent = setUserAgent;
function requestNoLogin(method, path, isCached, body) {
    if (isCached === void 0) { isCached = false; }
    if (body === void 0) { body = undefined; }
    logger.info("NO LOGIN: " + method + " " + path);
    if (isOffline) {
        throw new Error("Unsupported in offline mode: " + path);
    }
    return request_promise_native_1.default({ url: currentEndpoint + path, method: method, headers: headers, body: JSON.stringify(body), rejectUnauthorized: rejectUnauthorized })
        .then(function (response) { return JSON.parse(response); });
}
function request(method, path, isCached, body) {
    if (isCached === void 0) { isCached = false; }
    if (body === void 0) { body = undefined; }
    logger.info(method + " " + path);
    if (isOffline) {
        throw new Error("Unsupported in offline mode: " + path);
    }
    return updateTokens()
        //TODO: Remove the limit
        .then(function () { return request_promise_native_1.default({ url: currentEndpoint + path, method: method, headers: headers, body: JSON.stringify(body), rejectUnauthorized: rejectUnauthorized, qs: { limit: 20 } }); })
        .then(function (response) { try {
        return JSON.parse(response);
    }
    catch (error) {
        logger.info("Failed to parse response to " + path + " : " + response);
    } });
}
function requestPaged(method, path, limit, isCached, body) {
    if (limit === void 0) { limit = undefined; }
    if (isCached === void 0) { isCached = false; }
    if (body === void 0) { body = undefined; }
    return __asyncGenerator(this, arguments, function requestPaged_1() {
        var lastToken, response, error_1, error_2;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    logger.info(method + " " + path);
                    if (isOffline) {
                        throw new Error("Unsupported in offline mode: " + path);
                    }
                    return [4 /*yield*/, __await(updateTokens())];
                case 1:
                    _a.sent();
                    lastToken = undefined;
                    _a.label = 2;
                case 2:
                    if (!true) return [3 /*break*/, 12];
                    _a.label = 3;
                case 3:
                    _a.trys.push([3, 5, , 6]);
                    return [4 /*yield*/, __await(request_promise_native_1.default({ url: currentEndpoint + path, method: method, headers: headers, body: JSON.stringify(body), rejectUnauthorized: rejectUnauthorized, resolveWithFullResponse: true, qs: { paginationToken: lastToken, limit: limit } }))];
                case 4:
                    response = _a.sent();
                    return [3 /*break*/, 6];
                case 5:
                    error_1 = _a.sent();
                    console.error("Error in pagination");
                    console.error(error_1);
                    throw error_1;
                case 6:
                    lastToken = response.headers.paginationtoken;
                    _a.label = 7;
                case 7:
                    _a.trys.push([7, 10, , 11]);
                    return [4 /*yield*/, __await(JSON.parse(response.body))];
                case 8: return [4 /*yield*/, _a.sent()];
                case 9:
                    _a.sent();
                    return [3 /*break*/, 11];
                case 10:
                    error_2 = _a.sent();
                    logger.info("Failed to parse response to " + path + " : " + response.body);
                    throw error_2;
                case 11:
                    if (!lastToken) {
                        return [3 /*break*/, 12];
                    }
                    return [3 /*break*/, 2];
                case 12: return [2 /*return*/];
            }
        });
    });
}
function requestRefresh(method, path, isCached, body) {
    if (isCached === void 0) { isCached = false; }
    if (body === void 0) { body = undefined; }
    if (isOffline) {
        throw new Error("Unsupported in offline mode: " + path);
    }
    headers = __assign(__assign({}, headers), { Authorization: "Bearer " + refreshString });
    return request_promise_native_1.default({ url: currentEndpoint + path, method: method, headers: headers, body: JSON.stringify(body), rejectUnauthorized: rejectUnauthorized })
        .then(function (response) { return JSON.parse(response); });
}
function updateTokens() {
    if (!!refreshPromise) {
        logger.info("Awaiting current refresh promise");
        return refreshPromise;
    }
    if (!accessToken || accessToken.exp - (new Date().getTime() / 1000) < 15) {
        logger.info("Requiring refresh");
        refreshPromise = exports.Sessions.refreshSession().then(function () { return refreshPromise = undefined; });
        return refreshPromise;
    }
    else {
        logger.info("Access token valid");
        return Promise.resolve();
    }
}
exports.Sessions = {
    ensureLoggedIn: function () { return new Promise(function (resolve, reject) {
        if (!accessToken && !refreshString) {
            reject(new Error("Not logged in"));
        }
        else {
            updateTokens()
                .then(function () { return !!accessToken ? resolve() : reject(new Error("Not logged in")); })
                .catch(reject);
        }
    }); },
    getUserId: function () { return (!!accessToken && accessToken.UserId); },
    getVerified: function () { return (!!accessToken && (accessToken.is_verified || accessToken.is_verified === "True")); },
    getUsername: function () { return (!!accessToken && accessToken.Username); },
    getMember: function () { return (!!accessToken && (accessToken.is_member || accessToken.is_member === "True")); },
    getPolicy: function (policy) { return (!!accessToken && accessToken.Policy.some(function (item) { return item === policy; })); },
    connectToCookies: function (providedCookies) {
        cookies = providedCookies;
        exports.Sessions.setLocalTokens({
            refresh_token: cookies.get("refresh_token"),
            access_token: cookies.get("access_token"),
            identity_token: cookies.get("identity_token"),
        });
    },
    getLocalTokens: function () {
        return { access_token: accessString, refresh_token: refreshString, identity_token: identityString };
    },
    setLocalTokens: function (tokens) {
        if (!!tokens.access_token && accessString != tokens.access_token) {
            accessString = tokens.access_token;
            headers.Authorization = "Bearer " + accessString;
            accessToken = jsonwebtoken_1.default.decode(accessString);
            cookies && cookies.set("access_token", accessString, { path: '/' });
        }
        if (!!tokens.refresh_token && refreshString != tokens.refresh_token) {
            refreshString = tokens.refresh_token;
            refreshToken = jsonwebtoken_1.default.decode(refreshString);
        }
        if (!!tokens.identity_token && identityString != tokens.identity_token) {
            identityString = tokens.identity_token;
            identityToken = jsonwebtoken_1.default.decode(identityString);
            cookies && cookies.set("identity_token", identityString, { path: '/' });
        }
    },
    logout: function () {
        logger.info("Logging out");
        if (!!cookies) {
            cookies.remove("refresh_token", { path: '/' });
            cookies.remove("access_token", { path: '/' });
            cookies.remove("identity_token", { path: '/' });
        }
        identityString = undefined;
        refreshString = undefined;
        accessString = undefined;
        identityToken = undefined;
        refreshToken = undefined;
        accessToken = undefined;
    },
    loginOffline: function (username) {
        logger.info("Login offline " + username);
        var refresh = { "UserId": "0", "role": "Refresh", "exp": 9999999999, "iss": "AltaWebAPI", "aud": "AltaClient" };
        var access = { "UserId": "0", "Username": "OFFLINE " + username, "role": "Access", "is_verified": "True", "is_member": "True", "Policy": ["offline", "database_admin", "admin_vr_modes", "debug_features", "game_access_development", "play_offline", "server_access_development", "server_owner", "game_access_public", "server_access_pre_alpha", "server_access_tutorial", "server_create_development", "game_access_testing", "reuse_refresh_tokens", "server_access_testing"], "exp": 9999999999, "iss": "AltaWebAPI", "aud": "AltaClient" };
        var identity = { "UserId": "0", "Username": "OFFLINE " + username, "role": "Identity", "is_member": "True", "is_dev": "True", "exp": 9999999999, "iss": "AltaWebAPI", "aud": "AltaClient" };
        exports.Sessions.setLocalTokens({
            refresh_token: jsonwebtoken_1.default.sign(refresh, "offline"),
            access_token: jsonwebtoken_1.default.sign(access, "offline"),
            identity_token: jsonwebtoken_1.default.sign(identity, "offline")
        });
        return Promise.resolve();
    },
    hashPassword: function (password) {
        return sha512_1.default(password).toString();
    },
    loginWithUsername: function (username, passwordHash) {
        logger.info("Login " + username);
        if (isOffline) {
            return exports.Sessions.loginOffline(username);
        }
        return requestNoLogin('POST', 'sessions', false, { username: username, password_hash: passwordHash })
            .then(function (result) { return exports.Sessions.setLocalTokens(result); });
    },
    loginWithEmail: function (email, passwordHash) {
        logger.info("Login with email");
        if (isOffline) {
            return exports.Sessions.loginOffline(email);
        }
        return requestNoLogin('POST', 'sessions/email', false, { email: email, password_hash: passwordHash })
            .then(function (result) { return exports.Sessions.setLocalTokens(result); });
    },
    loginWithRefreshToken: function (refreshToken) {
        logger.info("Login with refresh");
        if (isOffline) {
            return exports.Sessions.loginOffline("refresh");
        }
        refreshString = refreshToken;
        return exports.Sessions.refreshSession();
    },
    checkRemembered: function () {
        logger.info("Check remembered");
        try {
            if (!fs_1.default.existsSync(appdata)) {
                fs_1.default.mkdirSync(appdata, { recursive: true });
            }
            var rememberPath = path_1.default.join(appdata, '.rememberme');
            if (fs_1.default.existsSync(rememberPath)) {
                var content = fs_1.default.readFileSync(rememberPath, 'utf8');
                return exports.Sessions.loginWithRefreshToken(content);
            }
        }
        catch (error) {
            console.error("Error while checking remembered. See below.");
            console.error(error);
        }
        return Promise.resolve();
    },
    remember: function () {
        logger.info("Remember");
        cookies && cookies.set("refresh_token", refreshString, { path: '/' });
        if (!fs_1.default.existsSync(appdata)) {
            fs_1.default.mkdirSync(appdata, { recursive: true });
        }
        var rememberPath = path_1.default.join(appdata, '.rememberme');
        fs_1.default.writeFileSync(rememberPath, refreshString, 'utf8');
    },
    forget: function () {
        logger.info("Forget");
        if (!!cookies) {
            cookies.remove("refresh_token", { path: '/' });
        }
        var rememberPath = path_1.default.join(appdata, '.rememberme');
        if (fs_1.default.existsSync(rememberPath)) {
            fs_1.default.unlinkSync(rememberPath);
        }
    },
    refreshSession: function () {
        logger.info("Refreshing session");
        return requestRefresh('PUT', 'sessions', false, {})
            .then(function (result) { return exports.Sessions.setLocalTokens(result); });
    },
};
exports.Launcher = {
    getGames: function () {
        logger.info("Get games");
        return request('GET', 'launcher/games');
    },
    getGameInfo: function (gameId) {
        logger.info("Get game info");
        return request('GET', "launcher/games/" + gameId);
    },
};
exports.Groups = {
    Member: 1,
    Moderator: 2,
    Admin: 4,
    MemberUp: 7,
    ModeratorUp: 6,
    /*
    Member 1,
    Moderator 2,
    Admin 4
    */
    Open: 0,
    Public: 1,
    Private: 2,
    getJoined: function () {
        logger.info("Get joined groups");
        return requestPaged('GET', 'groups/joined');
    },
    getVisible: function () {
        logger.info("Get visible groups");
        return requestPaged('GET', 'groups');
    },
    getInvited: function () {
        logger.info("Get invited to groups");
        return requestPaged('GET', 'groups/invites');
    },
    getRequested: function () {
        logger.info("Get requested groups");
        return requestPaged('GET', 'groups/requested');
    },
    createGroup: function (name, description) {
        logger.info("Create group");
        return request('POST', 'groups', false, {
            type: exports.Groups.Private,
            description: description,
            Name: name,
            invite_permissions: exports.Groups.ModeratorUp,
            kick_permissions: exports.Groups.ModeratorUp,
            accept_member_permissions: exports.Groups.ModeratorUp,
            create_server_permissions: exports.Groups.Admin
        });
    },
    getGroupInfo: function (groupId) {
        logger.info("Get group info " + groupId);
        return request('GET', "groups/" + groupId);
    },
    getMembers: function (groupId) {
        logger.info("Get members " + groupId);
        return requestPaged('GET', "groups/" + groupId + "/members");
    },
    getBans: function (groupId) {
        logger.info("Get banned " + groupId);
        return requestPaged('GET', "groups/" + groupId + "/bans");
    },
    banUser: function (groupId, userId) {
        logger.info("Ban user " + groupId + " " + userId);
        return request('POST', "groups/" + groupId + "/bans/" + userId);
    },
    unbanUser: function (groupId, userId) {
        logger.info("Unban user " + groupId + " " + userId);
        return request('DELETE', "groups/" + groupId + "/bans/" + userId);
    },
    getMemberInfo: function (groupId, userId) {
        logger.info("Get member permissions " + groupId + " " + userId);
        return request('GET', "groups/" + groupId + "/members/" + userId);
    },
    getJoinRequests: function (groupId) {
        logger.info("Get join requests " + groupId);
        return requestPaged('GET', "groups/" + groupId + "/requests");
    },
    getOutgoingInvites: function (groupId) {
        logger.info("Get outgoing invites " + groupId);
        return requestPaged('GET', "groups/" + groupId + "/invites");
    },
    requestJoin: function (groupId) {
        logger.info("Request join " + groupId);
        return request('POST', "groups/" + groupId + "/requests");
    },
    revokeRequest: function (groupId) {
        logger.info("Revoke request " + groupId);
        return request('DELETE', "groups/" + groupId + "/requests");
    },
    acceptInvite: function (groupId) {
        logger.info("Accept invite " + groupId);
        return request('POST', "groups/invites/" + groupId);
    },
    rejectInvite: function (groupId) {
        logger.info("Reject invite " + groupId);
        return request('DELETE', "groups/invites/" + groupId);
    },
    leave: function (groupId) {
        logger.info("Leave " + groupId);
        return request('DELETE', "groups/" + groupId + "/members");
    },
    inviteMember: function (groupId, userId) {
        logger.info("Invite member " + groupId + " " + userId);
        return request('POST', "groups/" + groupId + "/invites/" + userId);
    },
    revokeInvite: function (groupId, userId) {
        logger.info("Revoke invite " + groupId + " " + userId);
        return request('DELETE', "groups/" + groupId + "/invites/" + userId);
    },
    acceptRequest: function (groupId, userId) {
        logger.info("Accept request " + groupId + " " + userId);
        return request('PUT', "groups/" + groupId + "/requests/" + userId);
    },
    rejectRequest: function (groupId, userId) {
        logger.info("Reject request " + groupId + " " + userId);
        return request('DELETE', "groups/" + groupId + "/requests/" + userId);
    },
    kickMember: function (groupId, userId) {
        logger.info("Invite member " + groupId + " " + userId);
        return request('DELETE', "groups/" + groupId + "/members/" + userId);
    },
    editPermissions: function (groupId, userId, permissions) {
        logger.info("Edit member permissions " + groupId + " " + userId);
        return request('POST', "groups/" + groupId + "/members/" + userId + "/permissions", false, {
            permissions: permissions
        });
    },
    createServer: function (groupId, name, description, region) {
        logger.info("Create server " + groupId + " " + name);
        return request('POST', "groups/" + groupId + "/servers", false, {
            name: name,
            description: description,
            region: region
        });
    }
};
exports.Friends = {
    getUserFriends: function (userId) {
        logger.info("Get user friends");
        return requestPaged('GET', "friends/" + userId);
    },
    getFriends: function () {
        logger.info("Get friends");
        return requestPaged('GET', 'friends', 10);
    },
    getOutgoingRequests: function () {
        logger.info("Get outgoing friend requests");
        return requestPaged('GET', 'friends/requests/sent');
    },
    getFriendRequests: function () {
        logger.info("Get friend requests");
        return requestPaged('GET', 'friends/requests');
    },
    acceptFriendRequest: function (userId) {
        logger.info("Accept friend request");
        // return request('POST', `friends/requests/${userId}`);
        return exports.Friends.addFriend(userId);
    },
    addFriend: function (userId) {
        logger.info("Add friend");
        return request('POST', "friends/" + userId);
    },
    revokeFriendRequest: function (userId) {
        logger.info("Revoke friend request");
        return exports.Friends.removeFriend(userId);
    },
    rejectFriendRequest: function (userId) {
        logger.info("Reject friend request");
        return exports.Friends.removeFriend(userId);
    },
    removeFriend: function (userId) {
        logger.info("Remove friend");
        return request('DELETE', "friends/" + userId);
    }
};
exports.Users = {
    getInfo: function (userId) {
        logger.info("Get user " + userId);
        return request('GET', "users/" + userId);
    },
    register: function (username, passwordHash, email, referral) {
        if (referral === void 0) { referral = undefined; }
        logger.info("Register " + username);
        return requestNoLogin('POST', 'users', false, { username: username, password_hash: passwordHash, email: email, referral: referral });
    },
    getVerified: function () {
        logger.info("Get verified");
        return request('GET', "users/" + accessToken.UserId + "/verification")
            .then(function (result) {
            if (result) {
                accessToken.is_verified = true;
            }
            return result;
        });
    },
    requestVerificationEmail: function (email) {
        logger.info("Request verification");
        return request('PUT', "users/" + accessToken.UserId + "/verification", false, { email: email });
    },
    verify: function (token) {
        logger.info("Verify");
        return request('POST', "users/" + accessToken.UserId + "/verification", false, { verification_token: token });
    },
    changePassword: function (oldHash, newHash) {
        logger.info("Change password");
        return request('PUT', "users/" + accessToken.UserId + "/password", false, { old_password_hash: oldHash, new_password_hash: newHash });
    },
    resetPassword: function (userId, newHash, token) {
        logger.info("Reset password " + userId);
        return request('POST', "users/" + userId + "/password", false, { reset_token: token, new_password_hash: newHash });
    },
    changeUsername: function (username) {
        logger.info("Change username " + username);
        return request('PUT', "users/" + accessToken.UserId + "/username", false, { new_username: username });
    },
    findUserByUsername: function (username) {
        logger.info("Find user with username " + username);
        return request('POST', "users/search/username", false, { username: username });
    },
    getStatistics: function (userId) {
        logger.info("Getting Users statistics id: " + userId);
        return request('GET', "users/" + userId + "/statistics");
    },
};
exports.Meta = {
//No applicable methods
};
exports.Servers = {
    getRegions: function () {
        logger.info("Get regions");
        return requestNoLogin('GET', "servers/regions");
    },
    getFavorites: function () {
        logger.info("Getting favorite servers");
        return request('GET', 'servers/favorites');
    },
    addFavorite: function (serverId) {
        logger.info("Add favorite server " + serverId);
        return request('POST', "servers/favorites/" + serverId);
    },
    removeFavorite: function (serverId) {
        logger.info("Add favorite server " + serverId);
        return request('DELETE', "servers/favorites/" + serverId);
    },
    getRunning: function () {
        logger.info("Getting running servers");
        return request('GET', 'servers/running');
    },
    getOnline: function () {
        logger.info("Getting visible servers");
        return request('GET', 'servers/online');
    },
    getPublic: function () {
        logger.info("Getting public servers");
        return request('GET', 'servers/public');
    },
    getJoined: function () {
        logger.info("Getting joined servers");
        return request('GET', 'servers/joined');
    },
    getOpen: function () {
        logger.info("Getting open servers");
        return request('GET', 'servers/open');
    },
    getDetails: function (serverId) {
        logger.info("Getting server details " + serverId);
        return request('GET', "servers/" + serverId);
    },
    getControllable: function () {
        logger.info("Getting controllable");
        return request('GET', "servers/control");
    },
    joinConsole: function (id, should_launch, ignore_offline) {
        if (should_launch === void 0) { should_launch = false; }
        if (ignore_offline === void 0) { ignore_offline = false; }
        logger.info("Join console " + id);
        return request('POST', "servers/" + id + "/console", false, { should_launch: should_launch, ignore_offline: ignore_offline });
    }
};
exports.Services = {
    resetPassword: function (email) {
        logger.info("Reset password");
        return requestNoLogin('POST', "services/reset-password", false, { email: email });
    },
    getTemporaryIdentity: function (data) {
        logger.info("Get temp ID");
        return request('POST', 'services/identity-token', false, { user_data: data });
    }
};
exports.Shop = {
    getSandbox: function () {
        logger.info("Getting whether to use the sandbox");
        return request('GET', 'shop/sandbox');
        // {
        //     "sandbox": true
        // }
    },
    Account: {
        getProfile: function () {
            logger.info("Getting profile");
            return request('GET', 'shop/account');
            // {
            //     "shard_balance": 0,
            //     "wallet_amount": 0,
            //     "wallet_currency": "string",
            //     "subscription_status": 
            //      {
            //       "is_member": true,
            //       "member_end_date": "2019-01-31T03:48:29.902Z",
            //       "is_renewing": true
            //      }
            //   }
        },
        getPaymentMethods: function () {
            logger.info("Getting payment methods");
            return request('GET', 'shop/account/payments');
            // [
            //     {
            //       "type": "paypal",
            //       "id": 0,
            //       "name": "string",
            //       "payment_system": 
            //       {
            //         "id": 0,
            //         "name": "string"
            //       }
            //     }
            // ]
        },
        getItems: function () {
            logger.info("Getting account items");
            return request('GET', 'shop/account/items');
            // [
            //     {
            //       "image_url": "string",
            //       "quantity": 0,
            //       "id": 0,
            //       "sku": "string",
            //       "localized_name": "string",
            //       "enabled": true,
            //       "advertisement_type": "recommended",
            //       "virtual_currency_price": 0
            //     }
            // ]
        },
        getRewards: function () {
            logger.info("Getting account rewards");
            return request('GET', 'shop/account/rewards');
            // {
            //     "comment": "string",
            //     "rewards": 
            //      [
            //       {
            //         "type": "string",
            //         "amount": 0
            //       }
            //     ],
            //     "reward_periods_passed": 0
            // }
        },
        getSubscription: function () {
            logger.info("Getting supporter status");
            return request('GET', 'shop/account/subscription');
            // {
            //     "id": 0,
            //     "plan": {
            //       "id": 0,
            //       "external_id": "string",
            //       "group_id": "string",
            //       "project_id": "string",
            //       "name": {
            //         "en": "string"
            //       },
            //       "description": {
            //         "en": "string"
            //       },
            //       "localized_name": "string",
            //       "charge": {
            //         "amount": 0,
            //         "currency": "string",
            //         "period": {
            //           "value": 0,
            //           "type": "string"
            //         }
            //       },
            //       "expiration": {
            //         "value": 0,
            //         "type": "string"
            //       },
            //       "trial": {
            //         "value": 0,
            //         "type": "string"
            //       },
            //       "grace_period": {
            //         "value": 0,
            //         "type": "string"
            //       },
            //       "type": "string",
            //       "tags": [
            //         "string"
            //       ],
            //       "status": {
            //         "value": "disabled",
            //         "counters": {
            //           "active": 0,
            //           "canceled": 0,
            //           "expired": 0,
            //           "frozen": 0
            //         }
            //       }
            //     },
            //     "user": {
            //       "id": "string",
            //       "name": "string"
            //     },
            //     "product": {},
            //     "charge_amount": 0,
            //     "currency": "string",
            //     "date_create": "2019-01-31T03:51:29.364Z",
            //     "date_end": "2019-01-31T03:51:29.364Z",
            //     "date_next_charge": "2019-01-31T03:51:29.364Z",
            //     "date_last_charge": "2019-01-31T03:51:29.364Z",
            //     "status": "active",
            //     "comment": "string"
            // }
        },
        cancelSubscription: function () {
            return request('DELETE', 'shop/account/subscription');
        },
    },
    Debug: {
        modifyBalance: function (change) {
            return request('POST', 'shop/debug/balance', false, { change: change });
        },
        deleteMembership: function () {
            return request('DELETE', 'shop/debug/membership');
        },
        clearItems: function () {
            return request('DELETE', 'shop/debug/inventory');
        },
    },
    Categories: {
    //Unused
    },
    Items: {
        getItems: function () {
            logger.info("Get all items");
            return request('GET', 'shop/items');
            // [
            //     {
            //       "prices": {
            //         "USD": 0
            //       },
            //       "default_currency": "string",
            //       "permanent": true,
            //       "id": 0,
            //       "sku": "string",
            //       "localized_name": "string",
            //       "enabled": true,
            //       "advertisement_type": "recommended",
            //       "virtual_currency_price": 0
            //     }
            // ]
        },
        getInfo: memoizee_1.default(function (itemId) {
            logger.info("Get item info");
            return request('GET', "shop/items/" + itemId);
            // {
            //     "item_code": "string",
            //     "name": {
            //       "en": "string"
            //     },
            //     "description": {
            //       "en": "string"
            //     },
            //     "long_description": {
            //       "en": "string"
            //     },
            //     "image_url": "string",
            //     "item_type": "Consumable",
            //     "expiration": 0,
            //     "purchase_limit": 0,
            //     "keywords": {
            //       "en": [
            //         "string"
            //       ]
            //     },
            //     "groups": [
            //       0
            //     ],
            //     "deleted": true,
            //     "prices": {
            //       "USD": 0
            //     },
            //     "default_currency": "string",
            //     "permanent": true,
            //     "id": 0,
            //     "sku": "string",
            //     "localized_name": "string",
            //     "enabled": true,
            //     "advertisement_type": "recommended",
            //     "virtual_currency_price": 0
            // }
        }),
    },
    Sets: {
        getSet: memoizee_1.default(function (sku) {
            logger.info("Get set info");
            return request('GET', "shop/sets/" + sku);
            // {
            //     "sku": "string",
            //     "items": [
            //       {
            //         "identifier": 0,
            //         "sku": "string"
            //       }
            //     ]
            // }
        }),
    },
    Transactions: {
        getStatus: function (transactionId) {
            logger.info("Get Transaction ID " + transactionId);
            return request('GET', "shop/transactions/" + transactionId + "/status");
        },
    },
    Purchase: {
        Shards: {
            buyItem: function (itemId) {
                logger.info("Purchase item");
                return request('POST', 'shop/purchase/shards/items', false, { item_id: itemId });
            },
        },
        Premium: {
            buyItem: function (itemId) {
                logger.info("Purchase premium item");
                return request('POST', 'shop/purchase/premium/items', false, { item_id: itemId });
                // {
                //     "token": "string"
                // }
            },
            buySubscription: function (subscriptionId) {
                logger.info("Purchase subscription");
                return request('POST', 'shop/purchase/premium/subscriptions', false, { plan_external_id: subscriptionId });
                // {
                //     "token": "string"
                // }
            },
            buyShards: function (shardsId, quantity) {
                logger.info("Purchase currency " + shardsId + " " + quantity);
                return request('POST', 'shop/purchase/premium/shards', false, { shards_package_id: shardsId, quantity: quantity });
                // {
                //     "token": "string"
                // }
            },
            buyCoupon: function (shardsId, quantity) {
                logger.info("Purchase coupon " + shardsId + " " + quantity);
                return request('POST', 'shop/purchase/shards/coupons', false, { currency_package_id: shardsId, quantity: quantity });
                // {
                //     "transaction_id": number,
                //     "token": "string",
                // }
            },
        }
    },
    Coupons: {
        redeem: function (coupon) {
            logger.info("Redeem coupon");
            return request('POST', 'shop/coupons/redeem', false, { coupon: coupon });
            // {
            //     "coupon_code": "SCHMEECHEE-245WC-FNV85-DNRXE-BYQYK",
            //     "virtual_currency_amount": 1000,
            //     "virtual_items": []
            // }
        }
    },
    Subscriptions: {
        getSubscriptions: function () {
            logger.info("Get subscription options");
            return requestNoLogin('GET', 'shop/subscriptions');
            // [
            //     {
            //       "id": 0,
            //       "external_id": "string",
            //       "group_id": "string",
            //       "project_id": "string",
            //       "name": {
            //         "en": "string"
            //       },
            //       "description": {
            //         "en": "string"
            //       },
            //       "localized_name": "string",
            //       "charge": {
            //         "amount": 0,
            //         "currency": "string",
            //         "period": {
            //           "value": 0,
            //           "type": "string"
            //         }
            //       },
            //       "expiration": {
            //         "value": 0,
            //         "type": "string"
            //       },
            //       "trial": {
            //         "value": 0,
            //         "type": "string"
            //       },
            //       "grace_period": {
            //         "value": 0,
            //         "type": "string"
            //       },
            //       "type": "string",
            //       "tags": [
            //         "string"
            //       ],
            //       "status": {
            //         "value": "disabled",
            //         "counters": {
            //           "active": 0,
            //           "canceled": 0,
            //           "expired": 0,
            //           "frozen": 0
            //         }
            //       }
            //     }
            // ]
        },
    },
    Shards: {
        getPackages: function () {
            logger.info("Get currency packs");
            return request('GET', 'shop/shards');
            // {
            //     "id": 0,
            //     "vc_name": {
            //       "en": "string"
            //     },
            //     "base": {
            //       "USD": 0
            //     },
            //     "default_currency": "string",
            //     "min": 0,
            //     "max": 0,
            //     "is_currency_discrete": true,
            //     "allow_user_sum": true,
            //     "packets": {
            //       "additionalProp1": [
            //         {
            //           "amount": 0,
            //           "id": 0,
            //           "price": 0,
            //           "image_url": "string",
            //           "sku": "string",
            //           "description": {
            //             "en": "string"
            //           },
            //           "bonus": 0,
            //           "enabled": true
            //         }
            //       ],
            //       "additionalProp2": [
            //         {
            //           "amount": 0,
            //           "id": 0,
            //           "price": 0,
            //           "image_url": "string",
            //           "sku": "string",
            //           "description": {
            //             "en": "string"
            //           },
            //           "bonus": 0,
            //           "enabled": true
            //         }
            //       ],
            //       "additionalProp3": [
            //         {
            //           "amount": 0,
            //           "id": 0,
            //           "price": 0,
            //           "image_url": "string",
            //           "sku": "string",
            //           "description": {
            //             "en": "string"
            //           },
            //           "bonus": 0,
            //           "enabled": true
            //         }
            //       ]
            //     },
            //     "type": "string",
            //     "image_url": "string"
            // }
        },
    },
};
