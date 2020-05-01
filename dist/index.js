"use strict";
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
const request_promise_native_1 = __importDefault(require("request-promise-native"));
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const memoizee_1 = __importDefault(require("memoizee"));
const sha512_1 = __importDefault(require("crypto-js/sha512"));
const logger_1 = __importDefault(require("./logger"));
var appdata = path_1.default.join(process.env.APPDATA || "./", "Alta Launcher");
const publicBaseUrl = (name) => `https://967phuchye.execute-api.ap-southeast-2.amazonaws.com/${name}/api/`;
const localEndpoint = "http://localhost:13490/api/";
function getEndpoint(name) {
    switch (name) {
        case "dev":
        case "prod":
        case "test":
        case "latest":
            return publicBaseUrl(name);
        case "local":
            return localEndpoint;
    }
}
const DEV = "dev";
const PROD = "prod";
const TEST = "test";
const LATEST = "latest";
const LOCAL = "local";
//Change here
let currentEndpoint = getEndpoint(PROD);
//Reject Unauthorized Setting
let rejectUnauthorized = true;
let loggingLevel = 0;
var refreshPromise;
exports.setEndpoint = (endpoint) => {
    console.log("SETTING ENDPOINT TO " + endpoint);
    currentEndpoint = getEndpoint(endpoint);
};
exports.getRejectUnauthorized = () => rejectUnauthorized;
const hasFs = !!fs_1.default.existsSync;
if (process.env.APPDATA != undefined) {
    var settingsFile = path_1.default.join(process.env.APPDATA, "Alta Launcher", "Settings.json");
    console.log("Couldn't find Settings file to check rejectUnauthorized");
    if (fs_1.default.existsSync(settingsFile)) {
        var settings = JSON.parse(fs_1.default.readFileSync(settingsFile, "utf8"));
        rejectUnauthorized = !!settings.rejectUnauthorized;
        loggingLevel = settings.jsapiLoggingLevel || 0;
        if (!!settings.apiEndpoint) {
            exports.setEndpoint(settings.apiEndpoint);
        }
        console.log("rejectUnauthorized: " + rejectUnauthorized);
        console.log("jsapi logging level: " + loggingLevel);
    }
}
else {
    console.info("Couldn't find APPDATA to check rejectUnauthorized");
}
console.log("jsapi endpoint: " + currentEndpoint);
const logger = logger_1.default("WEBAPI", loggingLevel);
let isOffline = false;
let accessToken;
let refreshToken;
let identityToken;
let accessString;
let refreshString;
let identityString;
let cookies;
let headers = {
    "Content-Type": "application/json",
    "x-api-key": "2l6aQGoNes8EHb94qMhqQ5m2iaiOM9666oDTPORf",
    Authorization: "",
    "User-Agent": "Unknown",
};
function setVersion(version) {
    headers["User-Agent"] = "Launcher/" + version;
}
exports.setVersion = setVersion;
function setUserAgent(userAgent) {
    headers["User-Agent"] = userAgent;
}
exports.setUserAgent = setUserAgent;
function requestNoLogin(method, path, isCached = false, body = undefined) {
    logger.info("NO LOGIN: " + method + " " + path);
    if (isOffline) {
        throw new Error("Unsupported in offline mode: " + path);
    }
    return request_promise_native_1.default({
        url: currentEndpoint + path,
        method,
        headers,
        body: JSON.stringify(body),
        rejectUnauthorized,
    }).then((response) => JSON.parse(response));
}
function request(method, path, isCached = false, body = undefined) {
    logger.info(method + " " + path);
    if (isOffline) {
        throw new Error("Unsupported in offline mode: " + path);
    }
    return (updateTokens()
        //TODO: Remove the limit
        .then(() => request_promise_native_1.default({
        url: currentEndpoint + path,
        method,
        headers,
        body: JSON.stringify(body),
        rejectUnauthorized,
        qs: { limit: 20 },
    }))
        .then((response) => {
        try {
            return JSON.parse(response);
        }
        catch (error) {
            logger.info("Failed to parse response to " + path + " : " + response);
        }
    }));
}
function requestPaged(method, path, limit = undefined, isCached = false, body = undefined) {
    return __asyncGenerator(this, arguments, function* requestPaged_1() {
        logger.info(method + " " + path);
        if (isOffline) {
            throw new Error("Unsupported in offline mode: " + path);
        }
        yield __await(updateTokens());
        var lastToken = undefined;
        while (true) {
            try {
                var jsonBody = JSON.stringify(body);
                var response = yield __await(request_promise_native_1.default({
                    url: currentEndpoint + path,
                    method,
                    headers,
                    body: jsonBody,
                    rejectUnauthorized,
                    resolveWithFullResponse: true,
                    qs: { paginationToken: lastToken, limit },
                }));
            }
            catch (error) {
                console.error("Error in pagination");
                console.error(error);
                throw error;
            }
            lastToken = response.headers.paginationtoken;
            try {
                yield yield __await(JSON.parse(response.body));
            }
            catch (error) {
                logger.info("Failed to parse response to " + path + " : " + response.body);
                throw error;
            }
            if (!lastToken) {
                break;
            }
        }
    });
}
function requestRefresh(method, path, isCached = false, body = undefined) {
    if (isOffline) {
        throw new Error("Unsupported in offline mode: " + path);
    }
    if (!!refreshString) {
        headers = Object.assign(Object.assign({}, headers), { Authorization: "Bearer " + refreshString });
    }
    return request_promise_native_1.default({
        url: currentEndpoint + path,
        method,
        headers,
        body: JSON.stringify(body),
        rejectUnauthorized,
    }).then((response) => JSON.parse(response));
}
function updateTokens() {
    if (!!refreshPromise) {
        logger.info("Awaiting current refresh promise");
        return refreshPromise;
    }
    if (!accessToken || accessToken.exp - new Date().getTime() / 1000 < 15) {
        logger.info("Requiring refresh");
        refreshPromise = exports.Sessions.refreshSession().then(() => (refreshPromise = undefined));
        return refreshPromise;
    }
    else {
        logger.info("Access token valid");
        return Promise.resolve();
    }
}
exports.Sessions = {
    ensureLoggedIn: () => new Promise((resolve, reject) => {
        if (!accessToken && !refreshString) {
            reject(new Error("Not logged in"));
        }
        else {
            updateTokens()
                .then(() => !!accessToken ? resolve() : reject(new Error("Not logged in")))
                .catch(reject);
        }
    }),
    getUserId: () => !!accessToken && accessToken.UserId,
    getVerified: () => !!accessToken &&
        (accessToken.is_verified || accessToken.is_verified === "True"),
    getUsername: () => !!accessToken && accessToken.Username,
    getSupporter: () => exports.Sessions.getPolicy("supporter"),
    getPolicy: (policy) => !!accessToken && accessToken.Policy.some((item) => item === policy),
    getPolicies: () => !!accessToken && accessToken.Policy,
    connectToCookies(providedCookies) {
        cookies = providedCookies;
        exports.Sessions.setLocalTokens({
            refresh_token: cookies.get("refresh_token"),
            access_token: cookies.get("access_token"),
            identity_token: cookies.get("identity_token"),
        });
    },
    getLocalTokens: () => {
        return {
            access_token: accessString,
            refresh_token: refreshString,
            identity_token: identityString,
        };
    },
    setLocalTokens: (tokens) => {
        logger.info("Setting local tokens");
        if (!!tokens.access_token && accessString != tokens.access_token) {
            accessString = tokens.access_token;
            headers.Authorization = "Bearer " + accessString;
            accessToken = jsonwebtoken_1.default.decode(accessString);
            cookies && cookies.set("access_token", accessString, { path: "/" });
        }
        if (!!tokens.refresh_token && refreshString != tokens.refresh_token) {
            refreshString = tokens.refresh_token;
            refreshToken = jsonwebtoken_1.default.decode(refreshString);
        }
        if (!!tokens.identity_token && identityString != tokens.identity_token) {
            identityString = tokens.identity_token;
            identityToken = jsonwebtoken_1.default.decode(identityString);
            cookies && cookies.set("identity_token", identityString, { path: "/" });
        }
    },
    logout: () => {
        logger.info("Logging out");
        if (!!cookies) {
            cookies.remove("refresh_token", { path: "/" });
            cookies.remove("access_token", { path: "/" });
            cookies.remove("identity_token", { path: "/" });
        }
        identityString = undefined;
        refreshString = undefined;
        accessString = undefined;
        identityToken = undefined;
        refreshToken = undefined;
        accessToken = undefined;
    },
    loginOffline: (username) => {
        logger.info("Login offline " + username);
        var refresh = {
            UserId: "0",
            role: "Refresh",
            exp: 9999999999,
            iss: "AltaWebAPI",
            aud: "AltaClient",
        };
        var access = {
            UserId: "0",
            Username: "OFFLINE " + username,
            role: "Access",
            is_verified: "True",
            is_member: "True",
            Policy: [
                "offline",
                "database_admin",
                "admin_vr_modes",
                "debug_features",
                "game_access_development",
                "play_offline",
                "server_access_development",
                "server_owner",
                "game_access_public",
                "server_access_pre_alpha",
                "server_access_tutorial",
                "server_create_development",
                "game_access_testing",
                "reuse_refresh_tokens",
                "server_access_testing",
            ],
            exp: 9999999999,
            iss: "AltaWebAPI",
            aud: "AltaClient",
        };
        var identity = {
            UserId: "0",
            Username: "OFFLINE " + username,
            role: "Identity",
            is_member: "True",
            is_dev: "True",
            exp: 9999999999,
            iss: "AltaWebAPI",
            aud: "AltaClient",
        };
        exports.Sessions.setLocalTokens({
            refresh_token: jsonwebtoken_1.default.sign(refresh, "offline"),
            access_token: jsonwebtoken_1.default.sign(access, "offline"),
            identity_token: jsonwebtoken_1.default.sign(identity, "offline"),
        });
        return Promise.resolve();
    },
    hashPassword: (password) => {
        return sha512_1.default(password).toString();
    },
    loginWithUsername: (username, passwordHash) => {
        logger.info("Login " + username);
        if (isOffline) {
            return exports.Sessions.loginOffline(username);
        }
        return requestNoLogin("POST", "sessions", false, {
            username,
            password_hash: passwordHash,
        })
            .then((result) => exports.Sessions.setLocalTokens(result))
            .catch((error) => {
            logger.info("Error logging in");
            logger.info(JSON.stringify(headers));
            throw error;
        });
    },
    loginWithEmail: (email, passwordHash) => {
        logger.info("Login with email");
        if (isOffline) {
            return exports.Sessions.loginOffline(email);
        }
        return requestNoLogin("POST", "sessions/email", false, {
            email,
            password_hash: passwordHash,
        })
            .then((result) => exports.Sessions.setLocalTokens(result))
            .catch((error) => {
            logger.info("Error logging in");
            logger.info(JSON.stringify(headers));
            throw error;
        });
    },
    loginWithRefreshToken: (refreshToken) => {
        if (!refreshToken || refreshToken.includes("\u0000")) {
            throw new Error("Invalid refresh token");
        }
        logger.info("Login with refresh");
        if (isOffline) {
            return exports.Sessions.loginOffline("refresh");
        }
        refreshString = refreshToken;
        return exports.Sessions.refreshSession();
    },
    checkRemembered: () => {
        logger.info("Check remembered");
        try {
            if (hasFs) {
                if (!fs_1.default.existsSync(appdata)) {
                    fs_1.default.mkdirSync(appdata, { recursive: true });
                }
                var rememberPath = path_1.default.join(appdata, ".rememberme");
                if (fs_1.default.existsSync(rememberPath)) {
                    var content = fs_1.default.readFileSync(rememberPath, "utf8");
                    return exports.Sessions.loginWithRefreshToken(content);
                }
            }
        }
        catch (error) {
            console.error("Error while checking remembered. See below.");
            console.error(error);
        }
        return Promise.resolve();
    },
    remember: () => {
        logger.info("Remember");
        cookies && cookies.set("refresh_token", refreshString, { path: "/" });
        if (hasFs) {
            if (!fs_1.default.existsSync(appdata)) {
                fs_1.default.mkdirSync(appdata, { recursive: true });
            }
            var rememberPath = path_1.default.join(appdata, ".rememberme");
            fs_1.default.writeFileSync(rememberPath, refreshString, "utf8");
        }
    },
    forget: () => {
        logger.info("Forget");
        if (!!cookies) {
            cookies.remove("refresh_token", { path: "/" });
        }
        var rememberPath = path_1.default.join(appdata, ".rememberme");
        if (hasFs && fs_1.default.existsSync(rememberPath)) {
            fs_1.default.unlinkSync(rememberPath);
        }
    },
    refreshSession: () => {
        logger.info("Refreshing session");
        return requestRefresh("PUT", "sessions", false, {}).then((result) => exports.Sessions.setLocalTokens(result));
    },
};
var BanType;
(function (BanType) {
    BanType[BanType["Server"] = 0] = "Server";
    BanType[BanType["Global"] = 1] = "Global";
    BanType[BanType["Public"] = 2] = "Public";
})(BanType = exports.BanType || (exports.BanType = {}));
var BanMethod;
(function (BanMethod) {
    BanMethod[BanMethod["UserId"] = 1] = "UserId";
    BanMethod[BanMethod["IpAddress"] = 2] = "IpAddress";
    BanMethod[BanMethod["DeviceId"] = 4] = "DeviceId";
})(BanMethod = exports.BanMethod || (exports.BanMethod = {}));
exports.Bans = {
    createBan: (user_id, duration_hours, type, method, reason, servers) => {
        logger.info(`Creating ban ${user_id}`);
        return request("POST", "bans", false, {
            user_id,
            duration_hours,
            type,
            method,
            reason,
            servers,
        });
    },
    deleteBan: (banId) => {
        logger.info(`Delete ban by ID`);
        return request("DELETE", `bans/${banId}`);
    },
    getBan: (banId) => {
        logger.info(`Get ban by ID`);
        return request("GET", `bans/${banId}`);
    },
    getAll: () => {
        logger.info(`Get all banned`);
        return request("GET", `bans`);
    },
    getModBans: (modId) => {
        logger.info(`Get bans from ${modId}`);
        return request("GET", `bans/creator/${modId}`);
    },
    getUserBans: (userId) => {
        logger.info(`Get bans for ${userId}`);
        return request("GET", `bans/user/${userId}`);
    },
};
exports.Launcher = {
    getGames: () => {
        logger.info("Get games");
        return request("GET", "launcher/games");
    },
    getGameInfo: (gameId) => {
        logger.info("Get game info");
        return request("GET", `launcher/games/${gameId}`);
    },
};
var GroupType;
(function (GroupType) {
    GroupType[GroupType["Open"] = 0] = "Open";
    GroupType[GroupType["Public"] = 1] = "Public";
    GroupType[GroupType["Private"] = 2] = "Private";
})(GroupType = exports.GroupType || (exports.GroupType = {}));
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
    getJoined: () => {
        logger.info("Get joined groups");
        return requestPaged("GET", "groups/joined");
    },
    getVisible: (type) => {
        logger.info("Get visible groups");
        return requestPaged("GET", `groups?type=${type}`);
    },
    getInvited: () => {
        logger.info("Get invited to groups");
        return requestPaged("GET", "groups/invites");
    },
    getRequested: () => {
        logger.info("Get requested groups");
        return requestPaged("GET", "groups/requested");
    },
    createGroup: (name, description) => {
        logger.info("Create group");
        return request("POST", "groups", false, {
            type: exports.Groups.Private,
            description,
            Name: name,
            invite_permissions: exports.Groups.ModeratorUp,
            kick_permissions: exports.Groups.ModeratorUp,
            accept_member_permissions: exports.Groups.ModeratorUp,
            create_server_permissions: exports.Groups.Admin,
        });
    },
    getGroupInfo: (groupId) => {
        logger.info(`Get group info ${groupId}`);
        return request("GET", `groups/${groupId}`);
    },
    editGroupInfo: (groupId, groupInfo) => {
        logger.info(`Patch group info ${groupId}`);
        return request("PATCH", `groups/${groupId}`, false, groupInfo);
    },
    editGroupRole: (groupId, roleId, newInfo) => {
        logger.info(`Put group role ${groupId} ${roleId}`);
        return request("PUT", `groups/${groupId}/roles/${roleId}`, false, newInfo);
    },
    getMembers: (groupId) => {
        logger.info(`Get members ${groupId}`);
        return requestPaged("GET", `groups/${groupId}/members`);
    },
    getBans: (groupId) => {
        logger.info(`Get banned ${groupId}`);
        return requestPaged("GET", `groups/${groupId}/bans`);
    },
    banUser: (groupId, userId) => {
        logger.info(`Ban user ${groupId} ${userId}`);
        return request("POST", `groups/${groupId}/bans/${userId}`);
    },
    unbanUser: (groupId, userId) => {
        logger.info(`Unban user ${groupId} ${userId}`);
        return request("DELETE", `groups/${groupId}/bans/${userId}`);
    },
    getMemberInfo: (groupId, userId) => {
        logger.info(`Get member permissions ${groupId} ${userId}`);
        return request("GET", `groups/${groupId}/members/${userId}`);
    },
    getJoinRequests: (groupId) => {
        logger.info(`Get join requests ${groupId}`);
        return requestPaged("GET", `groups/${groupId}/requests`);
    },
    getOutgoingInvites: (groupId) => {
        logger.info(`Get outgoing invites ${groupId}`);
        return requestPaged("GET", `groups/${groupId}/invites`);
    },
    requestJoin: (groupId) => {
        logger.info(`Request join ${groupId}`);
        return request("POST", `groups/${groupId}/requests`);
    },
    revokeRequest: (groupId) => {
        logger.info(`Revoke request ${groupId}`);
        return request("DELETE", `groups/${groupId}/requests`);
    },
    acceptInvite: (groupId) => {
        logger.info(`Accept invite ${groupId}`);
        return request("POST", `groups/invites/${groupId}`);
    },
    rejectInvite: (groupId) => {
        logger.info(`Reject invite ${groupId}`);
        return request("DELETE", `groups/invites/${groupId}`);
    },
    leave: (groupId) => {
        logger.info(`Leave ${groupId}`);
        return request("DELETE", `groups/${groupId}/members`);
    },
    inviteMember: (groupId, userId) => {
        logger.info(`Invite member ${groupId} ${userId}`);
        return request("POST", `groups/${groupId}/invites/${userId}`);
    },
    revokeInvite: (groupId, userId) => {
        logger.info(`Revoke invite ${groupId} ${userId}`);
        return request("DELETE", `groups/${groupId}/invites/${userId}`);
    },
    acceptRequest: (groupId, userId) => {
        logger.info(`Accept request ${groupId} ${userId}`);
        return request("PUT", `groups/${groupId}/requests/${userId}`);
    },
    rejectRequest: (groupId, userId) => {
        logger.info(`Reject request ${groupId} ${userId}`);
        return request("DELETE", `groups/${groupId}/requests/${userId}`);
    },
    kickMember: (groupId, userId) => {
        logger.info(`Invite member ${groupId} ${userId}`);
        return request("DELETE", `groups/${groupId}/members/${userId}`);
    },
    //OBSOLETE
    editPermissions: (groupId, userId, permissions) => {
        logger.info(`Edit member permissions ${groupId} ${userId}`);
        return request("POST", `groups/${groupId}/members/${userId}/permissions`, false, {
            permissions,
        });
    },
    setMemberRole: (groupId, userId, roleId) => {
        logger.info(`Edit member role ${groupId} ${userId} ${roleId}`);
        return request("POST", `groups/${groupId}/members/${userId}/role/${roleId}`);
    },
    createServer: (groupId, name, description, region) => {
        logger.info(`Create server ${groupId} ${name}`);
        return request("POST", `groups/${groupId}/servers`, false, {
            name,
            description,
            region,
        });
    },
};
exports.Security = {
    sso: () => {
        return request("GET", "Security/sso");
    },
};
exports.Analytics = {
    sendInstallation: (type, version_from, version_to, error, start_id) => {
        return request("POST", "analytics/installation", false, {
            type,
            version_from,
            version_to,
            error,
            start_id,
        });
    },
};
exports.Friends = {
    getUserFriends: (userId) => {
        logger.info("Get user friends");
        return requestPaged("GET", `friends/${userId}`);
    },
    getFriends: () => {
        logger.info("Get friends");
        return requestPaged("GET", "friends", 10);
    },
    getOutgoingRequests: () => {
        logger.info("Get outgoing friend requests");
        return requestPaged("GET", "friends/requests/sent");
    },
    getFriendRequests: () => {
        logger.info("Get friend requests");
        return requestPaged("GET", "friends/requests");
    },
    acceptFriendRequest: (userId) => {
        logger.info("Accept friend request");
        // return request('POST', `friends/requests/${userId}`);
        return exports.Friends.addFriend(userId);
    },
    addFriend: (userId) => {
        logger.info("Add friend");
        return request("POST", `friends/${userId}`);
    },
    revokeFriendRequest: (userId) => {
        logger.info("Revoke friend request");
        return exports.Friends.removeFriend(userId);
    },
    rejectFriendRequest: (userId) => {
        logger.info("Reject friend request");
        return exports.Friends.removeFriend(userId);
    },
    removeFriend: (userId) => {
        logger.info("Remove friend");
        return request("DELETE", `friends/${userId}`);
    },
};
exports.Users = {
    getInfo: memoizee_1.default((userId) => {
        logger.info("Get user " + userId);
        return request("GET", `users/${userId}`);
    }),
    register: (username, passwordHash, email, referral = undefined) => {
        logger.info("Register " + username);
        return requestNoLogin("POST", "users", false, {
            username,
            password_hash: passwordHash,
            email,
            referral,
        });
    },
    getVerified: () => {
        logger.info("Get verified");
        return request("GET", `users/${accessToken.UserId}/verification`).then((result) => {
            if (result) {
                accessToken.is_verified = true;
            }
            return result;
        });
    },
    requestVerificationEmail: (email) => {
        logger.info("Request verification");
        return request("PUT", `users/${accessToken.UserId}/verification`, false, {
            email,
        });
    },
    verify: (userId, token) => {
        logger.info("Verify");
        return requestNoLogin("POST", `users/${userId}/verification`, false, {
            verification_token: token,
        });
    },
    changeUsername: (username, passHash) => {
        logger.info("Change username");
        return request(`PUT`, `users/me/username`, false, {
            new_username: username,
            password_hash: passHash,
        });
    },
    changePassword: (oldHash, newHash) => {
        logger.info("Change password");
        return request("PUT", `users/${accessToken.UserId}/password`, false, {
            old_password_hash: oldHash,
            new_password_hash: newHash,
        });
    },
    resetPassword: (userId, newHash, token) => {
        logger.info("Reset password " + userId);
        return requestNoLogin("POST", `users/${userId}/password`, false, {
            reset_token: token,
            new_password_hash: newHash,
        });
    },
    findUserByUsername: (username) => {
        logger.info("Find user with username " + username);
        return request("POST", `users/search/username`, false, { username });
    },
    getStatistics: (userId) => {
        logger.info("Getting Users statistics id: " + userId);
        return request("GET", `users/${userId}/statistics`);
    },
};
exports.Meta = {
//No applicable methods
};
exports.Servers = {
    getAll: memoizee_1.default(() => {
        logger.info("Getting all servers");
        return request("GET", `servers`);
    }),
    getRegions: () => {
        logger.info("Get regions");
        return requestNoLogin("GET", `servers/regions`);
    },
    getConsoleServers: () => {
        logger.info("Getting console servers");
        return request("GET", "servers/console");
    },
    getFavorites: () => {
        logger.info("Getting favorite servers");
        return request("GET", "servers/favorites");
    },
    addFavorite: (serverId) => {
        logger.info(`Add favorite server ${serverId}`);
        return request("POST", `servers/favorites/${serverId}`);
    },
    removeFavorite: (serverId) => {
        logger.info(`Add favorite server ${serverId}`);
        return request("DELETE", `servers/favorites/${serverId}`);
    },
    getRunning: () => {
        logger.info("Getting running servers");
        return request("GET", "servers/running");
    },
    getOnline: () => {
        logger.info("Getting visible servers");
        return request("GET", "servers/online");
    },
    getPublic: () => {
        logger.info("Getting public servers");
        return request("GET", "servers/public");
    },
    getJoined: () => {
        logger.info("Getting joined servers");
        return request("GET", "servers/joined");
    },
    getOpen: () => {
        logger.info("Getting open servers");
        return request("GET", "servers/open");
    },
    getDetails: (serverId) => {
        logger.info(`Getting server details ${serverId}`);
        return request("GET", `servers/${serverId}`);
    },
    getControllable: () => {
        logger.info(`Getting controllable`);
        return request("GET", `servers/control`);
    },
    joinConsole: (id, should_launch = false, ignore_offline = false) => {
        logger.info(`Join console ${id}`);
        return request("POST", `servers/${id}/console`, false, {
            should_launch,
            ignore_offline,
        });
    },
};
exports.Services = {
    resetPassword: (email) => {
        logger.info("Reset password");
        return requestNoLogin("POST", `services/reset-password`, false, { email });
    },
    getTemporaryIdentity: (data) => {
        logger.info("Get temp ID");
        return request("POST", "services/identity-token", false, {
            user_data: data,
        });
    },
};
var UserReportStatus;
(function (UserReportStatus) {
    UserReportStatus[UserReportStatus["Unprocessed"] = 1] = "Unprocessed";
    UserReportStatus[UserReportStatus["AwaitingReply"] = 2] = "AwaitingReply";
    UserReportStatus[UserReportStatus["Resolved"] = 4] = "Resolved";
    UserReportStatus[UserReportStatus["Rejected"] = 8] = "Rejected";
})(UserReportStatus = exports.UserReportStatus || (exports.UserReportStatus = {}));
var UserReportType;
(function (UserReportType) {
    UserReportType[UserReportType["UserReport"] = 0] = "UserReport";
    UserReportType[UserReportType["LostItems"] = 1] = "LostItems";
    UserReportType[UserReportType["TempBan"] = 2] = "TempBan";
    UserReportType[UserReportType["PermaBan"] = 3] = "PermaBan";
    UserReportType[UserReportType["Warning"] = 4] = "Warning";
    UserReportType[UserReportType["Note"] = 5] = "Note";
})(UserReportType = exports.UserReportType || (exports.UserReportType = {}));
exports.UserReports = {
    getUserReports: (status, user_ids = undefined) => {
        logger.info("Get user reports");
        return requestPaged("GET", `userReports?status=${status}${!user_ids ? "" : `&user_ids=${user_ids.join()}`}`);
    },
    getTopicReports: (status, user_ids = undefined) => {
        logger.info("Get topic reports");
        return requestPaged("GET", `userReports/topic?status=${status}${!user_ids ? "" : `&user_ids=${user_ids.join()}`}`);
    },
    getAssigneeReports: (status, user_ids = undefined) => {
        logger.info("Get assignee reports");
        return requestPaged("GET", `userReports/assignee?status=${status}${!user_ids ? "" : `&user_ids=${user_ids.join()}`}`);
    },
    submitReport: (report) => {
        logger.info("Submit report");
        return request("POST", "userReports", false, report);
    },
};
exports.Shop = {
    getSandbox: () => {
        logger.info("Getting whether to use the sandbox");
        return request("GET", "shop/sandbox");
        // {
        //     "sandbox": true
        // }
    },
    Account: {
        getProfile: () => {
            logger.info("Getting profile");
            return request("GET", "shop/account");
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
        getPaymentMethods: () => {
            logger.info("Getting payment methods");
            return request("GET", "shop/account/payments");
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
        getItems: () => {
            logger.info("Getting account items");
            return request("GET", "shop/account/items");
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
        getRewards: () => {
            logger.info("Getting account rewards");
            return request("GET", "shop/account/rewards");
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
        getSubscription: () => {
            logger.info("Getting supporter status");
            return request("GET", "shop/account/subscription");
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
        cancelSubscription: () => {
            return request("DELETE", "shop/account/subscription");
        },
    },
    Debug: {
        modifyBalance: (change) => {
            return request("POST", "shop/debug/balance", false, { change });
        },
        deleteMembership: () => {
            return request("DELETE", "shop/debug/membership");
        },
        clearItems: () => {
            return request("DELETE", "shop/debug/inventory");
        },
    },
    Categories: {
    //Unused
    },
    Items: {
        getItems: () => {
            logger.info("Get all items");
            return request("GET", "shop/items");
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
        getInfo: memoizee_1.default((itemId) => {
            logger.info("Get item info");
            return request("GET", `shop/items/${itemId}`);
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
        getSet: memoizee_1.default((sku) => {
            logger.info("Get set info");
            return request("GET", `shop/sets/${sku}`);
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
        getStatus: (transactionId) => {
            logger.info("Get Transaction ID " + transactionId);
            return request("GET", `shop/transactions/${transactionId}/status`);
        },
    },
    Purchase: {
        Shards: {
            buyItem: (itemId) => {
                logger.info("Purchase item");
                return request("POST", "shop/purchase/shards/items", false, {
                    item_id: itemId,
                });
            },
        },
        Premium: {
            buyItem: (itemId) => {
                logger.info("Purchase premium item");
                return request("POST", "shop/purchase/premium/items", false, {
                    item_id: itemId,
                });
                // {
                //     "token": "string"
                // }
            },
            buySubscription: (subscriptionId) => {
                logger.info("Purchase subscription");
                return request("POST", "shop/purchase/premium/subscriptions", false, {
                    plan_external_id: subscriptionId,
                });
                // {
                //     "token": "string"
                // }
            },
            buyShards: (shardsId, quantity) => {
                logger.info("Purchase currency " + shardsId + " " + quantity);
                return request("POST", "shop/purchase/premium/shards", false, {
                    shards_package_id: shardsId,
                    quantity,
                });
                // {
                //     "token": "string"
                // }
            },
            buyCoupon: (shardsId, quantity) => {
                logger.info("Purchase coupon " + shardsId + " " + quantity);
                return request("POST", "shop/purchase/shards/coupons", false, {
                    currency_package_id: shardsId,
                    quantity,
                });
                // {
                //     "transaction_id": number,
                //     "token": "string",
                // }
            },
        },
    },
    Coupons: {
        redeem: (coupon) => {
            logger.info("Redeem coupon");
            return request("POST", "shop/coupons/redeem", false, { coupon });
            // {
            //     "coupon_code": "SCHMEECHEE-245WC-FNV85-DNRXE-BYQYK",
            //     "virtual_currency_amount": 1000,
            //     "virtual_items": []
            // }
        },
    },
    Subscriptions: {
        getSubscriptions: () => {
            logger.info("Get subscription options");
            return requestNoLogin("GET", "shop/subscriptions");
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
        getPackages: () => {
            logger.info("Get currency packs");
            return request("GET", "shop/shards");
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
