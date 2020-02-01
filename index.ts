import rp from 'request-promise-native';

import path from 'path';
import fs from 'fs';

import jwt from 'jsonwebtoken';

import memoizee from 'memoizee';
import sha512 from 'crypto-js/sha512';

import customLogger from './logger';

var appdata = path.join(process.env.APPDATA || "./", 'Alta Launcher');

const publicBaseUrl = (name:String) => `https://967phuchye.execute-api.ap-southeast-2.amazonaws.com/${name}/api/`;
const localEndpoint = "http://localhost:13490/api/";

function getEndpoint(name:String) 
{
    switch (name)
    {
        case 'dev':
        case 'prod':
        case 'test':
        case 'latest':
            return publicBaseUrl(name);
        
        case 'local':
            return localEndpoint;
    }
}

const DEV = 'dev';
const PROD = 'prod';
const TEST = 'test';
const LATEST = 'latest';
const LOCAL = 'local';

//Change here
let currentEndpoint = getEndpoint(PROD);

//Reject Unauthorized Setting
let rejectUnauthorized = true;
let loggingLevel = 0;

var refreshPromise:Promise<void>|undefined;

export const setEndpoint = (endpoint:string) =>
{
    console.log("SETTING ENDPOINT TO " + endpoint);
    currentEndpoint = getEndpoint(endpoint);
};

export const getRejectUnauthorized = () => rejectUnauthorized;

if (process.env.APPDATA != undefined)
{
    var settingsFile = path.join(process.env.APPDATA, 'Alta Launcher', 'Settings.json');

    console.log("Couldn't find Settings file to check rejectUnauthorized");

    if (fs.existsSync(settingsFile))
    {
        var settings = JSON.parse(fs.readFileSync(settingsFile, "utf8"));
        rejectUnauthorized = !!settings.rejectUnauthorized;
        loggingLevel = settings.jsapiLoggingLevel || 0;
        
        if (!!settings.apiEndpoint) 
        {
            setEndpoint(settings.apiEndpoint);
        }
        
        console.log("rejectUnauthorized: " + rejectUnauthorized);
        console.log("jsapi logging level: " + loggingLevel)
    }
}
else
{
    console.info("Couldn't find APPDATA to check rejectUnauthorized");
}

console.log("jsapi endpoint: " + currentEndpoint)

const logger = customLogger('WEBAPI', loggingLevel);

let isOffline:boolean = false;

let accessToken: any;
let refreshToken: any;
let identityToken: any;

let accessString: string | undefined;
let refreshString: string | undefined;
let identityString: string | undefined;
let cookies: any;

type Tokens =
{
    refresh_token: string;
    access_token: string;
    identity_token: string;
}

let headers =
{
    "Content-Type": "application/json",
    'x-api-key': '2l6aQGoNes8EHb94qMhqQ5m2iaiOM9666oDTPORf',
    'Authorization': '',
    'User-Agent': 'Unknown'
};

export function setVersion(version:string)
{
    headers['User-Agent'] = 'Launcher/' + version;
}

export function setUserAgent(userAgent:string)
{
    headers['User-Agent'] = userAgent;
}

function requestNoLogin(method: string, path: string, isCached: boolean = false, body: object | undefined = undefined)
{
    logger.info("NO LOGIN: " + method + " " + path);

    if (isOffline)
    {
        throw new Error("Unsupported in offline mode: " + path);
    }

    return rp({url: currentEndpoint + path, method, headers, body:JSON.stringify(body), rejectUnauthorized})
    .then((response:string) => JSON.parse(response));
}

function request(method: string, path: string, isCached: boolean = false, body: object | undefined = undefined)
{
    logger.info(method + " " + path);

    if (isOffline)
    {
        throw new Error("Unsupported in offline mode: " + path);
    }

    return updateTokens()
    //TODO: Remove the limit
    .then(() => rp({url: currentEndpoint + path, method, headers, body:JSON.stringify(body), rejectUnauthorized, qs:{limit:20}}))
    .then((response:string) => { try { return JSON.parse(response); } catch (error) { logger.info("Failed to parse response to " + path + " : " + response); } });
}

async function * requestPaged(method: string, path: string, limit:number|undefined = undefined, isCached: boolean = false, body: object | undefined = undefined)
{
    logger.info(method + " " + path);

    if (isOffline)
    {
        throw new Error("Unsupported in offline mode: " + path);
    }

    await updateTokens();

    var lastToken = undefined;

    while (true)
    {
        try
        {
            var jsonBody = JSON.stringify(body);
            
            var response:any = await rp({url: currentEndpoint + path, method, headers, body:jsonBody, rejectUnauthorized, resolveWithFullResponse:true, qs:{paginationToken:lastToken, limit}});
        }
        catch (error)
        {
            console.error("Error in pagination");
            console.error(error);

            throw error;
        }

        lastToken = response.headers.paginationtoken;

        try 
        { 
            yield JSON.parse(response.body); 
        } 
        catch (error) 
        {
            logger.info("Failed to parse response to " + path + " : " + response.body); 
            throw error;
        } 

        if (!lastToken)
        {
            break;
        }
    }
}

function requestRefresh(method: string, path: string, isCached: boolean = false, body: object | undefined = undefined) : Promise<Tokens>
{
    if (isOffline)
    {
        throw new Error("Unsupported in offline mode: " + path);
    }

    if (!!refreshString)
    {
        headers = { ...headers, Authorization: "Bearer " + refreshString };
    }

    return rp({url: currentEndpoint + path, method, headers, body:JSON.stringify(body), rejectUnauthorized})
    .then((response:string) => JSON.parse(response));
}

function updateTokens()
{
    if (!!refreshPromise)
    {
        logger.info("Awaiting current refresh promise");
        return refreshPromise;
    }

    if (!accessToken || accessToken.exp - (new Date().getTime() / 1000) < 15)
    {
        logger.info("Requiring refresh");
        refreshPromise = Sessions.refreshSession().then(() => refreshPromise = undefined);

        return refreshPromise;
    }
    else
    {
        logger.info("Access token valid");
        return Promise.resolve();
    }
}

export const Sessions =
{
    ensureLoggedIn: () => new Promise((resolve, reject) =>
    {        
        if (!accessToken && !refreshString)
        {
            reject(new Error("Not logged in"));
        }
        else
        {
            updateTokens()
                .then(() => !!accessToken ? resolve() : reject(new Error("Not logged in")))
                .catch(reject);
        }
    }),

    getUserId: () => (!!accessToken && accessToken.UserId),
    getVerified: () => (!!accessToken && (accessToken.is_verified || accessToken.is_verified === "True")),
    getUsername: () => (!!accessToken && accessToken.Username),
    getSupporter: () => Sessions.getPolicy('supporter'),
    getPolicy: (policy: string) => (!!accessToken && accessToken.Policy.some((item: string) => item === policy)),

    connectToCookies(providedCookies: any)
    {
        cookies = providedCookies;

        Sessions.setLocalTokens(
            {
                refresh_token: cookies.get("refresh_token"),
                access_token: cookies.get("access_token"),
                identity_token: cookies.get("identity_token"),
            });
    },

    getLocalTokens: () =>
    {
        return { access_token: accessString, refresh_token: refreshString, identity_token: identityString };
    },

    setLocalTokens: (tokens: Tokens) =>
    {
        logger.info("Setting local tokens");

        if (!!tokens.access_token && accessString != tokens.access_token)
        {
            accessString = tokens.access_token;

            headers.Authorization = "Bearer " + accessString;

            accessToken = jwt.decode(accessString);

            cookies && cookies.set("access_token", accessString, { path: '/' });
        }

        if (!!tokens.refresh_token && refreshString != tokens.refresh_token)
        {            
            refreshString = tokens.refresh_token;

            refreshToken = jwt.decode(refreshString);
        }

        if (!!tokens.identity_token && identityString != tokens.identity_token)
        {            
            identityString = tokens.identity_token;

            identityToken = jwt.decode(identityString);

            cookies && cookies.set("identity_token", identityString, { path: '/' });
        }
    },

    logout: () =>
    {
        logger.info("Logging out");

        if (!!cookies)
        {
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

    loginOffline : (username: string) =>
    {
        logger.info("Login offline " + username);

        var refresh = {"UserId":"0","role":"Refresh","exp":9999999999,"iss":"AltaWebAPI","aud":"AltaClient"}
        var access = {"UserId":"0","Username":"OFFLINE " + username,"role":"Access","is_verified":"True","is_member":"True","Policy":["offline", "database_admin","admin_vr_modes","debug_features","game_access_development","play_offline","server_access_development","server_owner","game_access_public","server_access_pre_alpha","server_access_tutorial","server_create_development","game_access_testing","reuse_refresh_tokens","server_access_testing"],"exp":9999999999,"iss":"AltaWebAPI","aud":"AltaClient"}
        var identity = {"UserId":"0","Username":"OFFLINE " + username,"role":"Identity","is_member":"True","is_dev":"True","exp":9999999999,"iss":"AltaWebAPI","aud":"AltaClient"}
    
        Sessions.setLocalTokens({ 
            refresh_token : jwt.sign(refresh, "offline"),
            access_token : jwt.sign(access, "offline"),
            identity_token : jwt.sign(identity, "offline") 
        });

        return Promise.resolve();
    },

    hashPassword: (password: string) =>
    {
        return sha512(password).toString();  
    },

    loginWithUsername: (username: string, passwordHash: string) =>
    {
        logger.info("Login " + username);

        if (isOffline)
        {
            return Sessions.loginOffline(username);
        }

        return requestNoLogin('POST', 'sessions', false, { username, password_hash: passwordHash })
            .then((result:Tokens) => Sessions.setLocalTokens(result))
            .catch(error =>
            {
               logger.info("Error logging in");
               logger.info(JSON.stringify(headers));
               
               throw error;
            });
    },

    loginWithEmail: (email: string, passwordHash: string) => 
    {
        logger.info("Login with email");

        if (isOffline)
        {
            return Sessions.loginOffline(email);
        }

        return requestNoLogin('POST', 'sessions/email', false, { email, password_hash: passwordHash })
            .then((result:Tokens) => Sessions.setLocalTokens(result))
            .catch(error =>
            {
               logger.info("Error logging in");
               logger.info(JSON.stringify(headers));
               
               throw error;
            });
    },

    loginWithRefreshToken: (refreshToken: string) =>
    {
        if (!refreshToken || refreshToken.includes('\u0000'))
        {
            throw new Error("Invalid refresh token");
        }

        logger.info("Login with refresh");

        if (isOffline)
        {
            return Sessions.loginOffline("refresh");
        }

        refreshString = refreshToken;

        return Sessions.refreshSession();
    },

    checkRemembered: () =>
    {
        logger.info("Check remembered");

        try
        {
            if (!fs.existsSync(appdata))
            {
                fs.mkdirSync(appdata, { recursive: true });
            }

            var rememberPath = path.join(appdata, '.rememberme');

            if (fs.existsSync(rememberPath))
            {
                var content = fs.readFileSync(rememberPath, 'utf8');

                return Sessions.loginWithRefreshToken(content);
            }
        }
        catch (error)
        {
            console.error("Error while checking remembered. See below.");
            console.error(error);
        }

        return Promise.resolve();
    },

    remember : () =>
    {
        logger.info("Remember");

        cookies && cookies.set("refresh_token", refreshString, { path: '/' });

        if (!fs.existsSync(appdata))
        {
            fs.mkdirSync(appdata, { recursive: true });
        }

        var rememberPath = path.join(appdata, '.rememberme');

        fs.writeFileSync(rememberPath, refreshString, 'utf8');
    },

    forget : () =>
    {
        logger.info("Forget");

        if (!!cookies)
        {
            cookies.remove("refresh_token", { path: '/' });
        }

        var rememberPath = path.join(appdata, '.rememberme');

        if (fs.existsSync(rememberPath))
        {
            fs.unlinkSync(rememberPath);
        }
    },

    refreshSession: () =>
    {
        logger.info("Refreshing session");

        return requestRefresh('PUT', 'sessions', false, {})
            .then((result:Tokens) => Sessions.setLocalTokens(result))
    },
}

export const Launcher =
{
    getGames: () =>
    {
        logger.info("Get games");

        return request('GET', 'launcher/games');
    },

    getGameInfo: (gameId: number) =>
    {
        logger.info("Get game info");

        return request('GET', `launcher/games/${gameId}`);
    },
}

export enum GroupType
{
    Open,
    Public,
    Private
}

export const Groups =
{
    Member : 1,
    Moderator : 2,
    Admin : 4,

    MemberUp : 7,
    ModeratorUp : 6,
    /*
    Member 1,
    Moderator 2,
    Admin 4
    */

    Open : 0,
    Public : 1,
    Private : 2,

    getJoined : () =>
    {
        logger.info("Get joined groups");

        return requestPaged('GET', 'groups/joined');
    },
    
    getVisible : (type:GroupType) =>
    {
        logger.info("Get visible groups");

        return requestPaged('GET', `groups?type=${type}`);
    },
    
    getInvited : () =>
    {
        logger.info("Get invited to groups");

        return requestPaged('GET', 'groups/invites');
    },
    
    getRequested : () =>
    {
        logger.info("Get requested groups");

        return requestPaged('GET', 'groups/requested');
    },
    
    createGroup : (name:string, description:string) =>
    {
        logger.info("Create group");

        return request('POST', 'groups', false,
        {
            type: Groups.Private,
            description,
            Name: name,
            invite_permissions: Groups.ModeratorUp,
            kick_permissions: Groups.ModeratorUp,
            accept_member_permissions: Groups.ModeratorUp,
            create_server_permissions: Groups.Admin
        });
    },
    
    getGroupInfo : (groupId:number|string) =>
    {
        logger.info(`Get group info ${groupId}`);

        return request('GET', `groups/${groupId}`);
    },

    editGroupInfo : (groupId:number|string, groupInfo:{name:string|undefined, description:string|undefined, groupType:GroupType|undefined}) =>
    {
        logger.info(`Patch group info ${groupId}`);

        return request('PATCH', `groups/${groupId}`, false, groupInfo);
    },

    editGroupRole : (groupId:number|string, roleId:number|string, newInfo:{name:string|undefined, permissions:string[]|undefined}) =>
    {
        logger.info(`Put group role ${groupId} ${roleId}`);

        return request('PUT', `groups/${groupId}/roles/${roleId}`, false, newInfo);
    },
    
    getMembers : (groupId:number|string) =>
    {
        logger.info(`Get members ${groupId}`);

        return requestPaged('GET', `groups/${groupId}/members`);
    },
        
    getBans : (groupId:number|string) =>
    {
        logger.info(`Get banned ${groupId}`);

        return requestPaged('GET', `groups/${groupId}/bans`);
    },
        
    banUser : (groupId:number|string, userId:number|string) =>
    {
        logger.info(`Ban user ${groupId} ${userId}`);

        return request('POST', `groups/${groupId}/bans/${userId}`);
    },
        
    unbanUser : (groupId:number|string, userId:number|string) =>
    {
        logger.info(`Unban user ${groupId} ${userId}`);

        return request('DELETE', `groups/${groupId}/bans/${userId}`);
    },
    
    getMemberInfo : (groupId:number|string, userId:number|string) =>
    {
        logger.info(`Get member permissions ${groupId} ${userId}`);

        return request('GET', `groups/${groupId}/members/${userId}`);
    },
    
    getJoinRequests : (groupId:number|string) =>
    {
        logger.info(`Get join requests ${groupId}`);

        return requestPaged('GET', `groups/${groupId}/requests`);
    },
    
    getOutgoingInvites : (groupId:number|string) =>
    {
        logger.info(`Get outgoing invites ${groupId}`);

        return requestPaged('GET', `groups/${groupId}/invites`);
    },
    
    requestJoin : (groupId:number|string) =>
    {
        logger.info(`Request join ${groupId}`);

        return request('POST', `groups/${groupId}/requests`);
    },
    
    revokeRequest : (groupId:number|string) =>
    {
        logger.info(`Revoke request ${groupId}`);

        return request('DELETE', `groups/${groupId}/requests`);
    },
    
    acceptInvite : (groupId:number|string) =>
    {
        logger.info(`Accept invite ${groupId}`);

        return request('POST', `groups/invites/${groupId}`);
    },
    
    rejectInvite : (groupId:number|string) =>
    {
        logger.info(`Reject invite ${groupId}`);

        return request('DELETE', `groups/invites/${groupId}`);
    },
    
    leave : (groupId:number|string) =>
    {
        logger.info(`Leave ${groupId}`);

        return request('DELETE', `groups/${groupId}/members`);
    },
    
    inviteMember : (groupId:number|string, userId:number|string) =>
    {
        logger.info(`Invite member ${groupId} ${userId}`);

        return request('POST', `groups/${groupId}/invites/${userId}`);
    },
    
    revokeInvite : (groupId:number|string, userId:number|string) =>
    {
        logger.info(`Revoke invite ${groupId} ${userId}`);

        return request('DELETE', `groups/${groupId}/invites/${userId}`);
    },
    
    acceptRequest : (groupId:number|string, userId:number|string) =>
    {
        logger.info(`Accept request ${groupId} ${userId}`);

        return request('PUT', `groups/${groupId}/requests/${userId}`);
    },
    
    rejectRequest : (groupId:number|string, userId:number|string) =>
    {
        logger.info(`Reject request ${groupId} ${userId}`);

        return request('DELETE', `groups/${groupId}/requests/${userId}`);
    },
    
    kickMember : (groupId:number|string, userId:number|string) =>
    {
        logger.info(`Invite member ${groupId} ${userId}`);

        return request('DELETE', `groups/${groupId}/members/${userId}`);
    },
    
    //OBSOLETE
    editPermissions : (groupId:number|string, userId:number|string, permissions:number) =>
    {
        logger.info(`Edit member permissions ${groupId} ${userId}`);

        return request('POST', `groups/${groupId}/members/${userId}/permissions`, false, 
        {
            permissions
        });
    },

    setMemberRole : (groupId:number|string, userId:number|string, roleId:number|string) =>
    {
        logger.info(`Edit member role ${groupId} ${userId} ${roleId}`);

        return request('POST', `groups/${groupId}/members/${userId}/role/${roleId}`);
    },
   
    createServer : (groupId:number|string, name:string, description:string, region:string) =>
    {
        logger.info(`Create server ${groupId} ${name}`);
        
        return request('POST', `groups/${groupId}/servers`, false, 
        {
            name,
            description,
            region
        });
    }
}

export const Analytics =
{
    sendInstallation : (type:string, version_from:string|undefined, version_to:string, error:string|undefined, start_id:number|undefined) =>
    {
        return request('POST', 'analytics/installation', false, { type, version_from, version_to, error, start_id });
    }
}

export const Friends =
{
    getUserFriends : (userId: number|string) =>
    {
        logger.info("Get user friends");

        return requestPaged('GET', `friends/${userId}`);
    },
    
    getFriends : () =>
    {
        logger.info("Get friends");

        return requestPaged('GET', 'friends', 10);
    },
    
    getOutgoingRequests : () =>
    {
        logger.info("Get outgoing friend requests");

        return requestPaged('GET', 'friends/requests/sent');
    },
    
    getFriendRequests : () =>
    {
        logger.info("Get friend requests");

        return requestPaged('GET', 'friends/requests');
    },
    
    acceptFriendRequest : (userId : number|string) =>
    {
        logger.info("Accept friend request");

        // return request('POST', `friends/requests/${userId}`);

        return Friends.addFriend(userId);
    },
    
    addFriend : (userId : number|string) =>
    {
        logger.info("Add friend");

        return request('POST', `friends/${userId}`);
    },
    
    revokeFriendRequest : (userId : number|string) =>
    {
        logger.info("Revoke friend request");

        return Friends.removeFriend(userId);
    },
    
    rejectFriendRequest : (userId : number|string) =>
    {
        logger.info("Reject friend request");

        return Friends.removeFriend(userId);
    },
    
    removeFriend : (userId : number|string) =>
    {
        logger.info("Remove friend");

        return request('DELETE', `friends/${userId}`);
    }
}

export const Users =
{
    getInfo: (userId: number) =>
    {
        logger.info("Get user " + userId);

        return request('GET', `users/${userId}`);
    },

    register: (username: string, passwordHash: string, email: string, referral: string | undefined = undefined) =>
    {
        logger.info("Register " + username);

        return requestNoLogin('POST', 'users', false, { username, password_hash: passwordHash, email, referral });
    },

    getVerified: () =>
    {
        logger.info("Get verified");

        return request('GET', `users/${accessToken.UserId}/verification`)
            .then((result:boolean) =>
            {
                if (result)
                {
                    accessToken.is_verified = true;
                }

                return result;
            });
    },

    requestVerificationEmail: (email: string) =>
    {
        logger.info("Request verification");

        return request('PUT', `users/${accessToken.UserId}/verification`, false, { email });
    },

    verify: (userId:number, token: string) =>
    {
        logger.info("Verify");

        return requestNoLogin('POST', `users/${userId}/verification`, false, { verification_token: token });
    },

    changePassword: (oldHash: string, newHash: string) =>
    {
        logger.info("Change password");

        return request('PUT', `users/${accessToken.UserId}/password`, false, { old_password_hash: oldHash, new_password_hash: newHash });
    },

    resetPassword: (userId: number, newHash: string, token: string) =>
    {
        logger.info("Reset password " + userId);

        return requestNoLogin('POST', `users/${userId}/password`, false, { reset_token: token, new_password_hash: newHash });
    },

    changeUsername: (username: string) =>
    {
        logger.info("Change username " + username);

        return request('PUT', `users/${accessToken.UserId}/username`, false, { new_username: username });
    },

    findUserByUsername : (username : string) =>
    {
        logger.info("Find user with username " + username);

        return request('POST', `users/search/username`, false, { username });
    },
    
    getStatistics : (userId : Number) =>
    {
        logger.info("Getting Users statistics id: " + userId);

        return request('GET', `users/${userId}/statistics`);
    },
}

export const Meta =
{
    //No applicable methods
}

export const Servers =
{
    getRegions: () =>
    {
        logger.info("Get regions");

        return requestNoLogin('GET', `servers/regions`);
    },

    getConsoleServers: () =>
    {
        logger.info("Getting console servers");

        return request('GET', 'servers/console');
    },

    getFavorites: () =>
    {
        logger.info("Getting favorite servers");

        return request('GET', 'servers/favorites');
    },

    addFavorite: (serverId:number|string) =>
    {
        logger.info(`Add favorite server ${serverId}`);

        return request('POST', `servers/favorites/${serverId}`);
    },

    removeFavorite: (serverId:number|string) =>
    {
        logger.info(`Add favorite server ${serverId}`);

        return request('DELETE', `servers/favorites/${serverId}`);
    },

    getRunning: () =>
    {
        logger.info("Getting running servers");

        return request('GET', 'servers/running');
    },

    getOnline: () =>
    {
        logger.info("Getting visible servers");

        return request('GET', 'servers/online');
    },

    getPublic: () =>
    {
        logger.info("Getting public servers");

        return request('GET', 'servers/public');
    },

    getJoined: () =>
    {
        logger.info("Getting joined servers");

        return request('GET', 'servers/joined');
    },

    getOpen: () =>
    {
        logger.info("Getting open servers");

        return request('GET', 'servers/open');
    },

    getDetails: (serverId:number|string) =>
    {
        logger.info(`Getting server details ${serverId}`);

        return request('GET', `servers/${serverId}`);
    },

    getControllable: () =>
    {
        logger.info(`Getting controllable`);

        return request('GET', `servers/control`);
    },

    joinConsole: (id:number|string, should_launch:boolean = false, ignore_offline:boolean = false) =>
    {
        logger.info(`Join console ${id}`);

        return request('POST', `servers/${id}/console`, false, { should_launch, ignore_offline });
    }
}

export const Services =
{
    resetPassword: (email: string) =>
    {
        logger.info("Reset password");

        return requestNoLogin('POST', `services/reset-password`, false, { email });
    },

    getTemporaryIdentity: (data: any) =>
    {
        logger.info("Get temp ID");

        return request('POST', 'services/identity-token', false, { user_data: data });
    }
}

export enum UserReportStatus
{
    Unprocessed = 1 << 0,
    AwaitingReply = 1 << 1,
    Resolved = 1 << 2,
    Rejected = 1 << 3
}

export enum UserReportType
{
    UserReport,
    LostItems,
    TempBan,
    PermaBan,
    Warning,
    Note
}

export type UserReport =
{
    topic_user : number;
    assignee : number;
    incident_date:Date;
    type:UserReportType;
    status:UserReportStatus;
    linked_reports:{name:string, report_id:number}[];
    title:string;
    comments:{user_id:number, comment:string, timestamp: Date};
}

export const UserReports =
{
    getUserReports: ( status:UserReportStatus, user_ids:number[]|undefined = undefined) =>
    {
        logger.info("Get user reports");
        
        return requestPaged('GET', `userReports?status=${status}${!user_ids ? '' : `&user_ids=${user_ids.join()}`}`);
    },
    
    getTopicReports: ( status:UserReportStatus, user_ids:number[]|undefined = undefined) =>
    {
        logger.info("Get topic reports");
        
        return requestPaged('GET', `userReports/topic?status=${status}${!user_ids ? '' : `&user_ids=${user_ids.join()}`}`);
    },
    
    getAssigneeReports: ( status:UserReportStatus, user_ids:number[]|undefined = undefined) =>
    {
        logger.info("Get assignee reports");
        
        return requestPaged('GET', `userReports/assignee?status=${status}${!user_ids ? '' : `&user_ids=${user_ids.join()}`}`);
    },

    submitReport: ( report:UserReport ) =>
    {
        logger.info("Submit report");

        return request('POST', 'userReports', false, report);
    }
}

export const Shop =
{
    getSandbox: () =>
    {
        logger.info("Getting whether to use the sandbox");

        return request('GET', 'shop/sandbox');
        // {
        //     "sandbox": true
        // }
    },

    Account:
    {
        getProfile: () =>
        {
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

        getPaymentMethods: () =>
        {
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

        getItems: () =>
        {
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

        getRewards: () =>
        {
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

        getSubscription: () =>
        {
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

        cancelSubscription: () =>
        {
            return request('DELETE', 'shop/account/subscription');
        },
    },

    Debug:
    {
        modifyBalance: (change: number) =>
        {
            return request('POST', 'shop/debug/balance', false, { change });
        },

        deleteMembership: () =>
        {
            return request('DELETE', 'shop/debug/membership');
        },

        clearItems: () =>
        {
            return request('DELETE', 'shop/debug/inventory');
        },
    },

    Categories:
    {
        //Unused
    },

    Items:
    {
        getItems: () =>
        {
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

        getInfo: memoizee((itemId: number) =>
        {
            logger.info("Get item info");

            return request('GET', `shop/items/${itemId}`);
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

    Sets:
    {
        getSet: memoizee((sku: string) =>
        {
            logger.info("Get set info");

            return request('GET', `shop/sets/${sku}`);
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

    Transactions :
    {
        getStatus : (transactionId:string|number) =>
        {
            logger.info("Get Transaction ID " + transactionId);

            return request('GET', `shop/transactions/${transactionId}/status`);
        },
    },

    Purchase:
    {
        Shards:
        {
            buyItem: (itemId: number) =>
            {
                logger.info("Purchase item");

                return request('POST', 'shop/purchase/shards/items', false, {item_id:itemId});
            },
        },

        Premium:
        {
            buyItem: (itemId: number) =>
            {
                logger.info("Purchase premium item");

                return request('POST', 'shop/purchase/premium/items', false, { item_id: itemId });
                // {
                //     "token": "string"
                // }
            },

            buySubscription: (subscriptionId: number) =>
            {
                logger.info("Purchase subscription");

                return request('POST', 'shop/purchase/premium/subscriptions', false, { plan_external_id: subscriptionId });
                // {
                //     "token": "string"
                // }
            },

            buyShards : (shardsId:string|number, quantity:number) =>
            {
                logger.info("Purchase currency "  + shardsId + " " + quantity);

                return request('POST', 'shop/purchase/premium/shards', false, {shards_package_id:shardsId, quantity});
                // {
                //     "token": "string"
                // }
            },
            
            buyCoupon : (shardsId:string|number, quantity:number) =>
            {
                logger.info("Purchase coupon "  + shardsId + " " + quantity);

                return request('POST', 'shop/purchase/shards/coupons', false, {currency_package_id:shardsId, quantity});
                // {
                //     "transaction_id": number,
                //     "token": "string",
                // }
            },
        }
    },

    Coupons :
    {
        redeem : (coupon:String) =>
        {
            logger.info("Redeem coupon");

            return request('POST', 'shop/coupons/redeem', false, {coupon});
            // {
            //     "coupon_code": "SCHMEECHEE-245WC-FNV85-DNRXE-BYQYK",
            //     "virtual_currency_amount": 1000,
            //     "virtual_items": []
            // }
        }
    },

    Subscriptions:
    {
        getSubscriptions: () =>
        {
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

    Shards:
    {
        getPackages: () =>
        {
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
}