import memoizee from 'memoizee';
export declare const setEndpoint: (endpoint: string) => void;
export declare const getRejectUnauthorized: () => boolean;
type Tokens = {
    refresh_token: string;
    access_token: string;
    identity_token: string;
};
export declare function setVersion(version: string): void;
export declare function setUserAgent(userAgent: string): void;
export declare function requestNoLogin(method: string, path: string, isCached?: boolean, body?: object | undefined): Promise<any>;
export declare function request(method: string, path: string, isCached?: boolean, body?: object | undefined): Promise<any>;
export declare function requestPaged(method: string, path: string, limit?: number | undefined, isCached?: boolean, body?: object | undefined): AsyncGenerator<any, void, unknown>;
export declare const Sessions: {
    ensureLoggedIn: () => Promise<void>;
    getUserId: () => any;
    getVerified: () => any;
    getUsername: () => any;
    getSupporter: () => any;
    getPolicy: (policy: string) => any;
    getPolicies: () => any;
    connectToCookies(providedCookies: any): void;
    getLocalTokens: () => {
        access_token: string | undefined;
        refresh_token: string | undefined;
        identity_token: string | undefined;
    };
    setLocalTokens: (tokens: Tokens) => void;
    logout: () => void;
    loginOffline: (username: string) => Promise<void>;
    hashPassword: (password: string) => string;
    loginWithUsername: (username: string, passwordHash: string) => Promise<void>;
    loginWithEmail: (email: string, passwordHash: string) => Promise<void>;
    loginWithRefreshToken: (refreshToken: string) => Promise<void>;
    checkRemembered: () => Promise<void>;
    remember: () => void;
    forget: () => void;
    refreshSession: () => Promise<void>;
};
export declare enum BanType {
    Server = 0,
    Global = 1,
    Public = 2
}
export declare enum BanMethod {
    UserId = 1,
    IpAddress = 2,
    DeviceId = 4
}
export declare const Bans: {
    createBan: (user_id: number, duration_hours: number, type: BanType, method: BanMethod, reason: string, servers: number[] | undefined) => Promise<any>;
    deleteBan: (banId: number) => Promise<any>;
    getBan: (banId: number) => Promise<any>;
    getAll: () => Promise<any>;
    getModBans: (modId: number) => Promise<any>;
    getUserBans: (userId: number) => Promise<any>;
};
export declare const Launcher: {
    getGames: () => Promise<any>;
    getGameInfo: (gameId: number) => Promise<any>;
};
export declare enum GroupType {
    Open = 0,
    Public = 1,
    Private = 2
}
export declare const Groups: {
    Member: number;
    Moderator: number;
    Admin: number;
    MemberUp: number;
    ModeratorUp: number;
    Open: number;
    Public: number;
    Private: number;
    getJoined: () => AsyncGenerator<any, void, unknown>;
    getVisible: (type: GroupType, ignoreInactive?: boolean) => AsyncGenerator<any, void, unknown>;
    getInvited: () => AsyncGenerator<any, void, unknown>;
    getRequested: () => AsyncGenerator<any, void, unknown>;
    createGroup: (name: string, description: string) => Promise<any>;
    getGroupInfo: (groupId: number | string) => Promise<any>;
    editGroupInfo: (groupId: number | string, groupInfo: {
        name: string | undefined;
        description: string | undefined;
        groupType: GroupType | undefined;
    }) => Promise<any>;
    editGroupRole: (groupId: number | string, roleId: number | string, newInfo: {
        name: string | undefined;
        color: string | undefined;
        permissions: string[] | undefined;
    }) => Promise<any>;
    getMembers: (groupId: number | string) => AsyncGenerator<any, void, unknown>;
    getBans: (groupId: number | string) => AsyncGenerator<any, void, unknown>;
    banUser: (groupId: number | string, userId: number | string) => Promise<any>;
    unbanUser: (groupId: number | string, userId: number | string) => Promise<any>;
    getMemberInfo: (groupId: number | string, userId: number | string) => Promise<any>;
    getJoinRequests: (groupId: number | string) => AsyncGenerator<any, void, unknown>;
    getOutgoingInvites: (groupId: number | string) => AsyncGenerator<any, void, unknown>;
    requestJoin: (groupId: number | string) => Promise<any>;
    revokeRequest: (groupId: number | string) => Promise<any>;
    acceptInvite: (groupId: number | string) => Promise<any>;
    rejectInvite: (groupId: number | string) => Promise<any>;
    leave: (groupId: number | string) => Promise<any>;
    inviteMember: (groupId: number | string, userId: number | string) => Promise<any>;
    revokeInvite: (groupId: number | string, userId: number | string) => Promise<any>;
    acceptRequest: (groupId: number | string, userId: number | string) => Promise<any>;
    rejectRequest: (groupId: number | string, userId: number | string) => Promise<any>;
    kickMember: (groupId: number | string, userId: number | string) => Promise<any>;
    editPermissions: (groupId: number | string, userId: number | string, permissions: number) => Promise<any>;
    setMemberRole: (groupId: number | string, userId: number | string, roleId: number | string) => Promise<any>;
    createServer: (groupId: number | string, name: string, description: string, region: string) => Promise<any>;
};
export declare const Security: {
    sso: () => Promise<any>;
};
export declare const Analytics: {
    sendInstallation: (type: string, version_from: string | undefined, version_to: string, error: string | undefined, start_id: number | undefined) => Promise<any>;
};
export declare const Friends: {
    getUserFriends: (userId: number | string) => AsyncGenerator<any, void, unknown>;
    getFriends: () => AsyncGenerator<any, void, unknown>;
    getOutgoingRequests: () => AsyncGenerator<any, void, unknown>;
    getFriendRequests: () => AsyncGenerator<any, void, unknown>;
    acceptFriendRequest: (userId: number | string) => Promise<any>;
    addFriend: (userId: number | string) => Promise<any>;
    revokeFriendRequest: (userId: number | string) => Promise<any>;
    rejectFriendRequest: (userId: number | string) => Promise<any>;
    removeFriend: (userId: number | string) => Promise<any>;
};
export declare const Users: {
    getInfo: ((userId: number) => Promise<any>) & memoizee.Memoized<(userId: number) => Promise<any>>;
    register: (username: string, passwordHash: string, email: string, referral?: string | undefined) => Promise<any>;
    getVerified: () => Promise<boolean>;
    requestVerificationEmail: (email: string) => Promise<any>;
    verify: (userId: number, token: string) => Promise<any>;
    changeUsername: (username: string, passHash: string) => Promise<any>;
    changePassword: (oldHash: string, newHash: string) => Promise<any>;
    resetPassword: (userId: number, newHash: string, token: string) => Promise<any>;
    findUserByUsername: (username: string) => Promise<any>;
    getStatistics: (userId: Number) => Promise<any>;
};
export declare const Meta: {};
export declare const Servers: {
    getAll: (() => Promise<any>) & memoizee.Memoized<() => Promise<any>>;
    getRegions: () => Promise<any>;
    getConsoleServers: () => Promise<any>;
    getFavorites: () => Promise<any>;
    addFavorite: (serverId: number | string) => Promise<any>;
    removeFavorite: (serverId: number | string) => Promise<any>;
    getRunning: () => Promise<any>;
    getOnline: () => Promise<any>;
    getPublic: () => Promise<any>;
    getJoined: () => Promise<any>;
    getOpen: () => Promise<any>;
    getDetails: (serverId: number | string) => Promise<any>;
    getControllable: () => Promise<any>;
    joinConsole: (id: number | string, should_launch?: boolean, ignore_offline?: boolean) => Promise<any>;
};
export declare const Services: {
    resetPassword: (email: string) => Promise<any>;
    getTemporaryIdentity: (data: any) => Promise<any>;
    CheckTokenValidity: (token: string) => Promise<any>;
};
export declare enum UserReportStatus {
    Unprocessed = 1,
    AwaitingReply = 2,
    Resolved = 4,
    Rejected = 8
}
export declare enum UserReportType {
    UserReport = 0,
    LostItems = 1,
    TempBan = 2,
    PermaBan = 3,
    Warning = 4,
    Note = 5
}
export type UserReport = {
    topic_user: number;
    assignee: number;
    incident_date: Date;
    type: UserReportType;
    status: UserReportStatus;
    linked_reports: {
        name: string;
        report_id: number;
    }[];
    title: string;
    comments: {
        user_id: number;
        comment: string;
        timestamp: Date;
    };
};
export declare const UserReports: {
    getUserReports: (status: UserReportStatus, user_ids?: number[] | undefined) => AsyncGenerator<any, void, unknown>;
    getTopicReports: (status: UserReportStatus, user_ids?: number[] | undefined) => AsyncGenerator<any, void, unknown>;
    getAssigneeReports: (status: UserReportStatus, user_ids?: number[] | undefined) => AsyncGenerator<any, void, unknown>;
    submitReport: (report: UserReport) => Promise<any>;
};
export declare const Shop: {
    getSandbox: () => Promise<any>;
    Rewards: {
        getRewards: () => Promise<any>;
        getUnclaimedRewards: () => Promise<any>;
        claimReward: (rewardIdentifier: number) => Promise<any>;
    };
    Account: {
        getProfile: () => Promise<any>;
        getPaymentMethods: () => Promise<any>;
        getItems: () => Promise<any>;
        getRewards: () => Promise<any>;
        getSubscription: () => Promise<any>;
        cancelSubscription: () => Promise<any>;
    };
    Debug: {
        modifyBalance: (change: number) => Promise<any>;
        deleteMembership: () => Promise<any>;
        clearItems: () => Promise<any>;
    };
    Categories: {};
    Items: {
        getItems: () => Promise<any>;
        getInfo: ((itemId: number) => Promise<any>) & memoizee.Memoized<(itemId: number) => Promise<any>>;
    };
    Sets: {
        getSet: ((sku: string) => Promise<any>) & memoizee.Memoized<(sku: string) => Promise<any>>;
    };
    Transactions: {
        getStatus: (transactionId: string | number) => Promise<any>;
    };
    Purchase: {
        Shards: {
            buyItem: (itemId: number) => Promise<any>;
        };
        Premium: {
            buyItem: (itemId: number) => Promise<any>;
            buySubscription: (subscriptionId: number) => Promise<any>;
            buyShards: (shardsId: string | number, quantity: number) => Promise<any>;
            buyCoupon: (shardsId: string | number, quantity: number) => Promise<any>;
        };
    };
    Coupons: {
        redeem: (coupon: String) => Promise<any>;
    };
    Subscriptions: {
        getSubscriptions: () => Promise<any>;
    };
    Shards: {
        getPackages: () => Promise<any>;
    };
};
export {};
