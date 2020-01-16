import memoizee from 'memoizee';
export declare const setEndpoint: (endpoint: string) => void;
export declare const getRejectUnauthorized: () => boolean;
declare type Tokens = {
    refresh_token: string;
    access_token: string;
    identity_token: string;
};
export declare function setVersion(version: string): void;
export declare function setUserAgent(userAgent: string): void;
export declare const Sessions: {
    ensureLoggedIn: () => Promise<{}>;
    getUserId: () => any;
    getVerified: () => any;
    getUsername: () => any;
    getMember: () => any;
    getPolicy: (policy: string) => any;
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
    getJoined: () => AsyncIterableIterator<any>;
    getVisible: (type: GroupType) => AsyncIterableIterator<any>;
    getInvited: () => AsyncIterableIterator<any>;
    getRequested: () => AsyncIterableIterator<any>;
    createGroup: (name: string, description: string) => Promise<any>;
    getGroupInfo: (groupId: string | number) => Promise<any>;
    editGroupInfo: (groupId: string | number, groupInfo: {
        name: string | undefined;
        description: string | undefined;
        groupType: GroupType | undefined;
    }) => Promise<any>;
    editGroupRole: (groupId: string | number, roleId: string | number, newInfo: {
        name: string | undefined;
        permissions: string[] | undefined;
    }) => Promise<any>;
    getMembers: (groupId: string | number) => AsyncIterableIterator<any>;
    getBans: (groupId: string | number) => AsyncIterableIterator<any>;
    banUser: (groupId: string | number, userId: string | number) => Promise<any>;
    unbanUser: (groupId: string | number, userId: string | number) => Promise<any>;
    getMemberInfo: (groupId: string | number, userId: string | number) => Promise<any>;
    getJoinRequests: (groupId: string | number) => AsyncIterableIterator<any>;
    getOutgoingInvites: (groupId: string | number) => AsyncIterableIterator<any>;
    requestJoin: (groupId: string | number) => Promise<any>;
    revokeRequest: (groupId: string | number) => Promise<any>;
    acceptInvite: (groupId: string | number) => Promise<any>;
    rejectInvite: (groupId: string | number) => Promise<any>;
    leave: (groupId: string | number) => Promise<any>;
    inviteMember: (groupId: string | number, userId: string | number) => Promise<any>;
    revokeInvite: (groupId: string | number, userId: string | number) => Promise<any>;
    acceptRequest: (groupId: string | number, userId: string | number) => Promise<any>;
    rejectRequest: (groupId: string | number, userId: string | number) => Promise<any>;
    kickMember: (groupId: string | number, userId: string | number) => Promise<any>;
    editPermissions: (groupId: string | number, userId: string | number, permissions: number) => Promise<any>;
    setMemberRole: (groupId: string | number, userId: string | number, roleId: string | number) => Promise<any>;
    createServer: (groupId: string | number, name: string, description: string, region: string) => Promise<any>;
};
export declare const Friends: {
    getUserFriends: (userId: string | number) => AsyncIterableIterator<any>;
    getFriends: () => AsyncIterableIterator<any>;
    getOutgoingRequests: () => AsyncIterableIterator<any>;
    getFriendRequests: () => AsyncIterableIterator<any>;
    acceptFriendRequest: (userId: string | number) => Promise<any>;
    addFriend: (userId: string | number) => Promise<any>;
    revokeFriendRequest: (userId: string | number) => Promise<any>;
    rejectFriendRequest: (userId: string | number) => Promise<any>;
    removeFriend: (userId: string | number) => Promise<any>;
};
export declare const Users: {
    getInfo: (userId: number) => Promise<any>;
    register: (username: string, passwordHash: string, email: string, referral?: string | undefined) => Promise<any>;
    getVerified: () => Promise<boolean>;
    requestVerificationEmail: (email: string) => Promise<any>;
    verify: (userId: number, token: string) => Promise<any>;
    changePassword: (oldHash: string, newHash: string) => Promise<any>;
    resetPassword: (userId: number, newHash: string, token: string) => Promise<any>;
    changeUsername: (username: string) => Promise<any>;
    findUserByUsername: (username: string) => Promise<any>;
    getStatistics: (userId: Number) => Promise<any>;
};
export declare const Meta: {};
export declare const Servers: {
    getRegions: () => Promise<any>;
    getConsoleServers: () => Promise<any>;
    getFavorites: () => Promise<any>;
    addFavorite: (serverId: string | number) => Promise<any>;
    removeFavorite: (serverId: string | number) => Promise<any>;
    getRunning: () => Promise<any>;
    getOnline: () => Promise<any>;
    getPublic: () => Promise<any>;
    getJoined: () => Promise<any>;
    getOpen: () => Promise<any>;
    getDetails: (serverId: string | number) => Promise<any>;
    getControllable: () => Promise<any>;
    joinConsole: (id: string | number, should_launch?: boolean, ignore_offline?: boolean) => Promise<any>;
};
export declare const Services: {
    resetPassword: (email: string) => Promise<any>;
    getTemporaryIdentity: (data: any) => Promise<any>;
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
export declare type UserReport = {
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
    getUserReports: (status: UserReportStatus, user_ids?: number[] | undefined) => AsyncIterableIterator<any>;
    getTopicReports: (status: UserReportStatus, user_ids?: number[] | undefined) => AsyncIterableIterator<any>;
    getAssigneeReports: (status: UserReportStatus, user_ids?: number[] | undefined) => AsyncIterableIterator<any>;
    submitReport: (report: UserReport) => Promise<any>;
};
export declare const Shop: {
    getSandbox: () => Promise<any>;
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
