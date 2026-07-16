//! IRC numeric reply codes (RFC 1459/2812 + common extensions).
//!
//! Names follow the conventional `RPL_`/`ERR_` spelling; more are added as
//! handlers grow.

#![allow(missing_docs)] // the RFC name is the documentation

// --- Registration / server info ---
pub const RPL_WELCOME: u16 = 1;
pub const RPL_YOURHOST: u16 = 2;
pub const RPL_CREATED: u16 = 3;
pub const RPL_MYINFO: u16 = 4;
pub const RPL_ISUPPORT: u16 = 5;

// --- Server info queries (VERSION / TIME / ADMIN / INFO) ---
pub const RPL_VERSION: u16 = 351;
pub const RPL_TIME: u16 = 391;
pub const RPL_ADMINME: u16 = 256;
pub const RPL_ADMINLOC1: u16 = 257;
pub const RPL_ADMINLOC2: u16 = 258;
pub const RPL_ADMINEMAIL: u16 = 259;
pub const RPL_INFO: u16 = 371;
pub const RPL_ENDOFINFO: u16 = 374;

// --- USERHOST / ISON ---
pub const RPL_USERHOST: u16 = 302;
pub const RPL_ISON: u16 = 303;

// --- MONITOR (presence notification) ---
pub const RPL_MONONLINE: u16 = 730;
pub const RPL_MONOFFLINE: u16 = 731;
pub const RPL_MONLIST: u16 = 732;
pub const RPL_ENDOFMONLIST: u16 = 733;
pub const ERR_MONLISTFULL: u16 = 734;

// --- LUSERS ---
pub const RPL_LUSERCLIENT: u16 = 251;
pub const RPL_LUSEROP: u16 = 252;
pub const RPL_LUSERUNKNOWN: u16 = 253;
pub const RPL_LUSERCHANNELS: u16 = 254;
pub const RPL_LUSERME: u16 = 255;
pub const RPL_LOCALUSERS: u16 = 265;
pub const RPL_GLOBALUSERS: u16 = 266;

// --- SASL / accounts ---
pub const RPL_LOGGEDIN: u16 = 900;
pub const RPL_LOGGEDOUT: u16 = 901;
pub const ERR_NICKLOCKED: u16 = 902;
pub const RPL_SASLSUCCESS: u16 = 903;
pub const ERR_SASLFAIL: u16 = 904;
pub const ERR_SASLTOOLONG: u16 = 905;
pub const ERR_SASLABORTED: u16 = 906;
pub const ERR_SASLALREADY: u16 = 907;
pub const RPL_WHOISACCOUNT: u16 = 330;

// --- Metadata (draft/metadata-2) ---
pub const RPL_KEYVALUE: u16 = 761;
pub const RPL_METADATAEND: u16 = 762;
pub const RPL_SILELIST: u16 = 271;
pub const RPL_ENDOFSILELIST: u16 = 272;
pub const RPL_MAP: u16 = 15;
pub const RPL_MAPEND: u16 = 17;
pub const RPL_NOWON: u16 = 604;
pub const RPL_NOWOFF: u16 = 605;
pub const RPL_WATCHOFF: u16 = 602;
pub const RPL_WATCHLIST: u16 = 606;
pub const RPL_ENDOFWATCHLIST: u16 = 607;
pub const ERR_SILELISTFULL: u16 = 511;
pub const RPL_METADATASUBOK: u16 = 770;
pub const RPL_METADATAUNSUBOK: u16 = 771;
pub const RPL_METADATASUBS: u16 = 772;

// --- Away ---
pub const RPL_AWAY: u16 = 301;
pub const RPL_UNAWAY: u16 = 305;
pub const RPL_NOWAWAY: u16 = 306;

// --- Operators / moderation ---
pub const RPL_YOUREOPER: u16 = 381;
pub const RPL_REHASHING: u16 = 382;
pub const RPL_INVITING: u16 = 341;
pub const RPL_BANLIST: u16 = 367;
pub const RPL_ENDOFBANLIST: u16 = 368;
// 346/347 list the channel's `+I` invite-exception masks; 336/337 list the
// channels the *requesting user* has pending invitations to (`INVITE` with no
// parameters). The names follow solanum.
pub const RPL_INVEXLIST: u16 = 346;
pub const RPL_ENDOFINVEXLIST: u16 = 347;
pub const RPL_INVITELIST: u16 = 336;
pub const RPL_ENDOFINVITELIST: u16 = 337;
pub const RPL_EXCEPTLIST: u16 = 348;
pub const RPL_ENDOFEXCEPTLIST: u16 = 349;
pub const ERR_NOPRIVILEGES: u16 = 481;
pub const ERR_CANTKILLSERVER: u16 = 483;
pub const ERR_NOOPERHOST: u16 = 491;

// --- STATS ---
pub const RPL_STATSKLINE: u16 = 216;
pub const RPL_ENDOFSTATS: u16 = 219;
pub const RPL_STATSDLINE: u16 = 225;
pub const RPL_STATSUPTIME: u16 = 242;
pub const RPL_STATSOLINE: u16 = 243;

// --- LINKS ---
pub const RPL_LINKS: u16 = 364;
pub const RPL_ENDOFLINKS: u16 = 365;

// --- WHOWAS ---
pub const RPL_WHOWASUSER: u16 = 314;
pub const RPL_ENDOFWHOWAS: u16 = 369;
pub const ERR_WASNOSUCHNICK: u16 = 406;

// --- HELP ---
pub const ERR_HELPNOTFOUND: u16 = 524;
pub const RPL_HELPSTART: u16 = 704;
pub const RPL_HELPTXT: u16 = 705;
pub const RPL_ENDOFHELP: u16 = 706;

// --- KNOCK ---
pub const RPL_KNOCK: u16 = 710;
pub const RPL_KNOCKDLVR: u16 = 711;
pub const ERR_CHANOPEN: u16 = 713;
pub const ERR_KNOCKONCHAN: u16 = 714;

// --- Modes / WHOIS / WHO / NAMES / TOPIC ---
pub const RPL_UMODEIS: u16 = 221;
pub const RPL_WHOISUSER: u16 = 311;
pub const RPL_WHOISSERVER: u16 = 312;
pub const RPL_WHOISOPERATOR: u16 = 313;
pub const RPL_WHOISIDLE: u16 = 317;
pub const RPL_WHOISSECURE: u16 = 671;
pub const RPL_WHOISACTUALLY: u16 = 338;
pub const RPL_WHOSPCRPL: u16 = 354;
pub const RPL_ENDOFWHO: u16 = 315;
pub const RPL_LISTSTART: u16 = 321;
pub const RPL_LIST: u16 = 322;
pub const RPL_LISTEND: u16 = 323;
pub const RPL_ENDOFWHOIS: u16 = 318;
pub const RPL_WHOISCHANNELS: u16 = 319;
pub const RPL_CHANNELMODEIS: u16 = 324;
pub const RPL_CREATIONTIME: u16 = 329;
pub const RPL_NOTOPIC: u16 = 331;
pub const RPL_TOPIC: u16 = 332;
pub const RPL_TOPICWHOTIME: u16 = 333;
pub const RPL_WHOREPLY: u16 = 352;
pub const RPL_NAMREPLY: u16 = 353;
pub const RPL_ENDOFNAMES: u16 = 366;

// --- MOTD ---
pub const RPL_MOTDSTART: u16 = 375;
pub const RPL_MOTD: u16 = 372;
pub const RPL_ENDOFMOTD: u16 = 376;

// --- Errors ---
pub const ERR_NOSUCHNICK: u16 = 401;
pub const ERR_NOSUCHCHANNEL: u16 = 403;
pub const ERR_CANNOTSENDTOCHAN: u16 = 404;
pub const ERR_INVALIDCAPCMD: u16 = 410;
pub const ERR_NORECIPIENT: u16 = 411;
pub const ERR_NOTEXTTOSEND: u16 = 412;
pub const ERR_UNKNOWNCOMMAND: u16 = 421;
pub const ERR_NOMOTD: u16 = 422;
pub const ERR_NONICKNAMEGIVEN: u16 = 431;
pub const ERR_ERRONEUSNICKNAME: u16 = 432;
pub const ERR_NICKNAMEINUSE: u16 = 433;
pub const ERR_USERNOTINCHANNEL: u16 = 441;
pub const ERR_NOTONCHANNEL: u16 = 442;
pub const ERR_USERONCHANNEL: u16 = 443;
pub const ERR_NOTREGISTERED: u16 = 451;
pub const ERR_PASSWDMISMATCH: u16 = 464;
pub const ERR_NEEDMOREPARAMS: u16 = 461;
pub const ERR_ALREADYREGISTERED: u16 = 462;
pub const ERR_TOOMANYCHANNELS: u16 = 405;
pub const ERR_CHANNELISFULL: u16 = 471;
pub const ERR_UNKNOWNMODE: u16 = 472;
pub const ERR_INVITEONLYCHAN: u16 = 473;
pub const ERR_BANNEDFROMCHAN: u16 = 474;
pub const ERR_BADCHANNELKEY: u16 = 475;
pub const ERR_CHANOPRIVSNEEDED: u16 = 482;
pub const ERR_UMODEUNKNOWNFLAG: u16 = 501;
pub const ERR_USERSDONTMATCH: u16 = 502;
