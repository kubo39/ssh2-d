module ssh2.ffi;

import core.stdc.config : c_long;

extern(C):
@nogc:
nothrow:
@system:

enum LIBSSH2_FLAG_COMPRESS = 2;

enum LIBSSH2_HOSTKEY_TYPE_UNKNOWN = 0;
enum LIBSSH2_HOSTKEY_TYPE_RSA = 1;
enum LIBSSH2_HOSTKEY_TYPE_DSS = 2;
enum LIBSSH2_HOSTKEY_TYPE_ECDSA_256 = 3;
enum LIBSSH2_HOSTKEY_TYPE_ECDSA_384 = 4;
enum LIBSSH2_HOSTKEY_TYPE_ECDSA_521 = 5;
enum LIBSSH2_HOSTKEY_TYPE_ED25519 = 6;

enum LIBSSH2_METHOD_KEX = 0;
enum LIBSSH2_METHOD_HOSTKEY = 1;
enum LIBSSH2_METHOD_CRYPT_CS = 2;
enum LIBSSH2_METHOD_CRYPT_SC = 3;
enum LIBSSH2_METHOD_MAC_CS = 4;
enum LIBSSH2_METHOD_MAC_SC = 5;
enum LIBSSH2_METHOD_COMP_CS = 6;
enum LIBSSH2_METHOD_COMP_SC = 7;
enum LIBSSH2_METHOD_LANG_CS = 8;
enum LIBSSH2_METHOD_LANG_SC = 9;

enum uint LIBSSH2_CHANNEL_WINDOW_DEFAULT = 32768;
enum uint LIBSSH2_CHANNEL_PACKET_DEFAULT = 2 * 1024 * 1024;

enum LIBSSH2_ERROR_BANNER_RECV = -2;
enum LIBSSH2_ERROR_BANNER_SEND = -3;
enum LIBSSH2_ERROR_INVALID_MAC = -4;
enum LIBSSH2_ERROR_KEX_FAILURE = -5;
enum LIBSSH2_ERROR_ALLOC = -6;
enum LIBSSH2_ERROR_SOCKET_SEND = -7;
enum LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE = -8;
enum LIBSSH2_ERROR_TIMEOUT = -9;
enum LIBSSH2_ERROR_HOSTKEY_INIT = -10;
enum LIBSSH2_ERROR_HOSTKEY_SIGN = -11;
enum LIBSSH2_ERROR_DECRYPT = -12;
enum LIBSSH2_ERROR_SOCKET_DISCONNECT = -13;
enum LIBSSH2_ERROR_PROTO = -14;
enum LIBSSH2_ERROR_PASSWORD_EXPIRED = -15;
enum LIBSSH2_ERROR_FILE = -16;
enum LIBSSH2_ERROR_METHOD_NONE = -17;
enum LIBSSH2_ERROR_AUTHENTICATION_FAILED = -18;
enum LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED = LIBSSH2_ERROR_AUTHENTICATION_FAILED;
enum LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED = -19;
enum LIBSSH2_ERROR_CHANNEL_OUTOFORDER = -20;
enum LIBSSH2_ERROR_CHANNEL_FAILURE = -21;
enum LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED = -22;
enum LIBSSH2_ERROR_CHANNEL_UNKNOWN = -23;
enum LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED = -24;
enum LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED = -25;
enum LIBSSH2_ERROR_CHANNEL_CLOSED = -26;
enum LIBSSH2_ERROR_CHANNEL_EOF_SENT = -27;
enum LIBSSH2_ERROR_SCP_PROTOCOL = -28;
enum LIBSSH2_ERROR_ZLIB = -29;
enum LIBSSH2_ERROR_SOCKET_TIMEOUT = -30;
enum LIBSSH2_ERROR_SFTP_PROTOCOL = -31;
enum LIBSSH2_ERROR_REQUEST_DENIED = -32;
enum LIBSSH2_ERROR_METHOD_NOT_SUPPORTED = -33;
enum LIBSSH2_ERROR_INVAL = -34;
enum LIBSSH2_ERROR_INVALID_POLL_TYPE = -35;
enum LIBSSH2_ERROR_PUBLICKEY_PROTOCOL = -36;
enum LIBSSH2_ERROR_EAGAIN = -37;
enum LIBSSH2_ERROR_BUFFER_TOO_SMALL = -38;
enum LIBSSH2_ERROR_BAD_USE = -39;
enum LIBSSH2_ERROR_COMPRESS = -40;
enum LIBSSH2_ERROR_OUT_OF_BOUNDARY = -41;
enum LIBSSH2_ERROR_AGENT_PROTOCOL = -42;
enum LIBSSH2_ERROR_SOCKET_RECV = -43;
enum LIBSSH2_ERROR_ENCRYPT = -44;
enum LIBSSH2_ERROR_BAD_SOCKET = -45;
enum LIBSSH2_ERROR_KNOWN_HOSTS = -46;

enum LIBSSH2_FX_EOF = 1;
enum LIBSSH2_FX_NO_SUCH_FILE = 2;
enum LIBSSH2_FX_PERMISSION_DENIED = 3;
enum LIBSSH2_FX_FAILURE = 4;
enum LIBSSH2_FX_BAD_MESSAGE = 5;
enum LIBSSH2_FX_NO_CONNECTION = 6;
enum LIBSSH2_FX_CONNECTION_LOST = 7;
enum LIBSSH2_FX_OP_UNSUPPORTED = 8;
enum LIBSSH2_FX_INVALID_HANDLE = 9;
enum LIBSSH2_FX_NO_SUCH_PATH = 10;
enum LIBSSH2_FX_FILE_ALREADY_EXISTS = 11;
enum LIBSSH2_FX_WRITE_PROTECT = 12;
enum LIBSSH2_FX_NO_MEDIA = 13;
enum LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM = 14;
enum LIBSSH2_FX_QUOTA_EXCEEDED = 15;
enum LIBSSH2_FX_UNKNOWN_PRINCIPAL = 16;
enum LIBSSH2_FX_LOCK_CONFLICT = 17;
enum LIBSSH2_FX_DIR_NOT_EMPTY = 18;
enum LIBSSH2_FX_NOT_A_DIRECTORY = 19;
enum LIBSSH2_FX_INVALID_FILENAME = 20;
enum LIBSSH2_FX_LINK_LOOP = 21;

enum LIBSSH2_HOSTKEY_HASH_MD5 = 1;
enum LIBSSH2_HOSTKEY_HASH_SHA1 = 2;
enum LIBSSH2_HOSTKEY_HASH_SHA256 = 3;

enum LIBSSH2_INIT_NO_CRYPTO = 0x1;

enum LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL = 0;
enum LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE = 1;
enum LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE = 2;

enum LIBSSH2_SESSION_BLOCK_INBOUND = 1;
enum LIBSSH2_SESSION_BLOCK_OUTBOUND = 2;

struct LIBSSH2_SESSION;
struct LIBSSH2_AGENT;
struct LIBSSH2_CHANNEL;
struct LIBSSH2_KNOWNHOSTS;

struct libssh2_agent_publickey
{
    uint magic;
    void* node;
    ubyte* blob;
    size_t blob_len;
    char* comment;
}

struct libssh2_knownhost
{
    uint magic;
    void* node;
    char* name;
    char* key;
    int typemask;
}

alias LIBSSH2_ALLOC_FUNC = void* function(size_t, void**);
alias LIBSSH2_FREE_FUNC = void function(void*, void**);
alias LIBSSH2_REALLOC_FUNC = void* function(void*, size_t, void**);

version (Posix) alias libssh2_socket_t = int;
version (Win32) alias libssh2_socket_t = uint;
version (Win64) alias libssh2_socket_t = ulong;

// misc
int libssh2_init(int flag);
int libssh2_exit();
const(ubyte)* libssh2_free(LIBSSH2_SESSION* sess, void* ptr);
const(ubyte)* libssh2_hostkey_hash(LIBSSH2_SESSION* session, int hash_type);

// session
LIBSSH2_SESSION* libssh2_session_init_ex(
    LIBSSH2_ALLOC_FUNC* my_alloc,
    LIBSSH2_FREE_FUNC* my_free,
    LIBSSH2_REALLOC_FUNC* my_realloc,
    void* abstrakt);
void** libssh2_session_abstract(LIBSSH2_SESSION* session);
int libssh2_session_free(LIBSSH2_SESSION* sess);
const(char)* libssh2_session_banner_get(LIBSSH2_SESSION* sess);
int libssh2_session_banner_set(LIBSSH2_SESSION* sess, const(char)* banner);
int libssh2_session_disconnect_ex(
    LIBSSH2_SESSION* sess,
    int reason,
    const(char)* description,
    const(char)* lang);
int libssh2_session_flag(LIBSSH2_SESSION* sess, int flag, int value);
int libssh2_session_get_blocking(LIBSSH2_SESSION* session);
c_long libssh2_session_get_timeout(LIBSSH2_SESSION* sess);
const(ubyte)* libssh2_session_hostkey(
    LIBSSH2_SESSION* sess,
    size_t* len,
    int* kind);
int libssh2_session_method_pref(
    LIBSSH2_SESSION* sess,
    int method_type,
    const(char)* prefs);
const(char)* libssh2_session_methods(LIBSSH2_SESSION* sess, int method_type);
void libssh2_session_set_blocking(LIBSSH2_SESSION* session, int blocking);
void libssh2_session_set_timeout(LIBSSH2_SESSION* session, c_long timeout);
int libssh2_session_supported_algs(
    LIBSSH2_SESSION* session,
    int method_type,
    const(char)** algs);
int libssh2_session_last_error(
    LIBSSH2_SESSION* sess,
    char** msg,
    int* len,
    int want_buf);
int libssh2_session_handshake(LIBSSH2_SESSION* sess, libssh2_socket_t socket);
void libssh2_keepalive_config(
    LIBSSH2_SESSION* sess,
    int want_reply,
    uint interval);
int libssh2_keepalive_send(LIBSSH2_SESSION* sess, int* seconds_to_next);
int libssh2_session_block_directions(LIBSSH2_SESSION* sess);

// agent
LIBSSH2_AGENT* libssh2_agent_init(LIBSSH2_SESSION* sess);
void libssh2_agent_free(LIBSSH2_AGENT* agent);
int libssh2_agent_connect(LIBSSH2_AGENT* agent);
int libssh2_agent_disconnect(LIBSSH2_AGENT* agent);
int libssh2_agent_list_identities(LIBSSH2_AGENT* agent);
int libssh2_agent_get_identity(
    LIBSSH2_AGENT* agent,
    libssh2_agent_publickey** store,
    libssh2_agent_publickey* prev);
int libssh2_agent_userauth(
    LIBSSH2_AGENT* agent,
    const(char)* username,
    libssh2_agent_publickey* identity);

// channel
int libssh2_channel_free(LIBSSH2_CHANNEL* chan);
int libssh2_channel_close(LIBSSH2_CHANNEL* chan);
int libssh2_channel_wait_closed(LIBSSH2_CHANNEL* chan);
int libssh2_channel_wait_eof(LIBSSH2_CHANNEL* chan);
int libssh2_channel_eof(LIBSSH2_CHANNEL* chan);
int libssh2_channel_process_startup(
    LIBSSH2_CHANNEL* chan,
    const(char)* req,
    uint req_len,
    const(char)* msg,
    uint msg_len);
int libssh2_channel_flush_ex(LIBSSH2_CHANNEL* chan, int streamid);
int libssh2_channel_send_eof(LIBSSH2_CHANNEL* chan);
int libssh2_channel_request_pty_ex(
    LIBSSH2_CHANNEL* chan,
    const(char)* term,
    uint termlen,
    const(ubyte)* modes,
    uint modeslen,
    int width,
    int height,
    int width_px,
    int height_px);
ptrdiff_t libssh2_channel_write_ex(
    LIBSSH2_CHANNEL* chan,
    int stream_id,
    const(ubyte)* buf,
    size_t buflen);
int libssh2_channel_get_exit_status(LIBSSH2_CHANNEL* chan);
LIBSSH2_CHANNEL* libssh2_channel_open_ex(
    LIBSSH2_SESSION* sess,
    const(char)* channel_type,
    uint channel_type_len,
    uint window_size,
    uint packet_size,
    const(char)* message,
    uint message_len);
ptrdiff_t libssh2_channel_read_ex(
    LIBSSH2_CHANNEL* chan,
    int stream_id,
    ubyte* buf,
    size_t buflen);
int libssh2_channel_receive_window_adjust2(
    LIBSSH2_CHANNEL* chan,
    ulong adjust,
    ubyte force,
    uint* window);
int libssh2_channel_handle_extended_data2(LIBSSH2_CHANNEL* channel, int mode);

// userauth
int libssh2_userauth_authenticated(LIBSSH2_SESSION* sess);
const(char)* libssh2_userauth_list(
    LIBSSH2_SESSION* sess,
    const(char)* username,
    uint username_len);

// knownhosts
void libssh2_knownhost_free(LIBSSH2_KNOWNHOSTS* hosts);
int libssh2_knownhost_get(
    LIBSSH2_KNOWNHOSTS* hosts,
    libssh2_knownhost** store,
    libssh2_knownhost* prev);
LIBSSH2_KNOWNHOSTS* libssh2_knownhost_init(LIBSSH2_SESSION* sess);
