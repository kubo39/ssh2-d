module ssh2.session;

private import ssh2.ffi;
import ssh2.agent;
import ssh2.channel;
import ssh2.exception;
import ssh2.knownhosts;

import core.time : dur, Duration;
import core.stdc.config : c_long;

import std.socket : TcpSocket;
import std.typecons : Tuple;


enum HostKeyType
{
    UNKNOWN = LIBSSH2_HOSTKEY_TYPE_UNKNOWN,
    RSA = LIBSSH2_HOSTKEY_TYPE_RSA,
    DSS = LIBSSH2_HOSTKEY_TYPE_DSS,
    ECDSA256 = LIBSSH2_HOSTKEY_TYPE_ECDSA_256,
    ECDSA384 = LIBSSH2_HOSTKEY_TYPE_ECDSA_384,
    ECDSA521 = LIBSSH2_HOSTKEY_TYPE_ECDSA_521,
    ED25519 = LIBSSH2_HOSTKEY_TYPE_ED25519,
}

enum MethodType
{
    KEX = LIBSSH2_METHOD_KEX,
    HOSTKEY = LIBSSH2_METHOD_HOSTKEY,
    CRYPT_CS = LIBSSH2_METHOD_CRYPT_CS,
    CRYPT_SC = LIBSSH2_METHOD_CRYPT_SC,
    MAC_CS = LIBSSH2_METHOD_MAC_CS,
    MAC_SC = LIBSSH2_METHOD_MAC_SC,
    COMP_CS = LIBSSH2_METHOD_COMP_CS,
    COMP_SC = LIBSSH2_METHOD_COMP_SC,
    LANG_CS = LIBSSH2_METHOD_LANG_CS,
    LANG_SC = LIBSSH2_METHOD_LANG_SC,
}

enum HashType
{
    MD5 = LIBSSH2_HOSTKEY_HASH_MD5,
    SHA1 = LIBSSH2_HOSTKEY_HASH_SHA1,
    SHA256 = LIBSSH2_HOSTKEY_HASH_SHA256,
}

alias HostKey = Tuple!(const(ubyte)[], "data", HostKeyType, "type");


/// An SSH session.
class Session
{
private:
    TcpSocket sock;
    LIBSSH2_SESSION* raw;

public:

    /// Initialize an SSH session object.
    this() @nogc
    {
        this.raw = libssh2_session_init_ex(null, null, null, null);
        assert(this.raw !is null);
    }

    ~this()
    {
        libssh2_session_free(this.raw);
    }

    /// Set the SSH protocol banner for the local client.
    void banner(string banner)
    {
        import std.string : toStringz;
        auto rc = libssh2_session_banner_set(this.raw, banner.toStringz);
        if (rc < 0)
            throw new SessionError(this.raw, rc);
    }

    /// Get the remote banner.
    string banner() @nogc nothrow
    {
        import std.string : fromStringz;
        const ret = libssh2_session_banner_get(this.raw);
        return cast(immutable) ret.fromStringz;
    }

    /// Set or clear blocking mode on the session.
    void blocking(bool flag) @nogc nothrow
    {
        libssh2_session_set_blocking(this.raw, cast(int) flag);
    }

    /// Returns whether the session is blocking.
    bool blocking() @nogc nothrow
    {
        return libssh2_session_get_blocking(this.raw) != 0;
    }

    /// Set timeout for blocking functions.
    ///
    /// By default: 0, and this means libssh2 has not timeout for blocking
    /// functions.
    void timeout(Duration timeout) @nogc nothrow
    {
        auto timeout_ms = cast(c_long) timeout.total!"msecs";
        libssh2_session_set_timeout(this.raw, timeout_ms);
    }

    /// Returns the timeout, in milliseconds, for how long blocking calls may
    /// wait until they time-out.
    ///
    /// A timeout of 0 means no timeout.
    Duration timeout() @nogc nothrow
    {
        auto timeout_ms = libssh2_session_get_timeout(this.raw);
        return dur!"msecs"(timeout_ms);
    }

    /// Flag indicating whether this library will attempt to negotiate
    /// Compression.
    void compress(bool flag)
    {
        auto rc = libssh2_session_flag(
            this.raw,
            cast(int) LIBSSH2_FLAG_COMPRESS,
            cast(int) flag);
        if (rc < 0)
            throw new SessionError(this.raw, rc);
    }

    /// Get the remote key.
    HostKey hostKey() @nogc nothrow
    {
        size_t len;
        int kind;
        const ret = libssh2_session_hostkey(this.raw, &len, &kind);
        if (ret is null)
            return HostKey.init;
        const data = ret[0 .. len];
        auto type = () @nogc nothrow pure @safe {
            switch (kind)
            {
            case LIBSSH2_HOSTKEY_TYPE_RSA: return HostKeyType.RSA;
            case LIBSSH2_HOSTKEY_TYPE_DSS: return HostKeyType.DSS;
            case LIBSSH2_HOSTKEY_TYPE_ECDSA_256: return HostKeyType.ECDSA256;
            case LIBSSH2_HOSTKEY_TYPE_ECDSA_384: return HostKeyType.ECDSA384;
            case LIBSSH2_HOSTKEY_TYPE_ECDSA_521: return HostKeyType.ECDSA521;
            case LIBSSH2_HOSTKEY_TYPE_UNKNOWN: return HostKeyType.UNKNOWN;
            default: return HostKeyType.UNKNOWN;
            }
        } ();
        HostKey hostKey;
        hostKey.data = data;
        hostKey.type = type;
        return hostKey;
    }

    /// Set preferred key exchange method.
    void methodPref(MethodType method_type, string prefs)
    {
        import std.string : toStringz;
        auto rc = libssh2_session_method_pref(
            this.raw,
            cast(int) method_type,
            prefs.toStringz
            );
        if (rc < 0)
            throw new SessionError(this.raw, rc);
    }

    /// Returns the currently active algorithm.
    string methods(MethodType method_type) @nogc nothrow
    {
        import std.string : fromStringz;
        const ptr = libssh2_session_methods(this.raw, cast(int) method_type);
        return cast(immutable) ptr.fromStringz;
    }

    /// Get list of supported algorithm.
    string[] supprtedAlgs(MethodType method_type)
    {
        import std.string : fromStringz;
        string[] ret;
        const(char)* algs;
        auto rc = libssh2_session_supported_algs(this.raw, cast(int) method_type, &algs);
        if (rc <= 0)
            throw new SessionError(this.raw, rc);
        foreach (i; 0 .. rc)
        {
            const(char)* ptr = (algs + i);
            ret = ret ~ cast(immutable) ptr.fromStringz;
        }
        libssh2_free(this.raw, cast(void*) algs);
        return ret;
    }

    ///
    void setSock(TcpSocket sock) @nogc nothrow
    {
        this.sock = sock;
    }

    /// Begin transport layer protocol negotiation with the connected host.
    void handshake()
    {
        if (this.sock is null)
            throw new SessionErrnoException(LIBSSH2_ERROR_BAD_SOCKET);
        auto rc = libssh2_session_handshake(this.raw, this.sock.handle);
        if (rc < 0)
            throw new SessionError(this.raw, rc);
    }

    /// Send a SSH_USERAUTH_NONE request to the remote host.
    string authMethods(string username) nothrow
    {
        import std.string : fromStringz, toStringz;
        const ret = libssh2_userauth_list(
            this.raw,
            username.toStringz,
            cast(uint) username.length
            );
        if (ret is null)
            assert(false);
        return cast(immutable) ret.fromStringz;
    }

    /// Wheter the named session has been authenticated or not.
    bool authenticated() @nogc nothrow
    {
        return libssh2_userauth_authenticated(this.raw) != 0;
    }

    /// Initialize ssh-agent handle.
    Agent agent()
    {
        auto ptr = libssh2_agent_init(this.raw);
        if (ptr is null)
            throw new SessionErrnoException(LIBSSH2_ERROR_ALLOC);
        return new Agent(ptr, this.raw);
    }

    /// Initialize a collection of knownhosts for this session.
    Knownhosts knownhosts()
    {
        auto ptr = libssh2_knownhost_init(this.raw);
        if (ptr is null)
            throw new SessionErrnoException(LIBSSH2_ERROR_ALLOC);
        return new Knownhosts(ptr, this.raw);
    }

    /// Returns computed digest of the remote system's hostkey.
    const(ubyte)[] hostKeyHash(HashType hash) @nogc nothrow
    {
        size_t len = () @safe @nogc nothrow {
            final switch (hash)
            {
            case HashType.MD5: return 16;
            case HashType.SHA1: return 20;
            case HashType.SHA256: return 32;
            }
        } ();
        const ret = libssh2_hostkey_hash(this.raw, hash);
        if (ret is null)
            return null;
        return ret[0 .. len];
    }

    /// Establish new session-based channel.
    Channel channelSession()
    {
        return this.channelOpen(
            "session",
            LIBSSH2_CHANNEL_WINDOW_DEFAULT,
            LIBSSH2_CHANNEL_PACKET_DEFAULT,
            null);
    }

    /// Allocate new channel to exchange data with server.
    Channel channelOpen(string channel_type, uint window_size,
                        uint packet_size, string message)
    {
        import std.string : toStringz;

        const msg = message.length ? message.toStringz : null;
        auto ptr = libssh2_channel_open_ex(
            this.raw,
            channel_type.toStringz,
            cast(uint) channel_type.length,
            window_size,
            packet_size,
            msg,
            cast(uint) message.length);
        if (ptr is null)
            throw new SessionErrnoException(LIBSSH2_ERROR_ALLOC);
        return new Channel(ptr, this.raw);
    }
}
