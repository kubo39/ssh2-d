module ssh2.session;

private import ssh2.ffi;
import ssh2.exception;

import core.time : dur, Duration;
import core.stdc.config : c_long;

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

alias HostKey = Tuple!(const(ubyte)[], "data", HostKeyType, "type");


/// An SSH session.
class Session
{
private:
    LIBSSH2_SESSION* raw;

public:

    /// Initialize an SSH session object.
    this()
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
        const rc = libssh2_session_banner_set(this.raw, banner.toStringz);
        if (rc < 0)
            throw new SessionError(this.raw, rc);
    }

    /// Get the remote banner.
    string banner()
    {
        import std.string : fromStringz;
        auto ret = libssh2_session_banner_get(this.raw);
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
    void timeout(Duration timeout)
    {
        const timeout_ms = cast(c_long) timeout.total!"msecs";
        libssh2_session_set_timeout(this.raw, timeout_ms);
    }

    /// Returns the timeout, in milliseconds, for how long blocking calls may
    /// wait until they time-out.
    ///
    /// A timeout of 0 means no timeout.
    Duration timeout()
    {
        const timeout_ms = libssh2_session_get_timeout(this.raw);
        return dur!"msecs"(timeout_ms);
    }

    /// Flag indicating whether this library will attempt to negotiate
    /// Compression.
    void compress(bool flag)
    {
        const rc = libssh2_session_flag(
            this.raw,
            cast(int) LIBSSH2_FLAG_COMPRESS,
            cast(int) flag);
        if (rc < 0)
            throw new SessionError(this.raw, rc);
    }

    /// Get the remote key.
    HostKey hostKey() nothrow
    {
        size_t len;
        int kind;
        const ret = libssh2_session_hostkey(this.raw, &len, &kind);
        if (ret is null)
            return HostKey.init;
        const data = ret[0 .. len];
        HostKeyType type;
        switch (kind)
        {
        case LIBSSH2_HOSTKEY_TYPE_RSA:
            type = HostKeyType.RSA;
            break;
        case LIBSSH2_HOSTKEY_TYPE_DSS:
            type = HostKeyType.DSS;
            break;
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_256:
            type = HostKeyType.ECDSA256;
            break;
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_384:
            type = HostKeyType.ECDSA384;
            break;
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_521:
            type = HostKeyType.ECDSA521;
            break;
        case LIBSSH2_HOSTKEY_TYPE_UNKNOWN:
            type = HostKeyType.UNKNOWN;
            break;
        default:
            type = HostKeyType.UNKNOWN;
            break;
        }
        HostKey hostKey;
        hostKey.data = data;
        hostKey.type = type;
        return hostKey;
    }

    /// Set preferred key exchange method.
    void methodPref(MethodType method_type, string prefs)
    {
        import std.string : toStringz;
        const rc = libssh2_session_method_pref(
            this.raw,
            cast(int) method_type,
            prefs.toStringz
            );
        if (rc < 0)
            throw new SessionError(this.raw, rc);
    }

    /// Returns the currently active algorithm.
    string methods(MethodType method_type)
    {
        import std.string : fromStringz;
        const ptr = libssh2_session_methods(this.raw, cast(int) method_type);
        return cast(immutable) ptr.fromStringz;
    }
}
