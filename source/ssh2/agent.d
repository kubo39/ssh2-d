module ssh2.agent;

private import ssh2.ffi;
import ssh2.exception;
import ssh2.session;

class Agent
{
private:
    LIBSSH2_AGENT* raw;
    LIBSSH2_SESSION* session;

package:
    this(LIBSSH2_AGENT* raw, LIBSSH2_SESSION* session) @nogc nothrow
    {
        this.raw = raw;
        this.session = session;
    }

    class Identities
    {
    private:
        libssh2_agent_publickey* prev;
        Agent agent;
        PublicKey publicKey;

        void getIdentity(libssh2_agent_publickey* prev)
        {
            libssh2_agent_publickey* next;
            auto rc = libssh2_agent_get_identity(this.agent.raw, &next, prev);
            if (rc == 0)
            {
                this.prev = next;
                this.publicKey = new PublicKey(this.prev);
            }
            else if (rc == 1)
            {
                this.prev = null;
                this.publicKey = null;
            }
            else
                throw new SessionError(this.agent.session, rc);
        }
    package:
        this(Agent agent)
        {
            this.agent = agent;
            getIdentity(null);
        }

    public:
        bool empty() @nogc nothrow pure
        {
            return this.prev is null;
        }

        void popFront()
        {
            getIdentity(this.prev);
        }

        PublicKey front() @nogc nothrow pure
        {
            return this.publicKey;
        }
    }

    import std.range : isInputRange;
    static assert(isInputRange!Identities);

public:
    ~this() @nogc nothrow
    {
        libssh2_agent_free(this.raw);
    }

    /// Connect to an ssh-agent running on the system.
    void connect()
    {
        auto rc = libssh2_agent_connect(this.raw);
        if (rc < 0)
            throw new SessionError(this.session, rc);
    }

    /// Close connection to an ssh-agent.
    void disconnect()
    {
        auto rc = libssh2_agent_disconnect(this.raw);
        if (rc < 0)
            throw new SessionError(this.session, rc);
    }

    /// Request a ssh-agent to list of public keys and stores them
    /// into the internal collection of the handle.
    void listIdentities()
    {
        auto rc = libssh2_agent_list_identities(this.raw);
        if (rc < 0)
            throw new SessionError(this.session, rc);
    }

    /// Get a range over the identities of this agent.
    Identities identities()
    {
        return new Identities(this);
    }

    /// Attempt public key authentication.
    void userauth(string username, PublicKey identity)
    {
        import std.string : toStringz;
        auto rc = libssh2_agent_userauth(
            this.raw,
            username.toStringz,
            identity.raw);
        if (rc < 0)
            throw new SessionError(this.session, rc);
    }
}

class PublicKey
{
package:
    libssh2_agent_publickey* raw;

    this(libssh2_agent_publickey* raw) @nogc nothrow pure
    {
        this.raw = raw;
    }

public:
    /// Returns the data of this public key.
    const(ubyte)[] blob() @nogc nothrow pure
    {
        return this.raw.blob[0 ..this.raw.blob_len];
    }

    /// Returns the comment.
    string comment() @nogc nothrow pure
    {
        import std.string : fromStringz;
        return cast(immutable) this.raw.comment.fromStringz;
    }
}
