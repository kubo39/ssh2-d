module ssh2.agent;

private import ssh2.ffi;
import ssh2.exception;
import ssh2.session;

class Agent
{
private:
    LIBSSH2_AGENT* raw;
    Session session;

package:
    this(LIBSSH2_AGENT* raw, Session session)
    {
        this.raw = raw;
        this.session = session;
    }

    ~this()
    {
        libssh2_agent_free(this.raw);
    }

public:
    /// Connect to an ssh-agent running on the system.
    void connect()
    {
        const rc = libssh2_agent_connect(this.raw);
        if (rc < 0)
            throw new SessionError(this.session.raw, rc);
    }

    /// Close connection to an ssh-agent.
    void disconnect()
    {
        const rc = libssh2_agent_disconnect(this.raw);
        if (rc < 0)
            throw new SessionError(this.session.raw, rc);
    }

    /// Request a ssh-agent to list of public keys and stores them
    /// into the internal collection of the handle.
    void listIdentities()
    {
        const rc = libssh2_agent_list_identities(this.raw);
        if (rc < 0)
            throw new SessionError(this.session.raw, rc);
    }

    /// Get a range over the identities of this agent.
    Identities identities()
    {
        return new Identities(this);
    }

    class Identities
    {
    private:
        libssh2_agent_publickey* prev;

        void getIdentity(libssh2_agent_publickey* prev)
        {
            libssh2_agent_publickey* next;
            const rc = libssh2_agent_get_identity(this.agent.raw, &next, prev);
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
                throw new SessionError(this.agent.session.raw, rc);
        }

    public:
        Agent agent;
        PublicKey* publicKey;

        this(Agent agent)
        {
            this.agent = agent;
            getIdentity(null);
        }

        bool empty() @nogc nothrow
        {
            return this.prev is null;
        }

        void popFront()
        {
            getIdentity(this.prev);
        }

        PublicKey* front() @nogc nothrow
        {
            return this.publicKey;
        }
    }

    /// Attempt public key authentication.
    void userauth(string username, PublicKey* identity)
    {
        import std.string : toStringz;
        const rc = libssh2_agent_userauth(
            this.raw,
            username.toStringz,
            identity.raw);
        if (rc < 0)
            throw new SessionError(this.session.raw, rc);
    }
}

struct PublicKey
{
package:
    libssh2_agent_publickey* raw;

public:
    /// Returns the data of this public key.
    const(ubyte)[] blob() @nogc nothrow
    {
        return this.raw.blob[0 ..this.raw.blob_len];
    }

    /// Returns the comment.
    string comment() @nogc nothrow
    {
        import std.string : fromStringz;
        return cast(immutable) this.raw.comment.fromStringz;
    }
}