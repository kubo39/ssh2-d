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
}
