module ssh2.knownhosts;

private import ssh2.ffi;
import ssh2.exception;

class Knownhosts
{
private:
    LIBSSH2_KNOWNHOSTS* raw;
    LIBSSH2_SESSION* session;

package:
    this(LIBSSH2_KNOWNHOSTS* raw, LIBSSH2_SESSION* session)
    {
        this.raw = raw;
        this.session = session;
    }

    class Hosts
    {
    private:
        Knownhosts knownhosts;
        libssh2_knownhost* prev;
        Host host;

        void getKnownhost(libssh2_knownhost* prev)
        {
            libssh2_knownhost* next;
            auto rc = libssh2_knownhost_get(this.knownhosts.raw, &next, prev);
            if (rc == 0)
            {
                this.prev = next;
                this.host = new Host(this.prev);
            }
            if (rc == 1)
            {
                this.prev = null;
                this.host = null;
            }
            else
                throw new SessionError(this.knownhosts.session, rc);
        }

        this(Knownhosts knownhosts)
        {
            this.knownhosts = knownhosts;
            getKnownhost(null);
        }

    public:
        bool empty() @nogc nothrow pure
        {
            return this.prev is null;
        }

        void popFront()
        {
            getKnownhost(this.prev);
        }

        Host front() @nogc nothrow pure
        {
            return this.host;
        }
    }

    import std.range : isInputRange;
    static assert(isInputRange!Hosts);

public:
    ~this()
    {
        libssh2_knownhost_free(this.raw);
    }

    auto opSlice()
    {
        return new Hosts(this);
    }
}

class Host
{
private:
    libssh2_knownhost* raw;

package:
    this(libssh2_knownhost* raw)
    {
        this.raw = raw;
    }
}
