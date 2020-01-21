import ssh2.session;

import std.socket : InternetAddress;

/**
 *  Utilities.
 */

InternetAddress testAddress() @safe
{
    import std.conv : parse;
    import std.process : environment;

    auto s = environment.get("D_SSH2_FIXTURE_PORT", "22");
    auto port = parse!ushort(s);
    return new InternetAddress("127.0.0.1", port);
}

Session authedSession()
{
    import std.process : environment;
    import std.socket : TcpSocket;

    auto user = environment["USER"];
    auto socket = new TcpSocket(testAddress());
    auto sess = new Session;
    sess.setSock(socket);
    sess.handshake();
    assert(!sess.authenticated());

    {
        auto agent = sess.agent();
        agent.connect();
        agent.listIdentities();
        auto identity = agent.identities().front;
        agent.userauth(user, identity);
    }
    assert(sess.authenticated());
    return sess;
}

/**
 *  Session.
 */

void smokeSession()
{
    import core.time : msecs;

    auto sess = new Session();
    sess.banner("foo");
    assert(sess.blocking);
    assert(sess.timeout == 0.msecs);
    sess.compress(true);
    assert(sess.hostKey() == HostKey.init);
    sess.methodPref(MethodType.KEX, "diffie-hellman-group14-sha1");
    assert(sess.methods(MethodType.KEX) is null);
    sess.blocking(true);
    sess.timeout(0.msecs);
    assert(sess.supprtedAlgs(MethodType.KEX).length > 0);
    assert(sess.supprtedAlgs(MethodType.HOSTKEY).length > 0);
}

void smokeSessionHandshake()
{
    import std.process : environment;
    import std.socket : TcpSocket;
    import std.string : indexOf;

    auto user = environment["USER"];
    auto sock = new TcpSocket(testAddress());
    auto sess = new Session();
    sess.setSock(sock);
    sess.handshake();
    sess.hostKey();
    auto methods = sess.authMethods(user);
    assert(methods.indexOf("publickey") >= 0, methods);
    assert(!sess.authenticated());

    auto agent = sess.agent();
    agent.connect();
    agent.listIdentities();
    {
        auto identity = agent.identities().front();
        assert(identity !is null);
        agent.userauth(user, identity);
    }
    assert(sess.authenticated());
    assert(sess.hostKeyHash(HashType.MD5) !is null);
}

void keyboardInteractive()
{
    import std.format : format;
    import std.process : environment;
    import std.socket : TcpSocket;
    import std.string : indexOf;

    auto user = environment["USER"];
    auto address = testAddress();
    auto socket = new TcpSocket(address);
    auto sess = new Session;
    sess.setSock(socket);
    sess.handshake();
    sess.hostKey();
    auto methods = sess.authMethods(user);
    assert(methods.indexOf("keyboard-interactive"),
           format!"test server (%s) must support `ChallengeResponseAuthentication yes`, not just %s"(address, methods));
    assert(!sess.authenticated());
}

/**
 *  Agent.
 */

void smokeAgent()
{
    import std.exception : assertThrown;

    auto sess = new Session;
    auto agent = sess.agent();
    agent.connect();
    agent.listIdentities();
    {
        auto a = agent.identities();
        auto i1 = a.front();
        assert(i1 !is null);
        assertThrown(agent.userauth("foo", i1));
    }
    agent.disconnect();
}

/**
 *  Entrypoint.
 */

void main()
{
    // Session.
    smokeSession();
    smokeSessionHandshake();

    // Agent.
    smokeAgent();
}
