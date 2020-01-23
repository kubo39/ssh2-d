import ssh2.channel;
import ssh2.session;

import std.socket : InternetAddress;

/**
 *  Utilities.
 */

InternetAddress testAddress() @safe
{
    import std.conv : parse;
    import std.process : environment;

    auto s = environment["D_SSH2_FIXTURE_PORT"];
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
        agent.destroy();
    }
    assert(sess.authenticated());
    return sess;
}

/**
 *  Session.
 */

void sessionSmoke()
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

void sessionSmokeHandshake()
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
    agent.destroy();
    assert(sess.authenticated());
    assert(sess.hostKeyHash(HashType.MD5) !is null);
}

void sessionKeyboardInteractive()
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

void agentSmoke()
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
    agent.destroy();
}

/**
 *  Channel.
 */

import std.typecons;

auto consumeStdio(Channel channel)
{
    import std.stdio;

    ubyte[1024] _stdout;
    auto ret1 = channel.read(_stdout[]);

    ubyte[1024] _stderr;
    auto ret2 = channel.stderr().read(_stderr[]);

    stderr.writefln("stdout: %s", cast(string) _stdout);
    stderr.writefln("stderr: %s", cast(string) _stderr);

    return tuple(cast(string) _stdout[0 .. ret1],
                 cast(string) _stderr[0 .. ret2]);
}

void channelSmoke()
{
    auto sess = authedSession();
    auto channel = sess.channelSession();
    channel.flush();
    channel.exec("true");
    consumeStdio(channel);

    channel.waitEOF();
    assert(channel.eof());

    channel.close();
    channel.waitClosed();
    assert(channel.exitStatus() == 0);
    assert(channel.eof());
    channel.destroy();
}

void channelBadSmoke()
{
    auto sess = authedSession();
    auto channel = sess.channelSession();
    channel.flush();
    channel.exec("false");
    consumeStdio(channel);

    channel.waitEOF();
    assert(channel.eof());

    channel.close();
    channel.waitClosed();
    assert(channel.exitStatus() == 1);
    assert(channel.eof());
    channel.destroy();
}

void channelReadingData()
{
    auto sess = authedSession();
    auto channel = sess.channelSession();
    channel.exec("echo foo");

    auto pair = consumeStdio(channel);
    channel.destroy();
    assert(pair[0] == "foo\n");
}

void channelHandleExtendedData()
{
    import std.string : endsWith;

    auto sess = authedSession();
    auto channel = sess.channelSession();
    channel.handleExtendedData(ExtendedData.MERGE);
    channel.exec("echo foo >&2");
    auto pair = consumeStdio(channel);
    channel.destroy();
    assert(pair[0].endsWith("foo\n"));
}

void channelWritingData()
{
    auto sess = authedSession();
    auto channel = sess.channelSession();
    channel.exec("read foo && echo $foo");
    channel.write("foo\n");
    auto pair = consumeStdio(channel);
    channel.destroy();
    assert(pair[0] == "foo\n");
}

void channelEof()
{
    auto sess = authedSession();
    auto channel = sess.channelSession();
    channel.adjustReceiveWindow(10, true);
    channel.exec("read goo");
    channel.sendEOF();
    ubyte[1024] output;
    auto len = channel.read(output);
    channel.destroy();
    assert(cast(string) output[0 .. len] == "");
}

void channelShell()
{
    import std.stdio;

    auto sess = authedSession();
    auto channel = sess.channelSession();
    stderr.writeln("requesting pty");
    channel.requestPTY("xterm");
    stderr.writeln("shell");
    channel.shell();
    stderr.writeln("close");
    channel.close();
    stderr.writeln("done");
    consumeStdio(channel);
    channel.destroy();
}

/**
 *  Knownhosts
 */

void knownhostsSmoke()
{
    import std.range;
    auto sess = new Session;
    auto hosts = sess.knownhosts();
    assert(hosts[].walkLength() == 0);
    hosts.destroy();
}

/**
 *  Entrypoint.
 */

void main()
{
    // Session.
    sessionSmoke();
    sessionSmokeHandshake();
    sessionKeyboardInteractive();

    // Agent.
    agentSmoke();

    // Channel.
    channelSmoke();
    channelBadSmoke();
    channelReadingData();
    channelHandleExtendedData();
    channelWritingData();
    channelEof();
    channelShell();

    // Knownhosts.
    knownhostsSmoke();
}
