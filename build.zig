
const builtin = @import("builtin");
const std = @import("std");
const Path = std.Build.LazyPath;

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});
    const t = target.result;

    var lib = b.addStaticLibrary(.{
        .name = "ssh",
        .target = target,
        .optimize = optimize,
    });

    const config_header = b.addConfigHeader(
        .{
            .style = .{ .cmake = .{ .path = "config.h.cmake" } },
            .include_path = "config.h",
        },
        .{
            .GLOBAL_CLIENT_CONFIG = "KLLtestlibsshclientconfig",
            .HAVE_ARGP_H = true,
            .HAVE_ARPA_INET_H = true,
            .HAVE_GLOB_H = true,
            .HAVE_VALGRIND_VALGRIND_H = false,
            .HAVE_PTY_H = true,
            .HAVE_UTMP_H = true,
            .HAVE_UTIL_H = true,
            .HAVE_LIBUTIL_H = true,
            .HAVE_SYS_TIME_H = true,
            .HAVE_SYS_UTIME_H = false,
            .HAVE_IO_H = true,
            .HAVE_TERMIOS_H = true,
            .HAVE_UNISTD_H = true,
            .HAVE_STDINT_H = true,
            .HAVE_OPENSSL_AES_H = false,
            .HAVE_WSPIAPI_H = true,
            .HAVE_OPENSSL_BLOWFISH_H = false,
            .HAVE_OPENSSL_DES_H = false,
            .HAVE_OPENSSL_ECDH_H = false,
            .HAVE_OPENSSL_EC_H = false,
            .HAVE_OPENSSL_ECDSA_H = false,
            .HAVE_PTHREAD_H = true,
            .HAVE_OPENSSL_ECC = false,
            .HAVE_GCRYPT_ECC = false,
            .HAVE_ECC = true,
            .HAVE_GLOB_GL_FLAGS_MEMBER = true,
            .HAVE_GCRYPT_CHACHA_POLY = false,

            .HAVE_OPENSSL_EVP_CHACHA20 = false,
            .HAVE_OPENSSL_EVP_KDF_CTX = false,
            .HAVE_OPENSSL_FIPS_MODE = false,
            .HAVE_SNPRINTF = true,
            .HAVE__SNPRINTF = true,
            .HAVE__SNPRINTF_S = true,
            .HAVE_VSNPRINTF = true,
            .HAVE__VSNPRINTF = true,
            .HAVE__VSNPRINTF_S = true,
            .HAVE_ISBLANK = true,
            .HAVE_STRNCPY = true,
            .HAVE_STRNDUP = true,
            .HAVE_CFMAKERAW = true,
            .HAVE_GETADDRINFO = true,
            .HAVE_POLL = true,
            .HAVE_SELECT = true,
            .HAVE_CLOCK_GETTIME = true,
            .HAVE_NTOHLL = false,
            .HAVE_HTONLL = false,
            .HAVE_STRTOULL = true,
            .HAVE___STRTOULL = true,
            .HAVE__STRTOUI64 = true,
            .HAVE_GLOB = true,
            .HAVE_EXPLICIT_BZERO = true,
            .HAVE_MEMSET_S = true,
            .HAVE_SECURE_ZERO_MEMORY = true,
            .HAVE_CMOCKA_SET_TEST_FILTER = false,

            .HAVE_LIBCRYPTO = false,
            .HAVE_LIBGCRYPT = false,
            .HAVE_LIBMBEDCRYPTO = true,
            .HAVE_PTHREAD = true,
            .HAVE_CMOCKA = false,

            .HAVE_GCC_THREAD_LOCAL_STORAGE = true,
            .HAVE_MSC_THREAD_LOCAL_STORAGE = true,

            .HAVE_FALLTHROUGH_ATTRIBUTE = true,
            .HAVE_UNUSED_ATTRIBUTE = true,
            .HAVE_WEAK_ATTRIBUTE = true,

            .HAVE_CONSTRUCTOR_ATTRIBUTE = true,
            .HAVE_DESTRUCTOR_ATTRIBUTE = true,

            .HAVE_GCC_VOLATILE_MEMORY_PROTECTION = true,

            .HAVE_COMPILER__FUNC__ = true,
            .HAVE_COMPILER__FUNCTION__ = true,

            .HAVE_GCC_BOUNDED_ATTRIBUTE = false,
            .WITH_GSSAPI = false,
            .WITH_ZLIB = false,
            .WITH_SFTP = false,
            .WITH_SERVER = false,
            .WITH_GEX = true,
            .WITH_INSECURE_NONE = true,
            .WITH_BLOWFISH_CIPHER = false,
            .DEBUG_CRYPTO = false,
            .DEBUG_PACKET = false,
            .WITH_PCAP = false,
            .DEBUG_CALLTRACE = false,
            .WITH_NACL = false,
            .WITH_PKCS11_URI = true,
            .WITH_PKCS11_PROVIDER = true,

            .WORDS_BIGENDIAN = false
        },
    );
    lib.addConfigHeader(config_header);

    var source_files = std.ArrayList([]const u8).init(b.allocator);
    defer source_files.deinit();
    var flags = std.ArrayList([]const u8).init(b.allocator);
    defer flags.deinit();

    flags.appendSlice(&.{
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        //"-Wno-long-long",
    }) catch unreachable;

    source_files.appendSlice(&.{
        "src/agent.c",
        "src/auth.c",
        "src/base64.c",
        "src/bignum.c",
        "src/buffer.c",
        "src/callbacks.c",
        "src/channels.c",
        "src/client.c",
        "src/config.c",
        "src/connect.c",
        "src/connector.c",
        "src/crypto_common.c",
        "src/curve25519.c",
        "src/dh.c",
        "src/ecdh.c",
        "src/error.c",
        "src/getpass.c",
        "src/init.c",
        "src/kdf.c",
        "src/kex.c",
        "src/known_hosts.c",
        "src/knownhosts.c",
        "src/legacy.c",
        "src/log.c",
        "src/match.c",
        "src/messages.c",
        "src/misc.c",
        "src/options.c",
        "src/packet.c",
        "src/packet_cb.c",
        "src/packet_crypt.c",
        "src/pcap.c",
        "src/pki.c",
        "src/pki_container_openssh.c",
        "src/poll.c",
        "src/session.c",
        "src/scp.c",
        "src/socket.c",
        "src/string.c",
        "src/threads.c",
        "src/wrapper.c",
        "src/external/bcrypt_pbkdf.c",
        "src/external/blowfish.c",
        "src/config_parser.c",
        "src/token.c",
        "src/pki_ed25519_common.c",
    }) catch unreachable;

    if (t.os.tag == .linux) {
        source_files.appendSlice(&.{
            "src/threads/noop.c",
            "src/threads/pthread.c",
        }) catch unreachable;
    }

    const mbedtls = true;
    if (mbedtls) {
        source_files.appendSlice(&.{
            "src/threads/mbedtls.c",
            "src/libmbedcrypto.c",
            "src/mbedcrypto_missing.c",
            "src/pki_mbedcrypto.c",
            "src/ecdh_mbedcrypto.c",
            "src/getrandom_mbedcrypto.c",
            "src/md_mbedcrypto.c",
            "src/dh_key.c",
            "src/pki_ed25519.c",
            "src/external/ed25519.c",
            "src/external/fe25519.c",
            "src/external/ge25519.c",
            "src/external/sc25519.c",
        }) catch unreachable;

        source_files.appendSlice(&.{
            "src/external/chacha.c",
            "src/external/poly1305.c",
            "src/chachapoly.c",
        }) catch unreachable;
    }

    lib.addCSourceFiles(.{
        .files = source_files.items,
        .flags = flags.items,
    });
    lib.addIncludePath(.{ .path = "include" });
    lib.linkLibC();

    lib.installHeadersDirectory("include/libssh", "libssh");

    b.installArtifact(lib);
}
