#include "flirtparser.h"
#include <QDataStream>
#include <QBuffer>
#include <limits>
#include <QtEndian>

// Format references (not copied implementations):
// angr 6afa0c79a83d9f677a46b0275cdb63bf16c1979e, angr/analyses/flirt/{flirt_sig,consts}.py
// radare2 1ec2a778f4765e678ae65779108d9a2237e02a58, libr/anal/flirt.c
// https://github.com/angr/angr
// https://github.com/radareorg/radare2
#if HAVE_ZLIB
#include <zlib.h>
#endif

namespace SigParser {

#if HAVE_ZLIB
// Decompress deflate/zlib/gzip stream. windowBits: -15 raw deflate, 15 zlib, 15+16 gzip
static QByteArray decompressZlib(const QByteArray &compressed, int windowBits) {
    const int CHUNK = 65536;
    if (static_cast<quint64>(compressed.size()) > std::numeric_limits<uInt>::max())
        return QByteArray();
    z_stream strm = {};
    if (inflateInit2(&strm, windowBits) != Z_OK)
        return QByteArray();
    strm.avail_in = static_cast<uInt>(compressed.size());
    strm.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(compressed.constData()));
    QByteArray out;
    QByteArray buf(CHUNK, 0);
    // Bound expansion of untrusted input (also applies to external gzip files).
    constexpr qsizetype MAX_DECOMPRESSED_SIZE = 256 * 1024 * 1024;
    for (;;) {
        strm.avail_out = CHUNK;
        strm.next_out = reinterpret_cast<Bytef *>(buf.data());
        const uInt previousInput = strm.avail_in;
        const int ret = inflate(&strm, Z_NO_FLUSH);
        const int produced = CHUNK - strm.avail_out;
        if ((ret != Z_OK && ret != Z_STREAM_END) ||
            out.size() > MAX_DECOMPRESSED_SIZE - produced ||
            (ret != Z_STREAM_END && produced == 0 && strm.avail_in == previousInput)) {
            inflateEnd(&strm);
            return QByteArray();
        }
        out.append(buf.constData(), produced);
        if (ret == Z_STREAM_END) {
            inflateEnd(&strm);
            return out;
        }
    }
}
#endif

static bool parseError(ParseState &st, const QString &message) {
    st.err = true;
    if (st.errorMessage.isEmpty())
        st.errorMessage = QString("%1 at body offset %2").arg(message).arg(st.pos);
    return false;
}

static quint8 readByte(ParseState &st) {
    if (st.eof || st.err) return 0;
    if (st.pos >= st.body.size()) {
        st.eof = true;
        parseError(st, "Unexpected EOF");
        return 0;
    }
    return static_cast<quint8>(st.body[st.pos++]);
}

static quint16 readShortBE(ParseState &st) {
    quint16 r = readByte(st);
    r = (r << 8) | readByte(st);
    return r;
}

static quint32 readWordBE(ParseState &st) {
    quint32 r = readShortBE(st);
    return (r << 16) | readShortBE(st);
}

// read_multiple_bytes from flirt.c (big endian)
static quint32 readMultipleBytes(ParseState &st) {
    quint32 r = readByte(st);
    if ((r & 0x80) != 0x80) return r;
    if ((r & 0xc0) != 0xc0) return ((r & 0x7f) << 8) | readByte(st);
    if ((r & 0xe0) != 0xe0) {
        r = ((r & 0x3f) << 24) | (static_cast<quint32>(readByte(st)) << 16);
        r |= readShortBE(st);
        return r;
    }
    return readWordBE(st);
}

// read_max_2_bytes
static quint16 readMax2Bytes(ParseState &st) {
    quint16 r = readByte(st);
    return (r & 0x80) ? static_cast<quint16>(((r & 0x7f) << 8) | readByte(st)) : r;
}

QString FlirtPatternNode::toHexString() const {
    QString out;
    for (int i = 0; i < patternBytes.size(); ++i) {
        if (i < variantMask.size() && variantMask[i]) {
            out += "..";
        } else {
            out += QString("%1").arg(static_cast<quint8>(patternBytes[i]), 2, 16, QChar('0')).toUpper();
        }
    }
    return out;
}

QString FlirtModule::patternPathHex() const {
    QString out;
    for (const auto &n : patternPath) {
        if (!out.isEmpty()) out += " ";
        out += n.toHexString();
    }
    return out;
}

QString FlirtModule::rulesSummary() const {
    QStringList parts;
    parts << QString("CRC: len=%1 val=%2").arg(crcLength).arg(crc16, 4, 16, QChar('0'));
    parts << QString("Module length: %1").arg(length);
    if (!tailBytes.isEmpty()) {
        QStringList t;
        for (const auto &tb : tailBytes)
            t << QString("(%1: %2)").arg(tb.offset, 4, 16).arg(tb.value, 2, 16, QChar('0'));
        parts << "Tail bytes (relative to end of CRC region): " + t.join(" ");
    }
    if (!referencedFunctions.isEmpty()) {
        QStringList r;
        for (const auto &rf : referencedFunctions)
            r << QString("%1%2: %3").arg(rf.negativeOffset ? "-" : "")
                     .arg(rf.offset, 4, 16, QChar('0')).arg(rf.name);
        parts << "REF (relative to function start) " + r.join(" ");
    }
    return parts.join("\n");
}

QVector<FlirtResult::FunctionEntry> FlirtResult::allFunctions() const {
    QVector<FlirtResult::FunctionEntry> list;
    for (int mi = 0; mi < modules.size(); ++mi) {
        const FlirtModule &mod = modules[mi];
        for (const FlirtFunction &f : mod.publicFunctions) {
            FunctionEntry e;
            e.moduleIndex = mi;
            e.module = &mod;
            e.function = &f;
            list.append(e);
        }
    }
    return list;
}

bool FlirtParser::isFlirt(const QByteArray &data, int *outVersion) {
    if (data.size() < 7) return false;
    if (data.left(6) != "IDASGN") return false;
    quint8 v = static_cast<quint8>(data[6]);
    if (outVersion) *outVersion = v;
    return v >= 5 && v <= 10;
}

bool FlirtParser::parseHeader(ParseState &st, FlirtResult &result) {
    if (st.body.size() < 7) {
        result.errorMessage = "File too short";
        return false;
    }
    if (st.body.left(6) != "IDASGN") {
        result.errorMessage = "Invalid magic (not IDASGN)";
        return false;
    }
    st.version = static_cast<quint8>(st.body[6]);
    st.pos = 7;
    if (st.version < 5 || st.version > 10) {
        result.errorMessage = QString("Unsupported FLIRT version %1").arg(st.version);
        return false;
    }

    // v5 header: arch(1), file_types(4), os_types(2), app_types(2), features(2),
    // old_n_functions(2), crc16(2), ctype(12), library_name_len(1), ctypes_crc16(2) = 30 bytes after magic+version
    if (st.pos + 30 > st.body.size()) {
        result.errorMessage = "Truncated v5 header";
        return false;
    }
    FlirtHeader &h = result.header;
    h.version = st.version;
    h.arch = readByte(st);
    h.fileTypes = qFromLittleEndian<quint32>(st.body.constData() + st.pos);
    st.pos += 4;
    h.osTypes = static_cast<quint8>(st.body[st.pos]) | (static_cast<quint8>(st.body[st.pos+1])<<8);
    st.pos += 2;
    h.appTypes = static_cast<quint8>(st.body[st.pos]) | (static_cast<quint8>(st.body[st.pos+1])<<8);
    st.pos += 2;
    h.features = static_cast<quint8>(st.body[st.pos]) | (static_cast<quint8>(st.body[st.pos+1])<<8);
    st.pos += 2;
    h.oldNFunctions = static_cast<quint8>(st.body[st.pos]) | (static_cast<quint8>(st.body[st.pos+1])<<8);
    st.pos += 2;
    h.crc16 = static_cast<quint8>(st.body[st.pos]) | (static_cast<quint8>(st.body[st.pos+1])<<8);
    st.pos += 2;
    h.ctype = st.body.mid(st.pos, 12);
    st.pos += 12;
    h.libraryNameLen = readByte(st);
    h.ctypesCrc16 = static_cast<quint8>(st.body[st.pos]) | (static_cast<quint8>(st.body[st.pos+1])<<8);
    st.pos += 2;

    if (st.version >= 6) {
        if (st.pos + 4 > st.body.size()) { result.errorMessage = "Truncated v6/v7 header"; return false; }
        h.nFunctions = qFromLittleEndian<quint32>(st.body.constData() + st.pos);
        st.pos += 4;
        if (st.version >= 8) {
            if (st.pos + 2 > st.body.size()) { result.errorMessage = "Truncated v8/v9 header"; return false; }
            h.patternSize = static_cast<quint8>(st.body[st.pos]) | (static_cast<quint8>(st.body[st.pos+1]) << 8);
            st.pos += 2;
            if (st.version >= 10) {
                if (st.pos + 2 > st.body.size()) { result.errorMessage = "Truncated v10 header"; return false; }
                h.unknownV10 = static_cast<quint8>(st.body[st.pos]) | (static_cast<quint8>(st.body[st.pos+1]) << 8);
                st.pos += 2;
            }
        }
    }

    if (st.pos + h.libraryNameLen > st.body.size()) {
        result.errorMessage = "Truncated library name";
        return false;
    }
    result.libraryName = QString::fromLatin1(st.body.mid(st.pos, h.libraryNameLen));
    st.pos += h.libraryNameLen;

    return true;
}

quint8 FlirtParser::readByte(ParseState &st) {
    return ::SigParser::readByte(st);
}

quint16 FlirtParser::readShortBE(ParseState &st) {
    return ::SigParser::readShortBE(st);
}

quint16 FlirtParser::readMax2Bytes(ParseState &st) {
    return ::SigParser::readMax2Bytes(st);
}

quint32 FlirtParser::readMultipleBytes(ParseState &st) {
    return ::SigParser::readMultipleBytes(st);
}

bool FlirtParser::readNodeLength(ParseState &st, quint8 &len) {
    if (st.eof || st.err) return false;
    len = readByte(st);
    return !st.eof && !st.err;
}

bool FlirtParser::readNodeVariantMask(ParseState &st, quint8 nodeLen, quint64 &mask) {
    if (nodeLen < 16) {
        mask = readMax2Bytes(st);
    } else if (nodeLen <= 32) {
        mask = readMultipleBytes(st);
    } else if (nodeLen <= 64) {
        const quint32 high = readMultipleBytes(st);
        const quint32 low = readMultipleBytes(st);
        mask = (static_cast<quint64>(high) << 32) | low;
    } else {
        return parseError(st, "Node length exceeds 64 bytes");
    }
    return !st.eof && !st.err;
}

bool FlirtParser::readNodeBytes(ParseState &st, quint8 nodeLen, quint64 variantMask, FlirtPatternNode &nodeOut) {
    if (nodeLen > 64) return parseError(st, "Node length exceeds 64 bytes");
    nodeOut.patternBytes.resize(nodeLen);
    nodeOut.variantMask.resize(nodeLen);
    quint64 bit = nodeLen ? (1ULL << (nodeLen - 1)) : 0;
    for (int i = 0; i < nodeLen; ++i, bit >>= 1) {
        nodeOut.variantMask[i] = (variantMask & bit) ? 1 : 0;
        if (variantMask & bit) {
            nodeOut.patternBytes[i] = 0;
        } else {
            if (st.eof || st.err) return false;
            nodeOut.patternBytes[i] = static_cast<char>(readByte(st));
            if (st.eof || st.err) return false;
        }
    }
    return true;
}

bool FlirtParser::readModulePublicFunctions(ParseState &st, FlirtModule &mod, quint8 &flags) {
    quint32 offset = 0;
    do {
        const quint32 delta = st.version >= 9 ? readMultipleBytes(st) : readMax2Bytes(st);
        if (st.eof || st.err) return false;
        if (delta > std::numeric_limits<quint32>::max() - offset)
            return parseError(st, "Public function offset overflow");
        offset += delta;

        FlirtFunction f;
        f.offset = offset;

        quint8 currentByte = readByte(st);
        if (st.eof || st.err) return false;
        if (currentByte < 0x20) {
            if (currentByte & IDASIG_FUNCTION_LOCAL) f.isLocal = true;
            if (currentByte & IDASIG_FUNCTION_UNRESOLVED_COLLISION) f.isCollision = true;
            currentByte = readByte(st);
            if (st.eof || st.err) return false;
        }

        QByteArray nameBytes;
        while (currentByte >= 0x20) {
            if (nameBytes.size() >= FLIRT_NAME_MAX - 1)
                return parseError(st, "Public function name too long");
            nameBytes.append(static_cast<char>(currentByte));
            currentByte = readByte(st);
            if (st.eof || st.err) return false;
        }
        f.name = QString::fromLatin1(nameBytes);
        flags = currentByte;
        mod.publicFunctions.append(f);
    } while (flags & IDASIG_PARSE_MORE_PUBLIC_NAMES);
    return true;
}

bool FlirtParser::readModuleTailBytes(ParseState &st, FlirtModule &mod) {
    int count = (st.version >= 8) ? readByte(st) : 1;
    if (st.eof || st.err) return false;
    for (int i = 0; i < count; ++i) {
        FlirtTailByte tb;
        if (st.version >= 9) {
            tb.offset = readMultipleBytes(st);
        } else {
            tb.offset = readMax2Bytes(st);
        }
        if (st.eof || st.err) return false;
        tb.value = readByte(st);
        if (st.eof || st.err) return false;
        mod.tailBytes.append(tb);
    }
    return true;
}

bool FlirtParser::readModuleReferencedFunctions(ParseState &st, FlirtModule &mod) {
    int count = (st.version >= 8) ? readByte(st) : 1;
    if (st.eof || st.err) return false;
    for (int i = 0; i < count; ++i) {
        FlirtRefFunction rf;
        if (st.version >= 9) {
            rf.offset = readMultipleBytes(st);
        } else {
            rf.offset = readMax2Bytes(st);
        }
        if (st.eof || st.err) return false;
        quint32 nameLen = readByte(st);
        if (st.eof || st.err) return false;
        if (nameLen == 0) {
            nameLen = readMultipleBytes(st);
            if (st.eof || st.err) return false;
        }
        if (nameLen >= static_cast<quint32>(FLIRT_NAME_MAX))
            return parseError(st, "Referenced function name too long");
        if (nameLen > static_cast<quint64>(st.body.size() - st.pos))
            return parseError(st, "Truncated referenced function name");
        QByteArray nameBytes;
        for (quint32 j = 0; j < nameLen; ++j) {
            nameBytes.append(static_cast<char>(readByte(st)));
            if (st.eof || st.err) return false;
        }
        if (nameBytes.size() > 0 && nameBytes.back() == '\0') {
            rf.negativeOffset = true;
            nameBytes.chop(1);
        }
        rf.name = QString::fromLatin1(nameBytes);
        mod.referencedFunctions.append(rf);
    }
    return true;
}

bool FlirtParser::parseLeaf(ParseState &st, const QVector<FlirtPatternNode> &path, QVector<FlirtModule> &modulesOut) {
    quint8 flags = 0;
    do {
        quint8 crcLength = readByte(st);
        if (st.eof || st.err) return false;
        quint16 crc16 = readShortBE(st);
        if (st.eof || st.err) return false;
        do {
            FlirtModule mod;
            mod.patternPath = path;
            mod.crcLength = crcLength;
            mod.crc16 = crc16;
            if (st.version >= 9) {
                mod.length = readMultipleBytes(st);
            } else {
                mod.length = readMax2Bytes(st);
            }
            if (st.eof || st.err) return false;

            if (!readModulePublicFunctions(st, mod, flags)) return false;
            if (flags & IDASIG_PARSE_READ_TAIL_BYTES) {
                if (!readModuleTailBytes(st, mod)) return false;
            }
            if (flags & IDASIG_PARSE_READ_REFERENCED_FUNCTIONS) {
                if (!readModuleReferencedFunctions(st, mod)) return false;
            }
            modulesOut.append(mod);
        } while (flags & IDASIG_PARSE_MORE_MODULES_WITH_SAME_CRC);
    } while (flags & IDASIG_PARSE_MORE_MODULES);
    return true;
}

bool FlirtParser::parseTree(ParseState &st, FlirtResult &result, QVector<FlirtPatternNode> &path, QVector<FlirtModule> &modulesOut) {
    quint32 treeNodes = readMultipleBytes(st);
    if (st.eof || st.err) {
        result.errorMessage = "Unexpected EOF in tree";
        return false;
    }
    if (treeNodes == 0) {
        return parseLeaf(st, path, modulesOut);
    }
    // Count zero-length nodes too: they must not permit unbounded recursion.
    if (path.size() >= 64)
        return parseError(st, "Signature tree depth exceeds 64");
    if (treeNodes > static_cast<quint64>(st.body.size() - st.pos))
        return parseError(st, "Truncated child nodes");
    int patternLength = 0;
    for (const auto &node : path) patternLength += node.patternBytes.size();
    const int maxPatternLength = qMax(64, int(result.header.patternSize));
    for (quint32 i = 0; i < treeNodes; ++i) {
        quint8 nodeLen;
        if (!readNodeLength(st, nodeLen)) return false;
        if (patternLength + nodeLen > maxPatternLength)
            return parseError(st, "Signature pattern exceeds allowed length");
        quint64 variantMask;
        if (!readNodeVariantMask(st, nodeLen, variantMask)) return false;
        FlirtPatternNode node;
        if (!readNodeBytes(st, nodeLen, variantMask, node)) return false;

        QVector<FlirtPatternNode> childPath = path;
        childPath.append(node);
        if (!parseTree(st, result, childPath, modulesOut)) return false;
    }
    return true;
}

FlirtResult FlirtParser::parse(const QByteArray &data) {
    FlirtResult result;
    ParseState st;
    st.body = data;
    st.pos = 0;
    st.eof = false;
    st.err = false;

    if (!isFlirt(data, &st.version)) {
        result.errorMessage = "Not a valid FLIRT .sig file";
        return result;
    }

    if (!parseHeader(st, result)) return result;

    if (result.header.features & IDASIG_FEATURE_COMPRESSED) {
#if HAVE_ZLIB
        QByteArray body = st.body.mid(st.pos);
        int windowBits = (st.version == 5 || st.version == 6) ? -15 : 15;  // raw deflate vs zlib
        QByteArray decompressed = decompressZlib(body, windowBits);
        if (decompressed.isEmpty()) {
            result.errorMessage = "FLIRT decompression failed";
            return result;
        }
        st.body = decompressed;
        st.pos = 0;
        st.eof = false;
        st.err = false;
#else
        result.errorMessage = "Compressed .sig requires zlib (build without ZLIB found)";
        return result;
#endif
    }

    QVector<FlirtPatternNode> path;
    if (!parseTree(st, result, path, result.modules)) {
        if (!st.errorMessage.isEmpty()) result.errorMessage = st.errorMessage;
        else if (result.errorMessage.isEmpty()) result.errorMessage = "Parse error in signature tree";
        return result;
    }

    result.success = true;
    return result;
}

// Display helpers (minimal set for common archs)
QString archToString(quint8 arch) {
    switch (arch) {
    case 0: return "386";
    case 7: return "68K";
    case 12: return "MIPS";
    case 13: return "ARM";
    case 15: return "PPC";
    case 18: return "SH";
    case 19: return "NET";
    case 23: return "SPARC";
    case 31: return "IA64";
    case 58: return "MSP430";
    case 60: return "DALVIK";
    default: return QString("ARCH_%1").arg(arch);
    }
}

struct DisplayFlag { quint32 bit; const char *name; };

template<size_t N>
static QString displayFlags(quint32 value, const DisplayFlag (&flags)[N], int width,
                            const QString &zero = QString()) {
    QStringList names;
    quint32 remaining = value;
    for (const auto &flag : flags) {
        if (value & flag.bit) names << QString::fromLatin1(flag.name);
        remaining &= ~flag.bit;
    }
    if (remaining || (names.isEmpty() && zero.isEmpty()))
        names << QString("0x%1").arg(remaining, width, 16, QChar('0'));
    if (names.isEmpty()) return zero;
    return names.join(",");
}

QString fileTypesToString(quint32 ft) {
    static const DisplayFlag flags[] = {
        {0x1, "DOS_EXE_OLD"}, {0x2, "DOS_COM_OLD"}, {0x4, "BIN"},
        {0x8, "DOSDRV"}, {0x10, "NE"}, {0x20, "INTELHEX"}, {0x40, "MOSHEX"},
        {0x80, "LX"}, {0x100, "LE"}, {0x200, "NLM"}, {0x400, "COFF"},
        {0x800, "PE"}, {0x1000, "OMF"}, {0x2000, "SREC"}, {0x4000, "ZIP"},
        {0x8000, "OMFLIB"}, {0x10000, "AR"}, {0x20000, "LOADER"},
        {0x40000, "ELF"}, {0x80000, "W32RUN"}, {0x100000, "AOUT"},
        {0x200000, "PILOT"}, {0x400000, "DOS_EXE"}, {0x800000, "DOS_COM"},
        {0x1000000, "AIXAR"}
    };
    return displayFlags(ft, flags, 8);
}

QString osTypesToString(quint16 ot) {
    static const DisplayFlag flags[] = {
        {1, "MSDOS"}, {2, "WIN"}, {4, "OS2"}, {8, "NETWARE"},
        {0x10, "UNIX"}, {0x20, "OTHER"}
    };
    return displayFlags(ot, flags, 4);
}

QString appTypesToString(quint16 at) {
    static const DisplayFlag flags[] = {
        {1, "CONSOLE"}, {2, "GRAPHICS"}, {4, "EXE"}, {8, "DLL"}, {0x10, "DRV"},
        {0x20, "SINGLE_THREADED"}, {0x40, "MULTI_THREADED"}, {0x80, "16_BIT"},
        {0x100, "32_BIT"}, {0x200, "64_BIT"}
    };
    return displayFlags(at, flags, 4);
}

QString featuresToString(quint16 f) {
    static const DisplayFlag flags[] = {
        {1, "STARTUP"}, {2, "CTYPE_CRC"}, {4, "2BYTE_CTYPE"},
        {8, "ALT_CTYPE_CRC"}, {0x10, "COMPRESSED"}
    };
    return displayFlags(f, flags, 4, "none");
}

QByteArray FlirtParser::decompressGzip(const QByteArray &gzipData) {
#if HAVE_ZLIB
    if (gzipData.size() < 2 || static_cast<quint8>(gzipData[0]) != 0x1f || static_cast<quint8>(gzipData[1]) != 0x8b)
        return QByteArray();
    return decompressZlib(gzipData, 15 + 16);  // gzip
#else
    Q_UNUSED(gzipData);
    return QByteArray();
#endif
}

} // namespace SigParser
