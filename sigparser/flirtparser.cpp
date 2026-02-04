#include "flirtparser.h"
#include <QDataStream>
#include <QBuffer>
#if HAVE_ZLIB
#include <zlib.h>
#endif

namespace SigParser {

#if HAVE_ZLIB
// Decompress deflate/zlib/gzip stream. windowBits: -15 raw deflate, 15 zlib, 15+16 gzip
static QByteArray decompressZlib(const QByteArray &compressed, int windowBits) {
    const int CHUNK = 65536;
    z_stream strm = {};
    if (inflateInit2(&strm, windowBits) != Z_OK)
        return QByteArray();
    strm.avail_in = static_cast<uInt>(compressed.size());
    strm.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(compressed.constData()));
    QByteArray out;
    QByteArray buf(CHUNK, 0);
    int ret;
    do {
        strm.avail_out = CHUNK;
        strm.next_out = reinterpret_cast<Bytef *>(buf.data());
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
            inflateEnd(&strm);
            return QByteArray();
        }
        out.append(buf.constData(), CHUNK - strm.avail_out);
    } while (ret != Z_STREAM_END && strm.avail_out == 0);
    inflateEnd(&strm);
    return out;
}
#endif

static quint8 readByte(ParseState &st) {
    if (st.eof || st.err || st.pos >= st.body.size()) {
        st.eof = (st.pos >= st.body.size());
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
        parts << "Tail bytes: " + t.join(" ");
    }
    if (!referencedFunctions.isEmpty()) {
        QStringList r;
        for (const auto &rf : referencedFunctions)
            r << QString("%1: %2").arg(rf.offset, 4, 16).arg(rf.name);
        parts << "REF " + r.join(" ");
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
    h.fileTypes = static_cast<quint8>(st.body[st.pos]) | (static_cast<quint8>(st.body[st.pos+1])<<8) | (static_cast<quint8>(st.body[st.pos+2])<<16) | (static_cast<quint8>(st.body[st.pos+3])<<24);
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
        h.nFunctions = static_cast<quint8>(st.body[st.pos]) | (static_cast<quint8>(st.body[st.pos+1])<<8) | (static_cast<quint8>(st.body[st.pos+2])<<16) | (static_cast<quint8>(st.body[st.pos+3])<<24);
        st.pos += 4;
        if (st.version >= 8) {
            if (st.pos + 2 > st.body.size()) { result.errorMessage = "Truncated v8/v9 header"; return false; }
            h.patternSize = static_cast<quint8>(st.body[st.pos])<<8 | static_cast<quint8>(st.body[st.pos+1]);
            st.pos += 2;
            if (st.version >= 10) {
                if (st.pos + 2 > st.body.size()) { result.errorMessage = "Truncated v10 header"; return false; }
                h.unknownV10 = static_cast<quint8>(st.body[st.pos])<<8 | static_cast<quint8>(st.body[st.pos+1]);
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
    return true;
}

bool FlirtParser::readNodeVariantMask(ParseState &st, quint8 nodeLen, quint64 &mask) {
    if (nodeLen < 16) {
        mask = readMax2Bytes(st);
    } else if (nodeLen <= 32) {
        mask = readMultipleBytes(st);
    } else if (nodeLen <= 64) {
        mask = (static_cast<quint64>(readMultipleBytes(st)) << 32) | readMultipleBytes(st);
    } else {
        return false;
    }
    return !st.eof && !st.err;
}

bool FlirtParser::readNodeBytes(ParseState &st, quint8 nodeLen, quint64 variantMask, FlirtPatternNode &nodeOut) {
    if (nodeLen > 63 || nodeLen <= 0) return false;
    nodeOut.patternBytes.resize(nodeLen);
    nodeOut.variantMask.resize(nodeLen);
    quint64 bit = 1ULL << (nodeLen - 1);
    for (int i = 0; i < nodeLen; ++i, bit >>= 1) {
        nodeOut.variantMask[i] = (variantMask & bit) ? 1 : 0;
        if (variantMask & bit) {
            nodeOut.patternBytes[i] = 0;
        } else {
            if (st.eof || st.err) return false;
            nodeOut.patternBytes[i] = static_cast<char>(readByte(st));
        }
    }
    return true;
}

bool FlirtParser::readModulePublicFunctions(ParseState &st, FlirtModule &mod, quint8 &flags) {
    quint32 offset = 0;
    do {
        if (st.version >= 9) {
            offset += readMultipleBytes(st);
        } else {
            offset += readMax2Bytes(st);
        }
        if (st.eof || st.err) return false;

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
        while (currentByte >= 0x20 && nameBytes.size() < FLIRT_NAME_MAX) {
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
        if (nameLen >= static_cast<quint32>(FLIRT_NAME_MAX)) return false;
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
    for (quint32 i = 0; i < treeNodes; ++i) {
        quint8 nodeLen;
        if (!readNodeLength(st, nodeLen)) return false;
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
        if (result.errorMessage.isEmpty()) result.errorMessage = "Parse error in signature tree";
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

QString fileTypesToString(quint32 ft) {
    QStringList s;
    if (ft & 0x04) s << "BIN";
    if (ft & 0x400) s << "COFF";
    if (ft & 0x800) s << "PE";
    if (ft & 0x4000) s << "ELF";
    if (s.isEmpty()) s << QString("0x%1").arg(ft, 8, 16);
    return s.join(",");
}

QString osTypesToString(quint16 ot) {
    QStringList s;
    if (ot & 0x01) s << "MSDOS";
    if (ot & 0x02) s << "WIN";
    if (ot & 0x10) s << "UNIX";
    if (s.isEmpty()) s << QString("0x%1").arg(ot, 4, 16);
    return s.join(",");
}

QString appTypesToString(quint16 at) {
    QStringList s;
    if (at & 0x04) s << "EXE";
    if (at & 0x08) s << "DLL";
    if (at & 0x100) s << "32_BIT";
    if (at & 0x200) s << "64_BIT";
    if (s.isEmpty()) s << QString("0x%1").arg(at, 4, 16);
    return s.join(",");
}

QString featuresToString(quint16 f) {
    QStringList s;
    if (f & 0x10) s << "COMPRESSED";
    if (s.isEmpty()) s << "none";
    return s.join(",");
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
