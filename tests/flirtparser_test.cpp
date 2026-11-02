// Self-generated fixtures only; no third-party signature binaries are embedded.
// Format references (not copied implementations):
// angr 6afa0c79a83d9f677a46b0275cdb63bf16c1979e:
// https://github.com/angr/angr/blob/6afa0c79a83d9f677a46b0275cdb63bf16c1979e/angr/analyses/flirt/flirt_sig.py
// radare2 1ec2a778f4765e678ae65779108d9a2237e02a58:
// https://github.com/radareorg/radare2/blob/1ec2a778f4765e678ae65779108d9a2237e02a58/libr/anal/flirt.c
#include "sigparser/flirtparser.h"

#include <QCoreApplication>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QMap>
#include <QTextStream>
#include <limits>
#include <zlib.h>

using namespace SigParser;

namespace {
int failures = 0;
int checks = 0;

void check(bool condition, const QString &description)
{
    ++checks;
    if (!condition) {
        ++failures;
        QTextStream(stderr) << "FAIL: " << description << '\n';
    }
}

void byte(QByteArray &out, quint32 value) { out.append(char(value & 0xff)); }
void le16(QByteArray &out, quint16 value) { byte(out, value); byte(out, value >> 8); }
void le32(QByteArray &out, quint32 value)
{
    le16(out, quint16(value));
    le16(out, quint16(value >> 16));
}
void be32(QByteArray &out, quint32 value)
{
    byte(out, value >> 24); byte(out, value >> 16);
    byte(out, value >> 8); byte(out, value);
}

// FLIRT has 1-, 2-, 4- and 5-byte integers, not LEB128.
QByteArray number(quint32 value, int width = 0)
{
    QByteArray out;
    if (!width)
        width = value < 0x80 ? 1 : value < 0x8000 ? 2 : value < 0x20000000 ? 4 : 5;
    if (width == 1) {
        byte(out, value);
    } else if (width == 2) {
        byte(out, 0x80 | (value >> 8)); byte(out, value);
    } else if (width == 4) {
        byte(out, 0xc0 | (value >> 24)); byte(out, value >> 16);
        byte(out, value >> 8); byte(out, value);
    } else {
        byte(out, 0xe0); be32(out, value);
    }
    return out;
}

QByteArray offsetNumber(int version, quint32 value)
{
    return number(value, version >= 9 ? 0 : (value < 0x80 ? 1 : 2));
}

QByteArray header(int version, quint16 features = 0, quint16 patternSize = 32)
{
    QByteArray out("IDASGN", 6);
    byte(out, version); byte(out, 13);
    le32(out, 0x12345678); le16(out, 0x1234); le16(out, 0x5678);
    le16(out, features); le16(out, 0x2345); le16(out, 0x3456);
    out.append("abcdefghijkl", 12);
    byte(out, 3); le16(out, 0x4567);
    if (version >= 6) le32(out, 0x12345678);
    if (version >= 8) le16(out, patternSize);
    if (version >= 10) le16(out, 0x1234);
    out.append("lib", 3);
    return out;
}

QByteArray publicFunction(int version, quint32 delta, const QByteArray &name,
                          quint8 parseFlags = 0, quint8 functionFlags = 0)
{
    QByteArray out = offsetNumber(version, delta);
    if (functionFlags) byte(out, functionFlags);
    out += name;
    byte(out, parseFlags);
    return out;
}

QByteArray module(int version, const QByteArray &publics, quint32 length = 0x40)
{
    return offsetNumber(version, length) + publics;
}

QByteArray crcGroup(const QByteArray &modules, quint8 crcLength = 7, quint16 crc = 0x1234)
{
    QByteArray out;
    byte(out, crcLength); byte(out, crc >> 8); byte(out, crc);
    return out + modules;
}

QByteArray basicBody(int version)
{
    return number(0) + crcGroup(module(version, publicFunction(version, 0, "entry")));
}

FlirtResult parseBody(int version, const QByteArray &body, quint16 patternSize = 32)
{
    return FlirtParser().parse(header(version, 0, patternSize) + body);
}

void reject(const QByteArray &data, const QString &description)
{
    const FlirtResult result = FlirtParser().parse(data);
    check(!result.success, description);
    if (!result.success)
        check(!result.errorMessage.isEmpty(), description + " reports an error");
}

bool accepted(const FlirtResult &result, const QString &description)
{
    check(result.success, description + (result.success ? QString() : ": " + result.errorMessage));
    return result.success;
}

QByteArray node(int length, quint64 mask = 0)
{
    QByteArray out = number(1);
    byte(out, quint32(length));
    if (length < 16) {
        out += number(quint32(mask), mask < 0x80 ? 1 : 2);
    } else if (length <= 32) {
        out += number(quint32(mask));
    } else {
        out += number(quint32(mask >> 32));
        out += number(quint32(mask));
    }
    for (int i = 0; i < length; ++i) {
        if (!(mask & (quint64(1) << (length - i - 1))))
            byte(out, 0x90 + (i % 16));
    }
    return out;
}

QByteArray reference(int version, quint32 offset, const QByteArray &name, bool extended = false)
{
    QByteArray out = offsetNumber(version, offset);
    if (extended || name.size() > 255) {
        byte(out, 0); out += number(quint32(name.size()));
    } else {
        byte(out, quint32(name.size()));
    }
    return out + name;
}

QByteArray compressed(const QByteArray &input, int windowBits)
{
    z_stream stream = {};
    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, windowBits,
                     8, Z_DEFAULT_STRATEGY) != Z_OK) {
        check(false, "deflateInit2 fixture setup");
        return {};
    }
    stream.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(input.constData()));
    stream.avail_in = static_cast<uInt>(input.size());
    QByteArray output;
    int status;
    do {
        char chunk[4096];
        stream.next_out = reinterpret_cast<Bytef *>(chunk);
        stream.avail_out = sizeof(chunk);
        status = deflate(&stream, Z_FINISH);
        output.append(chunk, int(sizeof(chunk) - stream.avail_out));
    } while (status == Z_OK);
    deflateEnd(&stream);
    check(status == Z_STREAM_END, "synthetic compression finishes");
    return status == Z_STREAM_END ? output : QByteArray();
}

void testHeadersAndVersions()
{
    for (int version = 5; version <= 10; ++version) {
        const QString label = QString("v%1 header").arg(version);
        const QByteArray data = header(version) + basicBody(version);
        int detected = -1;
        check(FlirtParser::isFlirt(data, &detected) && detected == version, label + " detection");
        const FlirtResult result = FlirtParser().parse(data);
        if (!accepted(result, label)) continue;
        const auto &h = result.header;
        check(h.version == version && h.arch == 13, label + " version/architecture");
        check(h.fileTypes == 0x12345678 && h.osTypes == 0x1234 && h.appTypes == 0x5678,
              label + " little-endian types");
        check(h.oldNFunctions == 0x2345 && h.crc16 == 0x3456 && h.ctypesCrc16 == 0x4567,
              label + " little-endian words");
        check(h.features == 0 && h.ctype == "abcdefghijkl" && h.libraryNameLen == 3
              && result.libraryName == "lib", label + " fixed fields/library");
        check(h.patternSize == 32, label + " explicit/implicit pattern size");
        check(h.unknownV10 == (version == 10 ? 0x1234 : 0), label + " v10 little-endian field");
        if (version >= 6) check(h.nFunctions == 0x12345678, label + " extended function count");
        check(result.modules.size() == 1, label + " one module");
        if (result.modules.size() == 1)
            check(result.modules[0].crc16 == 0x1234 && result.modules[0].crcLength == 7,
                  label + " tree CRC is big-endian");
        // Every proper prefix includes all header, library and leaf truncations.
        for (int size = 0; size < data.size(); ++size)
            reject(data.left(size), QString("v%1 basic proper prefix %2").arg(version).arg(size));
    }
    for (int version : {0, 4, 11, 255}) {
        QByteArray data = header(10) + basicBody(10);
        data[6] = char(version);
        check(!FlirtParser::isFlirt(data), "unsupported version detection");
        reject(data, "unsupported version parse");
    }
    QByteArray bad = header(10) + basicBody(10);
    bad[0] = 'X';
    reject(bad, "invalid magic");
    check(fileTypesToString(0x40000) == "ELF", "ELF file type bit");
    check(fileTypesToString(0x4000) == "ZIP", "ZIP must not be ELF");
    check(fileTypesToString(0x80040000).contains("ELF")
          && fileTypesToString(0x80040000).contains("80000000"), "unknown file bits retained");
    check(osTypesToString(0x90).contains("UNIX") && osTypesToString(0x90).contains("0080"),
          "unknown OS bits retained");
    check(appTypesToString(0x8100).contains("32_BIT") && appTypesToString(0x8100).contains("8000"),
          "unknown application bits retained");
    check(featuresToString(0x8010).contains("COMPRESSED") && featuresToString(0x8010).contains("8000"),
          "unknown feature bits retained");
    check(featuresToString(0) == "none", "zero features");
}

void testIntegersAndContinuations()
{
    const quint32 values[] = {0x7f, 0x1234, 0x01234567, 0x89abcdef};
    const int widths[] = {1, 2, 4, 5};
    for (int i = 0; i < 4; ++i) {
        const QByteArray body = number(0, widths[i]) + crcGroup(number(values[i], widths[i])
            + number(values[i], widths[i]) + QByteArray("wide\0", 5));
        const auto result = parseBody(10, body);
        if (accepted(result, QString("%1-byte varints").arg(widths[i])) && result.modules.size() == 1) {
            check(result.modules[0].length == values[i], "varint module length value");
            check(result.modules[0].publicFunctions.size() == 1
                  && result.modules[0].publicFunctions[0].offset == values[i], "varint public offset value");
        }
    }
    for (int version : {5, 8, 9, 10}) {
        QByteArray publics = publicFunction(version, 0x1234, "first", IDASIG_PARSE_MORE_PUBLIC_NAMES,
                                            IDASIG_FUNCTION_LOCAL | IDASIG_FUNCTION_UNRESOLVED_COLLISION);
        publics += publicFunction(version, 2, "second", IDASIG_PARSE_MORE_MODULES_WITH_SAME_CRC);
        QByteArray group = module(version, publics, 0x2345);
        group += module(version, publicFunction(version, 3, "third", IDASIG_PARSE_MORE_MODULES));
        const QByteArray body = number(0) + crcGroup(group)
            + crcGroup(module(version, publicFunction(version, 4, "fourth")), 9, 0xabcd);
        const auto result = parseBody(version, body);
        if (!accepted(result, "public and both module continuation flags")) continue;
        check(result.modules.size() == 3, "module continuation count");
        if (result.modules.size() != 3) continue;
        const auto &functions = result.modules[0].publicFunctions;
        check(functions.size() == 2, "public continuation count");
        if (functions.size() == 2) {
            check(functions[0].isLocal && functions[0].isCollision, "local and collision flags");
            check(!functions[1].isLocal && !functions[1].isCollision, "function flags do not leak");
            check(functions[1].offset == 0x1236, "public offsets accumulate");
        }
        check(result.modules[1].crc16 == 0x1234 && result.modules[2].crc16 == 0xabcd,
              "same CRC versus new CRC continuation");
        check(result.modules[1].publicFunctions[0].offset == 3, "offset resets for next module");
        const auto entries = result.allFunctions();
        check(entries.size() == 4, "flattened function count");
        if (entries.size() == 4)
            check(entries[3].moduleIndex == 2 && entries[3].module == &result.modules[2]
                  && entries[3].function == &result.modules[2].publicFunctions[0], "flattened pointers");
    }
    const quint32 max = std::numeric_limits<quint32>::max();
    for (int version : {9, 10}) {
        const QByteArray first = publicFunction(version, max, "last", IDASIG_PARSE_MORE_PUBLIC_NAMES);
        const auto result = parseBody(version, number(0) + crcGroup(module(version,
            first + publicFunction(version, 0, "alias"), max)));
        if (accepted(result, "32-bit maximum offset and zero delta") && result.modules.size() == 1)
            check(result.modules[0].publicFunctions.size() == 2
                  && result.modules[0].publicFunctions[1].offset == max, "32-bit offset preserved");
        reject(header(version) + number(0) + crcGroup(module(version,
            first + publicFunction(version, 1, "overflow"), max)), "public offset overflow rejected");
    }
}

void testTailsReferencesAndNames()
{
    for (int version = 5; version <= 10; ++version) {
        QByteArray extra;
        const int count = version >= 8 ? 2 : 1;
        if (version >= 8) byte(extra, count);
        for (int i = 0; i < count; ++i) {
            extra += offsetNumber(version, 0x1234 + i); byte(extra, 0xa0 + i);
        }
        if (version >= 8) byte(extra, count);
        extra += reference(version, 0x1234, QByteArray("target\0", 7));
        if (count == 2) extra += reference(version, 3, QByteArray("caf\xe9", 4), true);
        const QByteArray body = number(0) + crcGroup(module(version, publicFunction(version, 0,
            QByteArray("pub\xe9", 4), IDASIG_PARSE_READ_TAIL_BYTES | IDASIG_PARSE_READ_REFERENCED_FUNCTIONS)) + extra);
        const auto result = parseBody(version, body);
        if (!accepted(result, QString("v%1 tail/reference counts").arg(version)) || result.modules.size() != 1) continue;
        const auto &mod = result.modules[0];
        check(mod.tailBytes.size() == count && mod.referencedFunctions.size() == count,
              "version-specific optional record counts");
        check(mod.publicFunctions[0].name == QString::fromLatin1("pub\xe9", 4), "public name stays Latin1");
        if (mod.tailBytes.size() == count)
            check(mod.tailBytes[0].offset == 0x1234 && mod.tailBytes[0].value == 0xa0, "tail offset/value");
        if (mod.referencedFunctions.size() == count) {
            const auto &ref = mod.referencedFunctions[0];
            check(ref.offset == 0x1234 && ref.negativeOffset && ref.name == "target",
                  "reference trailing NUL marks negative offset and is removed");
            check(mod.rulesSummary().contains("-1234") && mod.rulesSummary().contains("target"),
                  "reference summary contains negative sign/name");
            if (count == 2)
                check(!mod.referencedFunctions[1].negativeOffset
                      && mod.referencedFunctions[1].name == QString::fromLatin1("caf\xe9", 4),
                      "extended reference length and Latin1");
        }
        // Exercise truncation inside tail offsets, values, counts and reference names.
        for (int size = 0; size < extra.size(); ++size)
            reject(header(version) + body.left(body.size() - extra.size() + size), "truncated optional record");
    }
    const int version = 10;
    for (int size : {1500, FLIRT_NAME_MAX - 1, FLIRT_NAME_MAX, FLIRT_NAME_MAX + 1}) {
        const QByteArray name(size, 'N');
        const QByteArray data = header(version) + number(0)
            + crcGroup(module(version, publicFunction(version, 0, name)));
        if (size < FLIRT_NAME_MAX) {
            const auto result = FlirtParser().parse(data);
            if (accepted(result, "public name just below bound") && result.modules.size() == 1)
                check(result.modules[0].publicFunctions[0].name.size() == size, "long public name preserved");
        } else {
            reject(data, "public name at/above limit rejected");
        }
        QByteArray extra(1, char(1));
        extra += reference(version, 0, name, true);
        const QByteArray refData = header(version) + number(0) + crcGroup(module(version,
            publicFunction(version, 0, "entry", IDASIG_PARSE_READ_REFERENCED_FUNCTIONS)) + extra);
        if (size < FLIRT_NAME_MAX) {
            const auto result = FlirtParser().parse(refData);
            if (accepted(result, "reference name just below bound") && result.modules.size() == 1)
                check(result.modules[0].referencedFunctions.size() == 1
                      && result.modules[0].referencedFunctions[0].name.size() == size, "long reference preserved");
        } else {
            reject(refData, "reference length at/above bound rejected");
        }
    }
    // The next printable byte is 0x41 (MORE_PUBLIC_NAMES if misread as flags).
    // A complete fake second function must not rescue an overlong first name.
    QByteArray malicious = offsetNumber(version, 0) + QByteArray(FLIRT_NAME_MAX, 'N') + 'A';
    malicious += publicFunction(version, 0, "fake");
    reject(header(version) + number(0) + crcGroup(module(version, malicious)),
           "overlong name continuation is not parsed as flags");

    QByteArray extra(1, char(1));
    extra += offsetNumber(version, 0); byte(extra, 0); extra += number(0xffffffff);
    reject(header(version) + number(0) + crcGroup(module(version,
        publicFunction(version, 0, "entry", IDASIG_PARSE_READ_REFERENCED_FUNCTIONS)) + extra),
        "huge extended reference length rejected before reading/allocating");

    // v8+ explicit zero counts are valid and consume no implicit records.
    for (int v : {8, 9, 10}) {
        const auto result = parseBody(v, number(0) + crcGroup(module(v, publicFunction(v, 0, "entry",
            IDASIG_PARSE_READ_TAIL_BYTES | IDASIG_PARSE_READ_REFERENCED_FUNCTIONS)) + QByteArray(2, '\0')));
        if (accepted(result, "zero tail/reference counts") && result.modules.size() == 1)
            check(result.modules[0].tailBytes.isEmpty() && result.modules[0].referencedFunctions.isEmpty(),
                  "zero optional counts produce empty vectors");
    }
    // All offset-bearing optional fields need the full v9+ 32-bit decoder too.
    QByteArray wide(1, char(1)); wide += number(0x89abcdef); byte(wide, 0xa5);
    byte(wide, 1); wide += reference(10, 0xfedcba98, "wide");
    const auto result = parseBody(10, number(0) + crcGroup(module(10, publicFunction(10, 0, "entry",
        IDASIG_PARSE_READ_TAIL_BYTES | IDASIG_PARSE_READ_REFERENCED_FUNCTIONS), 0xffffffff) + wide));
    if (accepted(result, "32-bit tail/reference offsets") && result.modules.size() == 1)
        check(result.modules[0].tailBytes.size() == 1 && result.modules[0].referencedFunctions.size() == 1
              && result.modules[0].tailBytes[0].offset == 0x89abcdef
              && result.modules[0].referencedFunctions[0].offset == 0xfedcba98, "wide optional offsets preserved");
}

void testPatternsAndLimits()
{
    for (int length : {15, 16, 32, 33, 63, 64}) {
        const quint64 mask = (quint64(1) << (length - 1)) | 1;
        const auto result = parseBody(10, node(length, mask) + basicBody(10));
        if (!accepted(result, QString("%1-byte pattern mask boundary").arg(length)) || result.modules.size() != 1) continue;
        const auto &path = result.modules[0].patternPath;
        check(path.size() == 1, "one pattern node");
        if (path.size() != 1) continue;
        check(path[0].patternBytes.size() == length && path[0].variantMask.size() == length,
              "pattern/mask lengths");
        for (int i = 0; i < length; ++i) {
            const bool variant = i == 0 || i == length - 1;
            check(bool(path[0].variantMask[i]) == variant, "variant mask bit order");
            if (!variant)
                check(static_cast<quint8>(path[0].patternBytes[i]) == 0x90 + i % 16,
                      "literal bytes exclude wildcard positions");
        }
        check(path[0].toHexString().startsWith("..") && path[0].toHexString().endsWith("..")
              && path[0].toHexString().size() == 2 * length, "pattern display wildcards");
    }
    QByteArray tooLong = number(1); byte(tooLong, 65);
    tooLong += number(0) + number(0) + QByteArray(65, 'x') + basicBody(10);
    reject(header(10) + tooLong, "65-byte node rejected");
    for (int depth : {1, 64, 65}) {
        QByteArray body;
        for (int i = 0; i < depth; ++i) body += node(0);
        body += basicBody(10);
        if (depth <= 64) accepted(parseBody(10, body), "zero-length nodes allowed within depth bound");
        else reject(header(10) + body, "zero-length nodes cannot bypass depth limit 64");
    }
    accepted(parseBody(10, node(32) + node(32) + basicBody(10)), "cumulative pattern length 64 accepted");
    reject(header(10) + node(32) + node(33) + basicBody(10), "cumulative pattern length 65 rejected at default size");
    accepted(parseBody(10, node(40) + node(40) + basicBody(10), 80), "larger declared pattern size permits cumulative length 80");
    reject(header(10, 0, 80) + node(40) + node(41) + basicBody(10), "declared cumulative pattern length exceeded");
    accepted(parseBody(10, node(64) + basicBody(10), 1), "minimum cumulative allowance remains 64");
    const QByteArray full = header(10) + node(33, (quint64(1) << 32) | 1) + basicBody(10);
    for (int size = header(10).size(); size < full.size(); ++size)
        reject(full.left(size), "truncated node mask/literals/leaf");
    // Truncate each multibyte representation in a required integer field.
    for (int width : {2, 4, 5}) {
        const QByteArray encoded = number(width == 2 ? 0x1234 : width == 4 ? 0x1234567 : 0x89abcdef, width);
        for (int size = 1; size < encoded.size(); ++size)
            reject(header(10) + number(0) + QByteArray("\x07\x12\x34", 3) + encoded.left(size),
                   "truncated multibyte module length");
    }
}

void testCompression()
{
    for (int version = 5; version <= 10; ++version) {
        const QByteArray body = basicBody(version);
        const int bits = version <= 6 ? -MAX_WBITS : MAX_WBITS;
        const QByteArray packed = compressed(body, bits);
        const QByteArray h = header(version, IDASIG_FEATURE_COMPRESSED);
        const auto result = FlirtParser().parse(h + packed);
        if (accepted(result, QString("v%1 compressed body").arg(version)))
            check(result.modules.size() == 1 && result.modules[0].publicFunctions[0].name == "entry",
                  "compressed body content");
        for (int size = 0; size < packed.size(); ++size)
            reject(h + packed.left(size), "every truncated compressed stream rejected");
        if (version >= 7) {
            // Removing only the Adler32 trailer still inflates to a valid complete tree.
            // Successful parsing of that tree must not hide a missing stream trailer.
            reject(h + packed.left(packed.size() - 4), "valid inflated tree without Adler32 rejected");
            QByteArray corrupt = packed;
            corrupt[corrupt.size() - 1] = char(static_cast<quint8>(corrupt.back()) ^ 0x80);
            reject(h + corrupt, "corrupted zlib checksum rejected");
        }
    }
    const QByteArray signature = header(10) + basicBody(10);
    const QByteArray gzip = compressed(signature, MAX_WBITS + 16);
    const QByteArray unpacked = FlirtParser::decompressGzip(gzip);
    check(unpacked == signature, "external gzip round-trip");
    accepted(FlirtParser().parse(unpacked), "external gzip signature parses");
    for (int size = 0; size < gzip.size(); ++size)
        check(FlirtParser::decompressGzip(gzip.left(size)).isEmpty(), "truncated gzip rejected");
    for (int index : {int(gzip.size() - 8), int(gzip.size() - 1)}) {
        QByteArray corrupt = gzip;
        corrupt[index] = char(static_cast<quint8>(corrupt[index]) ^ 0x80);
        check(FlirtParser::decompressGzip(corrupt).isEmpty(), "gzip CRC/size corruption rejected");
    }
    check(FlirtParser::decompressGzip(signature).isEmpty(), "non-gzip input rejected");
    const QByteArray large(2 * 65536 + 17, 'x');
    check(FlirtParser::decompressGzip(compressed(large, MAX_WBITS + 16)) == large,
          "gzip expansion spans multiple output chunks");
}

void smokeDirectory(const QString &path)
{
    if (!QFileInfo(path).isDir()) {
        check(false, "smoke path is not a directory: " + path);
        return;
    }
    QMap<int, int> perVersion;
    int total = 0;
    int failed = 0;
    QDirIterator it(path, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString filePath = it.next();
        if (!filePath.endsWith(".sig", Qt::CaseInsensitive)) continue;
        ++total;
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly)) {
            ++failed;
            check(false, filePath + ": " + file.errorString());
            continue;
        }
        const QByteArray data = file.readAll();
        int version = -1;
        FlirtParser::isFlirt(data, &version);
        ++perVersion[version];
        const auto result = FlirtParser().parse(data);
        if (!result.success) {
            ++failed;
            check(false, filePath + ": " + result.errorMessage);
        }
    }
    QTextStream out(stdout);
    out << "Smoke: " << total << " .sig files, " << failed << " failures\n";
    for (int version = 5; version <= 10; ++version)
        out << "  v" << version << ": " << perVersion.value(version) << '\n';
    for (auto it = perVersion.cbegin(); it != perVersion.cend(); ++it)
        if (it.key() < 5 || it.key() > 10)
            out << "  unsupported/unknown v" << it.key() << ": " << it.value() << '\n';
}
} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    testHeadersAndVersions();
    testIntegersAndContinuations();
    testTailsReferencesAndNames();
    testPatternsAndLimits();
    testCompression();
    if (app.arguments().size() > 2) {
        check(false, "usage: flirtparser_test [directory-containing-sig-files]");
    } else if (app.arguments().size() == 2) {
        smokeDirectory(app.arguments().at(1));
    }
    QTextStream(stdout) << "Checks: " << checks << ", failures: " << failures << '\n';
    return failures == 0 ? 0 : 1;
}
