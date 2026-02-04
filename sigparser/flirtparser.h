#ifndef FLIRTPARSER_H
#define FLIRTPARSER_H

#include <QString>
#include <QByteArray>
#include <QVector>

namespace SigParser {

// FLIRT .sig format constants (from radare2 flirt.c)
constexpr uint8_t IDASIG_FEATURE_COMPRESSED = 0x10;
constexpr uint8_t IDASIG_PARSE_MORE_PUBLIC_NAMES = 0x01;
constexpr uint8_t IDASIG_PARSE_READ_TAIL_BYTES = 0x02;
constexpr uint8_t IDASIG_PARSE_READ_REFERENCED_FUNCTIONS = 0x04;
constexpr uint8_t IDASIG_PARSE_MORE_MODULES_WITH_SAME_CRC = 0x08;
constexpr uint8_t IDASIG_PARSE_MORE_MODULES = 0x10;
constexpr uint8_t IDASIG_FUNCTION_LOCAL = 0x02;
constexpr uint8_t IDASIG_FUNCTION_UNRESOLVED_COLLISION = 0x08;
constexpr int FLIRT_NAME_MAX = 1024;

struct FlirtFunction {
    QString name;
    quint32 offset = 0;
    bool isLocal = false;
    bool isCollision = false;
};

struct FlirtTailByte {
    quint32 offset = 0;
    quint8 value = 0;
};

struct FlirtRefFunction {
    quint32 offset = 0;
    QString name;
    bool negativeOffset = false;
};

// One node's pattern for display: hex string with ".." for variant bytes
struct FlirtPatternNode {
    QByteArray patternBytes;
    QByteArray variantMask;  // 1 = variant
    QString toHexString() const;
};

struct FlirtModule {
    QVector<FlirtPatternNode> patternPath;  // path from root to this leaf
    quint32 crcLength = 0;
    quint32 crc16 = 0;
    quint32 length = 0;
    QVector<FlirtFunction> publicFunctions;
    QVector<FlirtTailByte> tailBytes;
    QVector<FlirtRefFunction> referencedFunctions;
    QString patternPathHex() const;
    QString rulesSummary() const;
};

struct FlirtHeader {
    int version = 0;
    quint8 arch = 0;
    quint32 fileTypes = 0;
    quint16 osTypes = 0;
    quint16 appTypes = 0;
    quint16 features = 0;
    quint16 oldNFunctions = 0;
    quint16 crc16 = 0;
    QByteArray ctype;
    quint8 libraryNameLen = 0;
    quint16 ctypesCrc16 = 0;
    quint32 nFunctions = 0;   // v6/v7
    quint16 patternSize = 0;  // v8/v9
    quint16 unknownV10 = 0;    // v10
};

struct FlirtResult {
    bool success = false;
    QString errorMessage;
    QString libraryName;
    FlirtHeader header;
    QVector<FlirtModule> modules;
    // Flattened list of all public functions with module index for display
    struct FunctionEntry {
        int moduleIndex = 0;
        const FlirtModule *module = nullptr;
        const FlirtFunction *function = nullptr;
    };
    QVector<FunctionEntry> allFunctions() const;
};

// Parser internal state (used by FlirtParser and .cpp helpers)
struct ParseState {
    QByteArray body;
    qsizetype pos = 0;
    int version = 0;
    bool eof = false;
    bool err = false;
};

class FlirtParser
{
public:
    FlirtParser() = default;
    FlirtResult parse(const QByteArray &data);
    static bool isFlirt(const QByteArray &data, int *outVersion = nullptr);
    /** Decompress gzip (.sig.gz) file content. Returns empty QByteArray on error. */
    static QByteArray decompressGzip(const QByteArray &gzipData);

private:
    bool parseHeader(ParseState &st, FlirtResult &result);
    bool parseTree(ParseState &st, FlirtResult &result, QVector<FlirtPatternNode> &path, QVector<FlirtModule> &modulesOut);
    bool parseLeaf(ParseState &st, const QVector<FlirtPatternNode> &path, QVector<FlirtModule> &modulesOut);
    bool readNodeLength(ParseState &st, quint8 &len);
    bool readNodeVariantMask(ParseState &st, quint8 nodeLen, quint64 &mask);
    bool readNodeBytes(ParseState &st, quint8 nodeLen, quint64 variantMask, FlirtPatternNode &nodeOut);
    bool readModulePublicFunctions(ParseState &st, FlirtModule &mod, quint8 &flags);
    bool readModuleTailBytes(ParseState &st, FlirtModule &mod);
    bool readModuleReferencedFunctions(ParseState &st, FlirtModule &mod);

    quint8 readByte(ParseState &st);
    quint16 readShortBE(ParseState &st);
    quint16 readMax2Bytes(ParseState &st);
    quint32 readMultipleBytes(ParseState &st);
};

// Display helpers
QString archToString(quint8 arch);
QString fileTypesToString(quint32 ft);
QString osTypesToString(quint16 ot);
QString appTypesToString(quint16 at);
QString featuresToString(quint16 f);

} // namespace SigParser

#endif // FLIRTPARSER_H
