import argparse
import logging
import marshal
import opcode
import os
import py_compile
import struct
import sys
import math
import string
import types

magic_to_version = {
    20121: "1.5",
    50428: "1.6",
    50823: "2.0",
    60202: "2.1",
    60717: "2.2",
    62011: "2.3a0",
    62021: "2.3a0",
    62041: "2.4a0",
    62051: "2.4a3",
    62061: "2.4b1",
    62071: "2.5a0",
    62081: "2.5a0",
    62091: "2.5a0",
    62092: "2.5a0",
    62101: "2.5b3",
    62111: "2.5c1",
    62121: "2.5c2",
    62131: "2.6a0",
    62151: "2.6a1",
    62161: "2.7a0",
    62171: "2.7a0",
    62181: "2.7a0",
    62191: "2.7a0",
    62201: "2.7a0",
    62211: "2.7a0",
    3111: "Python 3.0a4",
    3131: "Python 3.0b1",
    3141: "Python 3.1a1",
    3151: "Python 3.1a1",
    3160: "Python 3.2a1",
    3170: "Python 3.2a2",
    3180: "Python 3.2a3",
    3190: "Python 3.3a1",
    3200: "Python 3.3a1",
    3210: "Python 3.3a1",
    3220: "Python 3.3a2",
    3230: "Python 3.3a4",
    3250: "Python 3.4a1",
    3260: "Python 3.4a1",
    3270: "Python 3.4a1",
    3280: "Python 3.4a1",
    3290: "Python 3.4a4",
    3300: "Python 3.4a4",
    3310: "Python 3.4rc2",
    3320: "Python 3.5a1",
    3330: "Python 3.5b1",
    3340: "Python 3.5b2",
    3350: "Python 3.5b3",
    3351: "Python 3.5.2",
    3360: "Python 3.6a0",
    3361: "Python 3.6a1",
    3370: "Python 3.6a2",
    3371: "Python 3.6a2",
    3372: "Python 3.6a2",
    3373: "Python 3.6b1",
    3375: "Python 3.6b1",
    3376: "Python 3.6b1",
    3377: "Python 3.6b1",
    3378: "Python 3.6b2",
    3379: "Python 3.6rc1",
    3390: "Python 3.7a1",
    3391: "Python 3.7a2",
    3392: "Python 3.7a4",
    3393: "Python 3.7b1",
    3394: "Python 3.7b5",
    3400: "Python 3.8a1",
    3401: "Python 3.8a1",
    3410: "Python 3.8a1",
    3411: "Python 3.8b2",
    3412: "Python 3.8b2",
    3413: "Python 3.8b4",
    3420: "Python 3.9a0",
    3421: "Python 3.9a0",
    3422: "Python 3.9a0",
    3423: "Python 3.9a2",
    3424: "Python 3.9a2",
    3425: "Python 3.9a2",
    3430: "Python 3.10a1",
    3431: "Python 3.10a1",
    3432: "Python 3.10a2",
    3433: "Python 3.10a2",
    3434: "Python 3.10a6",
    3435: "Python 3.10a7",
    3436: "Python 3.10b1",
    3437: "Python 3.10b1",
    3438: "Python 3.10b1",
    3439: "Python 3.10b1",
    3450: "Python 3.11a1",
    3451: "Python 3.11a1",
    3452: "Python 3.11a2",
    3453: "Python 3.11a3",
    3454: "Python 3.11a4",
    3455: "Python 3.11a5",
    3456: "Python 3.11a6",
    3457: "Python 3.11a7",
    3458: "Python 3.11a8",
    3459: "Python 3.11a9",
    3460: "Python 3.11a10",
    3461: "Python 3.11a11",
    3462: "Python 3.11a12",
    3470: "Python 3.12a1",
    3471: "Python 3.12a2",
    3472: "Python 3.12a3",
    3473: "Python 3.12a4",
    3474: "Python 3.12a5",
    3475: "Python 3.12a6",
    3476: "Python 3.12a7",
    3477: "Python 3.12a8",
    3478: "Python 3.12a9",
    3479: "Python 3.12a10",
}

if sys.version_info < (3, 6):
    sys.exit("Stegosaurus requires Python 3.6 or later")


def get_pyc_version(pyc_file):
    with open(pyc_file, 'rb') as f:
        magic = f.read(4)  # 读取魔数
        magic_number = struct.unpack('<H', magic[:2])[0]
        return magic_number

def check_version_compatibility(pyc_file):
    magic_number = get_pyc_version(pyc_file)

    # 检查魔数是否在字典中
    if magic_number in magic_to_version:
        pyc_version = magic_to_version[magic_number]
        print(f".pyc file is compiled with Python {pyc_version} (magic number: {magic_number})")
    else:
        print(f"Unknown magic number: {magic_number}")


class MutableBytecode():
    def __init__(self, code):
        self.originalCode = code
        self.bytes = bytearray(code.co_code)
        self.consts = [MutableBytecode(const) if isinstance(const, types.CodeType) else const for const in code.co_consts]


def _bytesAvailableForPayload(mutableBytecodeStack, explodeAfter, logger=None):
    for mutableBytecode in reversed(mutableBytecodeStack):
        bytes = mutableBytecode.bytes
        consecutivePrintableBytes = 0
        for i in range(0, len(bytes)):
            if chr(bytes[i]) in string.printable:
                consecutivePrintableBytes += 1
            else:
                consecutivePrintableBytes = 0

            if i % 2 == 0 and bytes[i] < opcode.HAVE_ARGUMENT:
                if consecutivePrintableBytes >= explodeAfter:
                    if logger:
                        logger.debug("Skipping available byte to terminate string leak")
                    consecutivePrintableBytes = 0
                    continue
                yield (bytes, i + 1)


def _createMutableBytecodeStack(mutableBytecode):
    def _stack(parent, stack):
        stack.append(parent)

        for child in [const for const in parent.consts if isinstance(const, MutableBytecode)]:
            _stack(child, stack)

        return stack

    return _stack(mutableBytecode, [])


def _dumpBytecode(header, code, carrier, logger):
    try:
        f = open(carrier, "wb")
        f.write(header)
        marshal.dump(code, f)
        logger.info("Wrote carrier file as %s", carrier)
    finally:
        f.close()


def _embedPayload(mutableBytecodeStack, payload, explodeAfter, logger):
    payloadBytes = bytearray(payload, "utf8")
    payloadIndex = 0
    payloadLen = len(payloadBytes)

    for bytes, byteIndex in _bytesAvailableForPayload(mutableBytecodeStack, explodeAfter):
        if payloadIndex < payloadLen:
            bytes[byteIndex] = payloadBytes[payloadIndex]
            payloadIndex += 1
        else:
            bytes[byteIndex] = 0

    print("Payload embedded in carrier")


def _extractPayload(mutableBytecodeStack, explodeAfter, logger):
    payloadBytes = bytearray()

    for bytes, byteIndex in _bytesAvailableForPayload(mutableBytecodeStack, explodeAfter):
        byte = bytes[byteIndex]
        if byte == 0:
            break
        payloadBytes.append(byte)

    payload = str(payloadBytes, "utf8")

    print("Extracted payload: {}".format(payload))


def _getCarrierFile(args, logger):
    carrier = args.carrier
    _, ext = os.path.splitext(carrier)

    if ext == ".py":
        carrier = py_compile.compile(carrier, doraise=True)
        logger.info("Compiled %s as %s for use as carrier", args.carrier, carrier)

    return carrier


def _initLogger(args):
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    logger = logging.getLogger("stegosaurus")
    logger.addHandler(handler)

    if args.verbose:
        if args.verbose == 1:
            logger.setLevel(logging.INFO)
        else:
            logger.setLevel(logging.DEBUG)

    return logger


def _loadBytecode(carrier, logger):
    try:
        f = open(carrier, "rb")
        header = b''
        code = None
        for i in range(1, 20):
            f.seek(0)
            header = f.read(i)
            try:
                potential_code = marshal.load(f)
                if isinstance(potential_code, types.CodeType):
                    code = potential_code
                    logger.debug(f"Successfully read header with length {i} and loaded bytecode")
                    break
                else:
                    logger.debug(f"Loaded object is not a CodeType with header length {i}")
            except Exception as e:
                logger.debug(f"Failed to load bytecode with header length {i}: {e}")
                continue
        if code is None:
            raise ValueError("Could not find a valid header size to load bytecode.")
    finally:
        f.close()

    return (header, code)

def _logBytesAvailableForPayload(mutableBytecodeStack, explodeAfter, logger):
    for bytes, i in _bytesAvailableForPayload(mutableBytecodeStack, explodeAfter, logger):
        logger.debug("%s (%d)", opcode.opname[bytes[i - 1]], bytes[i])


def _maxSupportedPayloadSize(mutableBytecodeStack, explodeAfter, logger):
    maxPayloadSize = 0

    for bytes, i in _bytesAvailableForPayload(mutableBytecodeStack, explodeAfter):
        maxPayloadSize += 1

    logger.info("Found %d bytes available for payload", maxPayloadSize)

    return maxPayloadSize


def _parseArgs():
    argParser = argparse.ArgumentParser()
    argParser.add_argument("carrier", help="Carrier py, pyc or pyo file")
    argParser.add_argument("-p", "--payload", help="Embed payload in carrier file")
    argParser.add_argument("-r", "--report", action="store_true", help="Report max available payload size carrier supports")
    argParser.add_argument("-s", "--side-by-side", action="store_true", help="Do not overwrite carrier file, install side by side instead.")
    argParser.add_argument("-v", "--verbose", action="count", help="Increase verbosity once per use")
    argParser.add_argument("-x", "--extract", action="store_true", help="Extract payload from carrier file")
    argParser.add_argument("-e", "--explode", type=int, default=math.inf, help="Explode payload into groups of a limited length if necessary")
    args = argParser.parse_args()

    return args


def _toCodeType(mutableBytecode):
    return types.CodeType(
        mutableBytecode.originalCode.co_argcount,
        mutableBytecode.originalCode.co_kwonlyargcount,
        mutableBytecode.originalCode.co_nlocals,
        mutableBytecode.originalCode.co_stacksize,
        mutableBytecode.originalCode.co_flags,
        bytes(mutableBytecode.bytes),
        tuple([_toCodeType(const) if isinstance(const, MutableBytecode) else const for const in mutableBytecode.consts]),
        mutableBytecode.originalCode.co_names,
        mutableBytecode.originalCode.co_varnames,
        mutableBytecode.originalCode.co_filename,
        mutableBytecode.originalCode.co_name,
        mutableBytecode.originalCode.co_firstlineno,
        mutableBytecode.originalCode.co_lnotab,
        mutableBytecode.originalCode.co_freevars,
        mutableBytecode.originalCode.co_cellvars
        )


def _validateArgs(args, logger):
    def _exit(msg):
        msg = "Fatal error: {}\nUse -h or --help for usage".format(msg)
        sys.exit(msg)

    allowedCarriers = {".py", ".pyc", ".pyo"}

    _, ext = os.path.splitext(args.carrier)

    if ext not in allowedCarriers:
        _exit("Carrier file must be one of the following types: {}, got: {}".format(allowedCarriers, ext))

    if args.payload is None:
        if not args.report and not args.extract:
            _exit("Unless -r or -x are specified, a payload is required")

    if args.extract or args.report:
        if args.payload:
            logger.warn("Payload is ignored when -x or -r is specified")
        if args.side_by_side:
            logger.warn("Side by side is ignored when -x or -r is specified")

    if args.explode and args.explode < 1:
        _exit("Values for -e must be positive integers")

    logger.debug("Validated args")


def main():
    args = _parseArgs()
    logger = _initLogger(args)

    _validateArgs(args, logger)

    carrier = _getCarrierFile(args, logger)
    check_version_compatibility(carrier)  # 在加载 bytecode 前再次进行版本检查
    header, code = _loadBytecode(carrier, logger)

    mutableBytecode = MutableBytecode(code)
    mutableBytecodeStack = _createMutableBytecodeStack(mutableBytecode)
    _logBytesAvailableForPayload(mutableBytecodeStack, args.explode, logger)

    if args.extract:
        _extractPayload(mutableBytecodeStack, args.explode, logger)
        return

    maxPayloadSize = _maxSupportedPayloadSize(mutableBytecodeStack, args.explode, logger)

    if args.report:
        print("Carrier can support a payload of {} bytes".format(maxPayloadSize))
        return

    payloadLen = len(args.payload)
    if payloadLen > maxPayloadSize:
        sys.exit("Carrier can only support a payload of {} bytes, payload of {} bytes received".format(maxPayloadSize, payloadLen))

    _embedPayload(mutableBytecodeStack, args.payload, args.explode, logger)
    _logBytesAvailableForPayload(mutableBytecodeStack, args.explode, logger)

    if args.side_by_side:
        logger.debug("Creating new carrier file name for side-by-side install")
        base, ext = os.path.splitext(carrier)
        carrier = "{}-stegosaurus{}".format(base, ext)

    code = _toCodeType(mutableBytecode)

    _dumpBytecode(header, code, carrier, logger)


if __name__ == "__main__":
    main()