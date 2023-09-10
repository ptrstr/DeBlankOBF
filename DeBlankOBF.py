import argparse
import re
import base64
import lzma
import codecs
import importlib
import struct

def marshal_to_pyc(marshal_data: bytes, bit_field=0, mod_time=0, source_size=0) -> bytes:
    data = bytearray(importlib.util.MAGIC_NUMBER)

    data.extend(struct.pack('<I', bit_field))
    data.extend(struct.pack('<I', mod_time))
    data.extend(struct.pack('<I', source_size))

    data.extend(marshal_data)

    return bytes(data)

def undo_stage1(data: bytes) -> bytes:
    blocks = dict(re.findall(br'(_+)\s*=\s*"(.*?)";', data))

    additions = re.search(br'(_+)\+(_+)\[::-1\]\+(_+)', data).groups()

    additions = [b for b in blocks.keys() if b not in additions] + list(additions)

    encoded = codecs.decode(blocks[additions[0]].decode(), 'rot13').encode() + blocks[additions[1]] + blocks[additions[2]][::-1] + blocks[additions[3]]

    return base64.b64decode(encoded)

def undo_stage2(data: bytes) -> bytes:
    return lzma.decompress(re.findall(br"b'(.*)'\s+_", data)[0].decode('unicode_escape').encode('latin1'))

def undo_stage3(data: bytes) -> bytes:
    return lzma.decompress(base64.b64decode(re.findall(br"base64.b64decode\(b'([A-Za-z0-9+/=]+)'\)", data)[0]))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('file')
    parser.add_argument('output')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    with open(args.file, 'rb') as f:
        stage3 = f.read()

    stage2 = undo_stage3(stage3)
    stage1 = undo_stage2(stage2)
    stage0 = undo_stage1(stage1)
    
    with open(args.output, 'wb') as f:
        f.write(marshal_to_pyc(stage0))

    if args.verbose:
        with open(args.output + '.2', 'wb') as f:
            f.write(stage2)

        with open(args.output + '.1', 'wb') as f:
            f.write(stage1)

        with open(args.output + '.0', 'wb') as f:
            f.write(stage0)

    print(f'Successfully wrote .pyc file to {args.output}')