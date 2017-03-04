from capstone import *
from keystone import *
from flask import Flask, request, Response
import json
import string as s

app = Flask(__name__)

asm_archmodes = {
    'x16': [KS_ARCH_X86, KS_MODE_16],
    'x32': [KS_ARCH_X86, KS_MODE_32],
    'x64': [KS_ARCH_X86, KS_MODE_64],
    'arm': [KS_ARCH_ARM, KS_MODE_ARM],
    'armbe': [KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_BIG_ENDIAN],
    'thumb': [KS_ARCH_ARM, KS_MODE_THUMB],
    'thumbbe': [KS_ARCH_ARM, KS_MODE_THUMB + KS_MODE_BIG_ENDIAN],
    'arm64': [KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN]
}

disasm_archmodes = {
    'x16': [CS_ARCH_X86, CS_MODE_16],
    'x32': [CS_ARCH_X86, CS_MODE_32],
    'x64': [CS_ARCH_X86, CS_MODE_64],
    'arm': [CS_ARCH_ARM, CS_MODE_ARM],
    'armbe': [CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_BIG_ENDIAN],
    'thumb': [CS_ARCH_ARM, CS_MODE_THUMB],
    'thumbbe': [CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_BIG_ENDIAN],
    'arm64': [CS_ARCH_ARM64, CS_MODE_ARM]
}


class JSONResponse(Response):
    default_mimetype = 'application/json'


@app.route('/')
def hello_world():
    return 'Get outta here'


def _format_opcode(op):
    op_addr = s.ljust(hex(int(op.address)), 15)
    op_bytes = s.ljust(str(bytearray(op.bytes)).encode('hex'), 20)
    op_mnemonic = s.ljust(op.mnemonic, 10)

    return op_addr + op_bytes  + op_mnemonic  + op.op_str


@app.errorhandler(Exception)
def all_exception_handler(error):
   return 'Error: ' + str(error)


@app.route('/disasm', methods=['POST'])
def disasm():
    text = request.form['text'].strip()

    if len(text) == 0:
        return JSONResponse(json.dumps({'response_type': 'ephemeral', 'text': 'Usage: /disasm [archmode] [hex code]\n  archmode: ' + ', '.join(disasm_archmodes.keys())}))

    parts = text.split(' ')
    archmode = parts[0]
    code = ' '.join(parts[1:])

    if archmode in disasm_archmodes:
        cs = Cs(*disasm_archmodes[archmode])

        out = "\n".join([_format_opcode(op) for op in cs.disasm(code.decode('hex'), 0x0)])

        return JSONResponse(json.dumps({'response_type': 'in_channel', 'text': '```' + out + '```'}))
    else:
        return '/usage [archmode] [hex code]\nInvalid archmode. Available archmodes are: ' + ', '.join(disasm_archmodes.keys())


@app.route('/asm', methods=['POST'])
def asm():
    text = request.form['text'].strip()

    if len(text) == 0:
        return JSONResponse(json.dumps({'response_type': 'ephemeral', 'text': 'Usage: /asm [archmode] [code]\n  archmode: ' + ', '.join(asm_archmodes.keys())}))

    parts = text.split(' ')
    archmode = parts[0]
    code = ' '.join(parts[1:])

    if archmode in asm_archmodes:
        ks = Ks(*asm_archmodes[archmode])
        code, count = ks.asm(code)
        data = str(bytearray(code)).encode('hex')

        return JSONResponse(json.dumps({'response_type': 'in_channel', 'text': data}))
    else:
        return 'Usage: /asm [archmode] [code]\nInvalid archmode. Available archmodes are: ' + ', '.join(asm_archmodes.keys())

