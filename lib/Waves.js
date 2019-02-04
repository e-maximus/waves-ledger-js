"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const signature_generator_1 = require("@waves/signature-generator");
const WAVES_CONFIG = {
    STATUS: {
        SW_OK: 0x9000,
        SW_USER_CANCELLED: 0x9100,
        SW_CONDITIONS_NOT_SATISFIED: 0x6985,
        SW_BUFFER_OVERFLOW: 0x6990,
        SW_INCORRECT_P1_P2: 0x6A86,
        SW_INS_NOT_SUPPORTED: 0x6D00,
        SW_CLA_NOT_SUPPORTED: 0x6E00,
        SW_SECURITY_STATUS_NOT_SATISFIED: 0x6982
    },
    SECRET: 'WAVES',
    PUBLIC_KEY_LENGTH: 32,
    ADDRESS_LENGTH: 35,
    STATUS_LENGTH: 2,
    SIGNED_CODES: {
        ORDER: 0xFC,
        SOME_DATA: 0xFD,
        REQUEST: 0xFE,
        MESSAGE: 0xFF
    },
    MAX_SIZE: 128,
    WAVES_PRECISION: 8,
    MAIN_NET_CODE: 87,
    VERSIONS: [[0, 9, 6], [0, 9, 7]],
};
class Waves {
    constructor(transport, networkCode = WAVES_CONFIG.MAIN_NET_CODE) {
        this._version = null;
        this.transport = transport;
        this.networkCode = networkCode;
        this.decorateClassByTransport();
    }
    decorateClassByTransport() {
        this.transport.decorateAppAPIMethods(this, [
            'getWalletPublicKey',
            '_signData',
            'getVersion',
        ], WAVES_CONFIG.SECRET);
    }
    getWalletPublicKey(path, verify = false) {
        return __awaiter(this, void 0, void 0, function* () {
            const buffer = Waves.splitPath(path);
            const p1 = verify ? 0x80 : 0x00;
            const response = yield this.transport.send(0x80, 0x04, p1, this.networkCode, buffer);
            const publicKey = signature_generator_1.libs.base58.encode(response.slice(0, WAVES_CONFIG.PUBLIC_KEY_LENGTH));
            const address = response
                .slice(WAVES_CONFIG.PUBLIC_KEY_LENGTH, WAVES_CONFIG.PUBLIC_KEY_LENGTH + WAVES_CONFIG.ADDRESS_LENGTH)
                .toString('ascii');
            const statusCode = response
                .slice(-WAVES_CONFIG.STATUS_LENGTH)
                .toString('hex');
            return { publicKey, address, statusCode };
        });
    }
    signTransaction(path, amountPrecession, txData, version = 2) {
        return __awaiter(this, void 0, void 0, function* () {
            const transactionType = txData[0];
            const version2 = [transactionType, version];
            const type = yield this._versionNum();
            if (transactionType === 4) {
                if (type === 0) {
                    return yield this.signSomeData(path, txData);
                }
            }
            const prefixData = Buffer.concat([
                Waves.splitPath(path),
                Buffer.from([
                    amountPrecession,
                    WAVES_CONFIG.WAVES_PRECISION,
                ]),
            ]);
            const dataForSign = yield this._fillData(prefixData, txData, version2);
            return yield this._signData(dataForSign);
        });
    }
    signOrder(path, amountPrecession, txData) {
        return __awaiter(this, void 0, void 0, function* () {
            const prefixData = Buffer.concat([
                Waves.splitPath(path),
                Buffer.from([
                    amountPrecession,
                    WAVES_CONFIG.WAVES_PRECISION,
                    WAVES_CONFIG.SIGNED_CODES.ORDER,
                ])
            ]);
            const dataForSign = yield this._fillData(prefixData, txData);
            return yield this._signData(dataForSign);
        });
    }
    signSomeData(path, msgBuffer) {
        return __awaiter(this, void 0, void 0, function* () {
            const prefixData = Buffer.concat([
                Waves.splitPath(path),
                Buffer.from([
                    WAVES_CONFIG.WAVES_PRECISION,
                    WAVES_CONFIG.WAVES_PRECISION,
                    WAVES_CONFIG.SIGNED_CODES.SOME_DATA,
                ])
            ]);
            const dataForSign = yield this._fillData(prefixData, msgBuffer);
            return yield this._signData(dataForSign);
        });
    }
    signRequest(path, msgBuffer) {
        return __awaiter(this, void 0, void 0, function* () {
            const prefixData = Buffer.concat([
                Waves.splitPath(path),
                Buffer.from([
                    WAVES_CONFIG.WAVES_PRECISION,
                    WAVES_CONFIG.WAVES_PRECISION,
                    WAVES_CONFIG.SIGNED_CODES.REQUEST,
                ])
            ]);
            const dataForSign = yield this._fillData(prefixData, msgBuffer);
            return yield this._signData(dataForSign);
        });
    }
    signMessage(path, msgBuffer) {
        return __awaiter(this, void 0, void 0, function* () {
            const prefixData = Buffer.concat([
                Waves.splitPath(path),
                Buffer.from([
                    WAVES_CONFIG.WAVES_PRECISION,
                    WAVES_CONFIG.WAVES_PRECISION,
                    WAVES_CONFIG.SIGNED_CODES.MESSAGE,
                ])
            ]);
            const dataForSign = yield this._fillData(prefixData, msgBuffer);
            return yield this._signData(dataForSign);
        });
    }
    getVersion() {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this._version) {
                this._version = this.transport.send(0x80, 0x06, 0, 0);
            }
            try {
                const version = yield this._version;
                const isError = Waves.checkError(version.slice(-2));
                if (isError) {
                    throw isError;
                }
                return version.slice(0, -2);
            }
            catch (e) {
                this._version = null;
                throw e;
            }
        });
    }
    _versionNum() {
        return __awaiter(this, void 0, void 0, function* () {
            const version = yield this.getVersion();
            return WAVES_CONFIG.VERSIONS.reduce((acc, conf_version, index) => {
                const isMyVersion = !version.some((num, ind) => conf_version[ind] > num);
                return isMyVersion ? index : acc;
            }, 0);
        });
    }
    _fillData(prefixBuffer, dataBuffer, ver2 = [0]) {
        return __awaiter(this, void 0, void 0, function* () {
            const type = yield this._versionNum();
            switch (type) {
                case 0:
                    return Buffer.concat([prefixBuffer, dataBuffer]);
                case 1:
                default:
                    return Buffer.concat([prefixBuffer, Buffer.from(ver2), dataBuffer]);
            }
        });
    }
    _signData(dataBufferAsync) {
        return __awaiter(this, void 0, void 0, function* () {
            const dataBuffer = yield dataBufferAsync;
            const maxChunkLength = WAVES_CONFIG.MAX_SIZE - 5;
            const dataLength = dataBuffer.length;
            let sendBytes = 0;
            let result;
            while (dataLength > sendBytes) {
                const chunkLength = Math.min(dataLength - sendBytes, maxChunkLength);
                const isLastByte = (dataLength - sendBytes > maxChunkLength) ? 0x00 : 0x80;
                const chainId = isLastByte ? this.networkCode : 0x00;
                const txChunk = dataBuffer.slice(sendBytes, chunkLength + sendBytes);
                sendBytes += chunkLength;
                result = yield this.transport.send(0x80, 0x02, isLastByte, chainId, txChunk);
                const isError = Waves.checkError(result.slice(-2));
                if (isError) {
                    throw isError;
                }
            }
            return signature_generator_1.libs.base58.encode(result.slice(0, -2));
        });
    }
    static checkError(data) {
        const statusCode = data[0] * 256 + data[1];
        if (statusCode === WAVES_CONFIG.STATUS.SW_OK) {
            return null;
        }
        return { error: 'Wrong data', status: statusCode };
    }
    static splitPath(path) {
        const result = [];
        path.split('/').forEach(element => {
            let number = parseInt(element, 10);
            if (isNaN(number)) {
                return;
            }
            if (element.length > 1 && element[element.length - 1] === '\'') {
                number += 0x80000000;
            }
            result.push(number);
        });
        const buffer = new Buffer(result.length * 4);
        result.forEach((element, index) => {
            buffer.writeUInt32BE(element, 4 * index);
        });
        return buffer;
    }
}
exports.Waves = Waves;
//# sourceMappingURL=Waves.js.map