/// <reference path="../interface.d.ts" />
import { Waves, IUserData } from './Waves';
export declare class WavesLedger {
    ready: boolean;
    private _wavesLibPromise;
    private _initTransportPromise;
    private _debug;
    private _openTimeout;
    private _listenTimeout;
    private _exchangeTimeout;
    private _networkCode;
    private _error;
    private _transport;
    constructor(options: IWavesLedger);
    tryConnect(): Promise<void>;
    disconnect(): Promise<void>;
    getTransport(): Promise<any>;
    getUserDataById(id: number): Promise<IUser>;
    getVersion(): Promise<Array<number>>;
    getPaginationUsersData(from: number, limit: number): Promise<Array<IUser>>;
    signTransaction(userId: number, asset: {
        precision: number;
    }, txData: Uint8Array, version?: number): Promise<any>;
    signOrder(userId: number, asset: {
        precision: number;
    }, txData: Uint8Array): Promise<any>;
    signSomeData(userId: number, dataBuffer: Uint8Array): Promise<any>;
    signRequest(userId: number, dataBuffer: Uint8Array): Promise<any>;
    signMessage(userId: number, message: string): Promise<any>;
    getLastError(): any;
    probeDevice(): Promise<boolean>;
    getPathById(id: number): string;
    _setSettings(): void;
    _initU2FTransport(): Promise<any> | null;
    _initWavesLib(): Promise<Waves>;
}
interface IWavesLedger {
    debug?: boolean;
    openTimeout?: number;
    listenTimeout?: number;
    exchangeTimeout?: number;
    networkCode?: number;
    transport?: any;
}
interface IUser extends IUserData {
    id: number;
    path: string;
}
export {};
