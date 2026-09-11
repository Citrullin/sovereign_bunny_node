// Account-Scoped Folder Storage Manager for Sovereign Account-Lattice
// Organizes state per account address: accounts/<address>/{keys,contracts,zanzibar,traces}

export interface AccountKeyStorage {
    pqPrivateKey?: string;
    pqPublicKey?: string;
    didDocument?: string;
    keyTier?: string;
    allowLegacy?: boolean;
}

export interface CustomContractEntry {
    name: string;
    targetAddress: string;
    abi: any[];
    uploadedAt: number;
}

export interface ZanzibarScopedTuple {
    namespace: number;
    objectId: string;
    relation: number;
    subject: string;
    timestamp: number;
}

export interface DebugTraceEntry {
    id: string;
    timestamp: number;
    input: string;
    targetAddress?: string;
    mode?: string;
    functionName?: string;
    status: 'success' | 'reverted' | 'error';
    summary: string;
}

export interface StorageBackend {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
    removeItem(key: string): void;
    getAllKeys(): string[];
}

export class MemoryStorageBackend implements StorageBackend {
    private store: Map<string, string> = new Map();

    getItem(key: string): string | null {
        return this.store.get(key) || null;
    }
    setItem(key: string, value: string): void {
        this.store.set(key, value);
    }
    removeItem(key: string): void {
        this.store.delete(key);
    }
    getAllKeys(): string[] {
        return Array.from(this.store.keys());
    }
}

export class BrowserLocalStorageBackend implements StorageBackend {
    getItem(key: string): string | null {
        try {
            return typeof localStorage !== 'undefined' ? localStorage.getItem(key) : null;
        } catch (_) {
            return null;
        }
    }
    setItem(key: string, value: string): void {
        try {
            if (typeof localStorage !== 'undefined') localStorage.setItem(key, value);
        } catch (_) {}
    }
    removeItem(key: string): void {
        try {
            if (typeof localStorage !== 'undefined') localStorage.removeItem(key);
        } catch (_) {}
    }
    getAllKeys(): string[] {
        try {
            return typeof localStorage !== 'undefined' ? Object.keys(localStorage) : [];
        } catch (_) {
            return [];
        }
    }
}

export class AccountScopedStorage {
    public readonly address: string;
    private readonly manager: AccountStorageManager;

    constructor(address: string, manager: AccountStorageManager) {
        this.address = address.toLowerCase();
        this.manager = manager;
    }

    // Keys category
    getKeys(): AccountKeyStorage {
        return this.manager.getAccountKeys(this.address);
    }
    saveKeys(keys: Partial<AccountKeyStorage>): void {
        this.manager.saveAccountKeys(this.address, keys);
    }

    // Contracts category
    getCustomContracts(): CustomContractEntry[] {
        return this.manager.getCustomContracts(this.address);
    }
    saveCustomContract(contract: CustomContractEntry): void {
        this.manager.saveCustomContract(this.address, contract);
    }

    // Zanzibar category
    getZanzibarTuples(): ZanzibarScopedTuple[] {
        return this.manager.getZanzibarTuples(this.address);
    }
    saveZanzibarTuple(tuple: ZanzibarScopedTuple): void {
        this.manager.saveZanzibarTuple(this.address, tuple);
    }

    // Traces category
    getDebugTraces(): DebugTraceEntry[] {
        return this.manager.getDebugTraces(this.address);
    }
    saveDebugTrace(trace: DebugTraceEntry): void {
        this.manager.saveDebugTrace(this.address, trace);
    }
}

export class AccountStorageManager {
    private backend: StorageBackend;

    constructor(backend?: StorageBackend) {
        if (backend) {
            this.backend = backend;
        } else if (typeof localStorage !== 'undefined') {
            this.backend = new BrowserLocalStorageBackend();
        } else {
            this.backend = new MemoryStorageBackend();
        }
    }

    private _key(address: string, category: string, subkey?: string): string {
        const normAddr = address.toLowerCase();
        return subkey 
            ? `accounts/${normAddr}/${category}/${subkey}`
            : `accounts/${normAddr}/${category}`;
    }

    public forAccount(address: string): AccountScopedStorage {
        return new AccountScopedStorage(address, this);
    }

    public listAccounts(): string[] {
        const keys = this.backend.getAllKeys();
        const accounts = new Set<string>();
        for (const k of keys) {
            if (k.startsWith('accounts/')) {
                const parts = k.split('/');
                if (parts[1]) accounts.add(parts[1]);
            }
        }
        return Array.from(accounts);
    }

    // Keys
    public getAccountKeys(address: string): AccountKeyStorage {
        const raw = this.backend.getItem(this._key(address, 'keys'));
        if (!raw) return {};
        try {
            return JSON.parse(raw);
        } catch (_) {
            return {};
        }
    }

    public saveAccountKeys(address: string, updates: Partial<AccountKeyStorage>): void {
        const current = this.getAccountKeys(address);
        const merged = { ...current, ...updates };
        this.backend.setItem(this._key(address, 'keys'), JSON.stringify(merged));
    }

    // Custom Contracts
    public getCustomContracts(address: string): CustomContractEntry[] {
        const raw = this.backend.getItem(this._key(address, 'contracts'));
        if (!raw) return [];
        try {
            return JSON.parse(raw);
        } catch (_) {
            return [];
        }
    }

    public saveCustomContract(address: string, contract: CustomContractEntry): void {
        const contracts = this.getCustomContracts(address);
        const idx = contracts.findIndex(c => 
            c.targetAddress.toLowerCase() === contract.targetAddress.toLowerCase() || 
            c.name.toLowerCase() === contract.name.toLowerCase()
        );
        if (idx >= 0) {
            contracts[idx] = contract;
        } else {
            contracts.push(contract);
        }
        this.backend.setItem(this._key(address, 'contracts'), JSON.stringify(contracts));
    }

    // Zanzibar
    public getZanzibarTuples(address: string): ZanzibarScopedTuple[] {
        const raw = this.backend.getItem(this._key(address, 'zanzibar', 'tuples'));
        if (!raw) return [];
        try {
            return JSON.parse(raw);
        } catch (_) {
            return [];
        }
    }

    public saveZanzibarTuple(address: string, tuple: ZanzibarScopedTuple): void {
        const tuples = this.getZanzibarTuples(address);
        tuples.push(tuple);
        this.backend.setItem(this._key(address, 'zanzibar', 'tuples'), JSON.stringify(tuples));
    }

    // Debug Traces
    public getDebugTraces(address: string): DebugTraceEntry[] {
        const raw = this.backend.getItem(this._key(address, 'traces'));
        if (!raw) return [];
        try {
            return JSON.parse(raw);
        } catch (_) {
            return [];
        }
    }

    public saveDebugTrace(address: string, trace: DebugTraceEntry): void {
        const traces = this.getDebugTraces(address);
        traces.unshift(trace);
        if (traces.length > 50) traces.length = 50; // Keep last 50
        this.backend.setItem(this._key(address, 'traces'), JSON.stringify(traces));
    }
}
