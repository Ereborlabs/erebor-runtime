import * as grpc from 'grpc-web';
import { AraphorAdministrativeServiceClient, AraphorClientServiceClient } from './generated/ClientServiceClientPb';
import * as wire from './generated/client_pb';

export { wire };

export class Client {
  readonly rpc: AraphorClientServiceClient;
  readonly admin: AraphorAdministrativeServiceClient;

  constructor(readonly tenant = '', origin = window.location.origin) {
    this.rpc = new AraphorClientServiceClient(origin, null, { withCredentials: true });
    this.admin = new AraphorAdministrativeServiceClient(origin, null, { withCredentials: true });
  }

  metadata(mutation = false): grpc.Metadata {
    Client.id(this.tenant);
    const headers: grpc.Metadata = { 'x-araphor-tenant': this.tenant };
    if (mutation) headers['x-araphor-csrf'] = Client.cookie('araphor-csrf');
    return headers;
  }

  submit(request: wire.SubmitTraceRequest, signal: AbortSignal) {
    return Client.unary<wire.TraceReceipt>((callback) => this.rpc.submitTrace(request, this.metadata(true), callback), signal);
  }

  detail(id: Uint8Array, signal: AbortSignal) {
    return Client.unary<wire.TraceDetail>((callback) => this.rpc.getTrace(new wire.GetTraceRequest().setTraceId(id), this.metadata(), callback), signal);
  }

  cancel(id: Uint8Array, signal: AbortSignal) {
    return Client.unary<wire.CancelTraceReceipt>((callback) => this.rpc.cancelTrace(new wire.CancelTraceRequest().setTraceId(id), this.metadata(true), callback), signal);
  }

  activation(token: string, signal: AbortSignal) {
    return Client.unary<wire.AdministrativeExecActivation>((callback) => this.admin.getAdministrativeExecActivation(
      new wire.GetAdministrativeExecActivationRequest().setActivationToken(token), {}, callback,
    ), signal);
  }

  approve(token: string, signal: AbortSignal) {
    return Client.unary<wire.AdministrativeExecApproval>((callback) => this.admin.approveAdministrativeExec(
      new wire.ApproveAdministrativeExecRequest().setActivationToken(token),
      { 'x-araphor-csrf': Client.cookie('araphor-approval-csrf') }, callback,
    ), signal);
  }

  static unary<T>(open: (callback: (error: grpc.RpcError, value: T) => void) => grpc.ClientReadableStream<T>, signal: AbortSignal): Promise<T> {
    return new Promise((resolve, reject) => {
      if (signal.aborted) { reject(new DOMException('Read stopped', 'AbortError')); return; }
      let stream: grpc.ClientReadableStream<T> | undefined;
      const abort = () => { stream?.cancel(); reject(new DOMException('Read stopped', 'AbortError')); };
      signal.addEventListener('abort', abort, { once: true });
      try {
        stream = open((error, value) => {
          signal.removeEventListener('abort', abort);
          if (signal.aborted) return;
          if (error) reject(error); else resolve(value);
        });
      } catch (error) {
        signal.removeEventListener('abort', abort);
        reject(error);
      }
    });
  }

  static cookie(name: string): string {
    const values = document.cookie.split(';').map((value) => value.trim().split('='))
      .filter(([key]) => key === name);
    if (values.length !== 1 || !/^[0-9a-f]{64}$/.test(values[0][1])) {
      throw new Error('Sign in again before this operation.');
    }
    return values[0][1];
  }

  static id(value: string): Uint8Array {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) || /^0+-0+-0+-0+-0+$/.test(value)) {
      throw new Error('Enter a nonzero canonical UUID.');
    }
    return Uint8Array.from(value.replaceAll('-', '').match(/../g)!, (byte) => parseInt(byte, 16));
  }

  static hex(value: Uint8Array): string {
    return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  static uuid(value: Uint8Array): string {
    const hex = Client.hex(value);
    if (value.length !== 16) throw new Error('The server returned an invalid identity.');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  static value(value: wire.QueryValue): string {
    switch (value.getKindCase()) {
      case wire.QueryValue.KindCase.NULL: return 'NULL';
      case wire.QueryValue.KindCase.BOOLEAN: return String(value.getBoolean());
      case wire.QueryValue.KindCase.SIGNED: return value.getSigned();
      case wire.QueryValue.KindCase.UNSIGNED: return value.getUnsigned();
      case wire.QueryValue.KindCase.REAL: return String(value.getReal());
      case wire.QueryValue.KindCase.TEXT: return value.getText();
      case wire.QueryValue.KindCase.BINARY: return `0x${Client.hex(value.getBinary_asU8())}`;
      case wire.QueryValue.KindCase.INTEGER128: return value.getInteger128();
      case wire.QueryValue.KindCase.UNSIGNED128: return value.getUnsigned128();
      case wire.QueryValue.KindCase.DECIMAL: {
        const number = value.getDecimal()!;
        return `${number.getUnscaled()} × 10^-${number.getScale()} (decimal ${number.getWidth()})`;
      }
      case wire.QueryValue.KindCase.TIMESTAMP: return `${value.getTimestamp()!.getValue()} ${value.getTimestamp()!.getUnit()} since epoch`;
      case wire.QueryValue.KindCase.TIME: return `${value.getTime()!.getValue()} ${value.getTime()!.getUnit()} since midnight`;
      case wire.QueryValue.KindCase.DATE: return `${value.getDate()} days since epoch`;
      case wire.QueryValue.KindCase.INTERVAL: {
        const interval = value.getInterval()!;
        return `${interval.getMonths()} months ${interval.getDays()} days ${interval.getNanoseconds()} ns`;
      }
      default: throw new Error('The server returned an unknown SQL value.');
    }
  }

  static parameters(text: string): wire.QueryValue[] {
    const values: unknown = JSON.parse(text);
    if (!Array.isArray(values) || values.length > 128) throw new Error('Parameters must be a JSON array with at most 128 values.');
    return values.map((value) => {
      const result = new wire.QueryValue();
      if (value === null) return result.setNull(true);
      if (typeof value === 'string') return result.setText(value);
      if (typeof value === 'boolean') return result.setBoolean(value);
      if (typeof value === 'number' && Number.isFinite(value)) {
        if (Number.isInteger(value)) {
          if (!Number.isSafeInteger(value)) throw new Error('Use a signed or unsigned string for large integers.');
          return result.setSigned(String(value));
        }
        return result.setReal(value);
      }
      if (value && typeof value === 'object' && Object.keys(value).length === 1) {
        const [kind, number] = Object.entries(value)[0];
        if (typeof number === 'string' && /^-?(0|[1-9][0-9]*)$/.test(number)) {
          const parsed = BigInt(number);
          if (kind === 'signed' && parsed >= -(1n << 63n) && parsed < 1n << 63n) return result.setSigned(number);
          if (kind === 'unsigned' && parsed >= 0n && parsed < 1n << 64n) return result.setUnsigned(number);
        }
      }
      throw new Error('Use JSON strings, booleans, null, numbers, or {"signed":"..."}/{"unsigned":"..."}.');
    });
  }

  static error(error: unknown): string {
    if (error && typeof error === 'object' && 'code' in error) {
      const code = Number(error.code);
      if (code === grpc.StatusCode.OUT_OF_RANGE) return 'Replay gap: retained history is no longer available. Start a new read.';
      if (code === grpc.StatusCode.UNAUTHENTICATED || code === grpc.StatusCode.PERMISSION_DENIED) return 'Access ended. Sign in with current tenant permission.';
      if ('message' in error) return `${grpc.StatusCode[code] ?? code}: ${String(error.message)}`;
    }
    return error instanceof Error ? error.message : String(error);
  }

  static read<T>(open: () => grpc.ClientReadableStream<T>, receive: (frame: T) => void, complete: () => boolean,
    reconnect: () => boolean, signal: AbortSignal, state: (text: string) => void): void {
    let stream: grpc.ClientReadableStream<T> | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let attempts = 0;
    let generation = 0;
    let stopped = false;
    const stop = () => {
      stopped = true; generation += 1;
      clearTimeout(timer); stream?.cancel();
    };
    const start = () => {
      if (signal.aborted || stopped) return;
      const current = ++generation;
      let ended = false;
      const finish = (error?: grpc.RpcError) => {
        if (ended || stopped || signal.aborted || current !== generation) return;
        ended = true;
        if (complete() && !error) { state('Read ended with an explicit final record.'); return; }
        const disconnected = error?.code === grpc.StatusCode.UNKNOWN
          && error.message === 'Http response at 400 or 500 level, http status code: 0'
          && Object.keys(error.metadata ?? {}).length === 0;
        if ((!error || error.code === grpc.StatusCode.UNAVAILABLE || disconnected) && attempts < 3 && reconnect()) {
          attempts += 1;
          state(`Disconnected. Resume ${attempts}/3 from the last complete checkpoint.`);
          timer = setTimeout(start, 1000 * attempts);
        } else {
          state(`Partial read: ${error ? Client.error(error) : 'The stream ended without a final result.'}`);
        }
      };
      try {
        state(attempts ? 'Resuming read…' : 'Connecting…');
        stream = open();
        stream.on('data', (frame) => {
          if (ended || stopped || signal.aborted || current !== generation) return;
          try { receive(frame); }
          catch (error) { stop(); state(`Partial read: ${Client.error(error)}`); }
        });
        stream.on('error', (error) => finish(error));
        stream.on('end', () => finish());
      } catch (error) { stop(); state(Client.error(error)); }
    };
    signal.addEventListener('abort', stop, { once: true });
    start();
  }
}
