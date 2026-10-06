import { Client, wire } from './client';

const ROW_LIMIT = 2000;
const TEXT_LIMIT = 1024 * 1024;

export class QueryRead {
  metadata?: wire.QueryMetadata;
  coverage: wire.QueryCoverage[] = [];
  health?: wire.QueryHealth;
  rows: string[][] = [];
  positions: wire.StorePosition[] = [];
  bookmark = '';
  store = '';
  epoch = '';
  revision = '';
  operation = wire.QueryOperation.QUERY_OPERATION_UNSPECIFIED;
  terminal = '';
  limited = false;
  clipped = false;
  missing: wire.ContextKey[] = [];
  private pending?: wire.QueryRows;
  private bytes = 0;

  constructor(readonly follow = false) {}

  receive(frame: wire.QueryFrame): void {
    const store = Client.uuid(frame.getStoreUuid_asU8());
    if (frame.getSchemaVersion() !== 1 || (this.store && (this.store !== store || this.epoch !== frame.getRecoveryEpoch()))) {
      throw new Error('The store or recovery epoch changed. Start a new read.');
    }
    if (![wire.QueryOperation.QUERY_OPERATION_APPEND, wire.QueryOperation.QUERY_OPERATION_REPLACE].includes(frame.getOperation())) {
      throw new Error('The query operation is unknown.');
    }
    if (this.operation && this.operation !== frame.getOperation()) throw new Error('The query operation changed.');
    this.store = store; this.epoch = frame.getRecoveryEpoch(); this.revision = frame.getReadRevision();
    this.operation = frame.getOperation();
    this.coverage = frame.getCoverageList();
    switch (frame.getPayloadCase()) {
      case wire.QueryFrame.PayloadCase.METADATA:
        this.metadata = frame.getMetadata();
        break;
      case wire.QueryFrame.PayloadCase.ROWS: {
        const rows = frame.getRows()!;
        if (!this.metadata || this.pending || rows.getRowsList().length > 200
          || rows.getRowsList().some((row) => row.getValuesList().length !== this.metadata!.getColumnsList().length)) {
          throw new Error('The query row batch is incomplete or invalid.');
        }
        if (this.operation === wire.QueryOperation.QUERY_OPERATION_APPEND
          && rows.getPositionsList().length !== rows.getRowsList().length) {
          throw new Error('Append rows have no exact replay positions.');
        }
        this.pending = rows;
        break;
      }
      case wire.QueryFrame.PayloadCase.CHECKPOINT:
        if (!frame.getCheckpoint_asU8().length) throw new Error('The checkpoint is absent.');
        this.commit();
        this.bookmark = frame.getCheckpoint_asB64();
        break;
      case wire.QueryFrame.PayloadCase.HEALTH:
        this.health = frame.getHealth();
        break;
      case wire.QueryFrame.PayloadCase.ERROR:
        this.pending = undefined;
        throw new Error(`${frame.getError()!.getCode()}: ${frame.getError()!.getReason()}`);
      case wire.QueryFrame.PayloadCase.TERMINAL:
        if (this.pending) throw new Error('The query ended before its complete checkpoint.');
        this.terminal = frame.getTerminal()!.getReason();
        if (this.terminal !== 'Completed' && this.terminal !== 'Cancelled') throw new Error(`The query ended: ${this.terminal}`);
        break;
      default: throw new Error('The query frame is unknown.');
    }
  }

  private commit(): void {
    if (!this.pending) return;
    const rows = this.pending;
    const values = rows.getRowsList().map((row) => row.getValuesList().map(Client.value));
    const positions = rows.getPositionsList();
    for (let index = 1; index < positions.length; index += 1) {
      if (QueryRead.compare(positions[index], positions[index - 1]) <= 0) throw new Error('Append positions are not ordered.');
    }
    if (this.operation === wire.QueryOperation.QUERY_OPERATION_REPLACE) {
      if (this.follow && rows.getLimited()) throw new Error('A replacement was truncated; the previous result remains visible.');
      this.rows = []; this.positions = []; this.bytes = 0; this.clipped = false;
    }
    values.forEach((row, index) => {
      const position = positions[index];
      if (position) {
        const last = this.positions.at(-1);
        if (last && QueryRead.compare(position, last) <= 0) return;
      }
      this.rows.push(row);
      if (position) this.positions.push(position);
      this.bytes += row.reduce((sum, value) => sum + value.length, 0);
      while (this.rows.length > ROW_LIMIT || this.bytes > TEXT_LIMIT) {
        this.bytes -= this.rows.shift()!.reduce((sum, value) => sum + value.length, 0);
        if (this.positions.length) this.positions.shift();
        this.clipped = true;
      }
    });
    this.limited = rows.getLimited(); this.missing = rows.getMissingContextsList();
    this.pending = undefined;
  }

  reconnect(): void { this.pending = undefined; this.terminal = ''; }

  static compare(left: wire.StorePosition, right: wire.StorePosition): number {
    const a = BigInt(left.getCommitRevision());
    const b = BigInt(right.getCommitRevision());
    return a < b ? -1 : a > b ? 1 : left.getOrdinal() - right.getOrdinal();
  }
}

export class TraceRead {
  detail?: wire.TraceDetail;
  result?: wire.TraceResult;
  coverage: wire.QueryCoverage[] = [];
  health?: wire.QueryHealth;
  terminals = new Map<number, wire.TraceTerminal>();
  output = '';
  clipped = false;
  bookmark = '';
  store = '';
  epoch = '';
  revision = '';
  private pending: wire.TraceFrame[] = [];
  private bytes = 0;
  private position?: wire.StorePosition;

  constructor(readonly id: string) { Client.id(id); }

  receive(frame: wire.TraceFrame): void {
    const store = Client.uuid(frame.getStoreUuid_asU8());
    if (frame.getSchemaVersion() !== 1 || Client.uuid(frame.getTraceId_asU8()) !== this.id
      || (this.store && (this.store !== store || this.epoch !== frame.getRecoveryEpoch()))) {
      throw new Error('The trace, store or recovery epoch changed. Start a new read.');
    }
    this.store = store; this.epoch = frame.getRecoveryEpoch(); this.revision = frame.getReadRevision();
    this.coverage = frame.getCoverageList();
    switch (frame.getPayloadCase()) {
      case wire.TraceFrame.PayloadCase.METADATA: {
        const detail = frame.getMetadata()!;
        if (!detail.getReceipt() || Client.uuid(detail.getReceipt()!.getTraceId_asU8()) !== this.id) throw new Error('Trace metadata names another trace.');
        this.detail = detail;
        break;
      }
      case wire.TraceFrame.PayloadCase.OUTPUT:
      case wire.TraceFrame.PayloadCase.TERMINAL:
        if (!this.detail || frame.getTargetIndex() >= this.detail.getTargetsList().length) throw new Error('Trace output names an unknown target.');
        this.bytes += frame.getOutput()?.getBytes_asU8().length ?? 0;
        if (this.pending.length >= 200 || this.bytes > TEXT_LIMIT) throw new Error('The trace page exceeds the browser input limit.');
        this.pending.push(frame);
        break;
      case wire.TraceFrame.PayloadCase.CHECKPOINT:
        if (!frame.getBookmark_asU8().length) throw new Error('The trace checkpoint is absent.');
        this.commit();
        this.bookmark = frame.getBookmark_asB64();
        break;
      case wire.TraceFrame.PayloadCase.HEALTH:
        this.health = frame.getHealth();
        break;
      case wire.TraceFrame.PayloadCase.ERROR:
        this.reconnect();
        throw new Error(`${frame.getError()!.getCode()}: ${frame.getError()!.getReason()}`);
      case wire.TraceFrame.PayloadCase.RESULT:
        if (this.pending.length) throw new Error('The trace ended before its complete checkpoint.');
        this.result = frame.getResult();
        break;
      default: throw new Error('The trace frame is unknown.');
    }
  }

  private commit(): void {
    for (let index = 1; index < this.pending.length; index += 1) {
      const left = this.pending[index - 1];
      const right = this.pending[index];
      if (QueryRead.compare(new wire.StorePosition().setCommitRevision(left.getCommitRevision()).setOrdinal(left.getOrdinal()),
        new wire.StorePosition().setCommitRevision(right.getCommitRevision()).setOrdinal(right.getOrdinal())) >= 0) {
        throw new Error('Trace positions are not ordered.');
      }
    }
    for (const frame of this.pending) {
      const position = new wire.StorePosition().setCommitRevision(frame.getCommitRevision()).setOrdinal(frame.getOrdinal());
      if (this.position && QueryRead.compare(position, this.position) <= 0) continue;
      const output = frame.getOutput();
      if (output) {
        this.output += `[target ${frame.getTargetIndex()}, execution ${Client.uuid(frame.getExecutionId_asU8())}, sequence ${frame.getSequence()}, ${output.getKind()}]\n${new TextDecoder().decode(output.getBytes_asU8())}\n`;
        if (this.output.length > TEXT_LIMIT) { this.output = this.output.slice(-TEXT_LIMIT); this.clipped = true; }
      }
      const terminal = frame.getTerminal();
      if (terminal) this.terminals.set(frame.getTargetIndex(), terminal);
      this.position = position;
    }
    this.pending = []; this.bytes = 0;
  }

  reconnect(): void { this.pending = []; this.bytes = 0; this.result = undefined; }
}
