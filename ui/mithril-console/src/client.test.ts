import { afterEach, describe, expect, it, vi } from 'vitest';
import * as grpc from 'grpc-web';
import { Client, wire } from './client';
import { QueryRead, TraceRead } from './clientState';

const STORE = '11111111-1111-1111-1111-111111111111';
const TRACE = '22222222-2222-2222-2222-222222222222';
const DISCONNECTED = 'Http response at 400 or 500 level, http status code: 0';

function queryFrame(operation = wire.QueryOperation.QUERY_OPERATION_APPEND) {
  return new wire.QueryFrame().setSchemaVersion(1).setStoreUuid(Client.id(STORE)).setRecoveryEpoch('1')
    .setReadRevision('9007199254740993').setOperation(operation);
}

function metadata(operation = wire.QueryOperation.QUERY_OPERATION_APPEND) {
  return queryFrame(operation).setMetadata(new wire.QueryMetadata().setColumnsList([
    new wire.QueryColumn().setName('value').setDataType('BIGINT'),
  ]));
}

function row(value: string, ordinal = 0, operation = wire.QueryOperation.QUERY_OPERATION_APPEND) {
  return queryFrame(operation).setRows(new wire.QueryRows()
    .setRowsList([new wire.QueryRow().setValuesList([new wire.QueryValue().setSigned(value)])])
    .setPositionsList(operation === wire.QueryOperation.QUERY_OPERATION_APPEND
      ? [new wire.StorePosition().setCommitRevision('9007199254740993').setOrdinal(ordinal)] : []));
}

function checkpoint(operation = wire.QueryOperation.QUERY_OPERATION_APPEND) {
  return queryFrame(operation).setCheckpoint(new TextEncoder().encode('complete-bookmark'));
}

function traceFrame() {
  return new wire.TraceFrame().setSchemaVersion(1).setTraceId(Client.id(TRACE)).setStoreUuid(Client.id(STORE))
    .setRecoveryEpoch('1').setReadRevision('9').setCommitRevision('8').setOrdinal(0)
    .setExecutionId(Client.id(TRACE)).setSequence('1').setTargetIndex(0);
}

function traceMetadata() {
  return traceFrame().setMetadata(new wire.TraceDetail()
    .setReceipt(new wire.TraceReceipt().setTraceId(Client.id(TRACE)))
    .setTargetsList([new wire.TraceTarget().setIndex(0)]));
}

class Stream<T> {
  callbacks = new Map<string, ((value?: unknown) => void)[]>();
  cancel = vi.fn();
  on(name: string, callback: (value?: unknown) => void) {
    this.callbacks.set(name, [...(this.callbacks.get(name) ?? []), callback]); return this;
  }
  emit(name: string, value?: unknown) { this.callbacks.get(name)?.forEach((callback) => callback(value)); }
  transport() { return this as unknown as grpc.ClientReadableStream<T>; }
}

afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

describe('generated browser contract', () => {
  it('keeps 64-bit values and binary identities exact', () => {
    const frame = row('9223372036854775807');
    const decoded = wire.QueryFrame.deserializeBinary(frame.serializeBinary());
    expect(decoded.getReadRevision()).toBe('9007199254740993');
    expect(decoded.getRows()!.getRowsList()[0].getValuesList()[0].getSigned()).toBe('9223372036854775807');
    expect(Client.uuid(decoded.getStoreUuid_asU8())).toBe(STORE);
    const value = new wire.QueryValue().setUnsigned('18446744073709551615');
    expect(Client.value(wire.QueryValue.deserializeBinary(value.serializeBinary()))).toBe('18446744073709551615');
  });

  it('maps parameters without rounding or treating scripts as HTML', () => {
    const values = Client.parameters('[null,true,"<script>alert(1)</script>",{"signed":"9223372036854775807"}]');
    expect(values.map(Client.value)).toEqual(['NULL', 'true', '<script>alert(1)</script>', '9223372036854775807']);
    expect(() => Client.parameters('[9007199254740993]')).toThrow('large integers');
    expect(() => Client.parameters('[{"unsigned":"18446744073709551616"}]')).toThrow();
    expect(() => Client.parameters('{"sql":"SELECT 1"}')).toThrow('JSON array');
  });

  it('sends tenant metadata and the current browser CSRF token only for mutations', () => {
    vi.stubGlobal('document', { cookie: `araphor-csrf=${'a'.repeat(64)}` });
    const client = new Client(STORE, 'https://control.example');
    expect(client.metadata()).toEqual({ 'x-araphor-tenant': STORE });
    expect(client.metadata(true)).toEqual({ 'x-araphor-tenant': STORE, 'x-araphor-csrf': 'a'.repeat(64) });
    vi.stubGlobal('document', { cookie: '' });
    expect(() => client.metadata(true)).toThrow('Sign in');
    expect(() => new Client('', 'https://control.example').metadata()).toThrow('UUID');
  });
});

describe('complete frame application', () => {
  it('shows append rows before EOF only after their checkpoint and deduplicates replay', () => {
    const read = new QueryRead(true);
    read.receive(metadata()); read.receive(row('1'));
    expect(read.rows).toEqual([]);
    read.receive(checkpoint()); expect(read.rows).toEqual([['1']]);
    expect(read.terminal).toBe('');
    read.receive(row('2', 1)); read.reconnect();
    read.receive(metadata()); read.receive(row('1')); read.receive(checkpoint());
    expect(read.rows).toEqual([['1']]);
    read.receive(row('2', 1)); read.receive(checkpoint());
    expect(read.rows).toEqual([['1'], ['2']]);
    expect(read.positions[1].getCommitRevision()).toBe('9007199254740993');
  });

  it('replaces a moving aggregate atomically and keeps the last complete result on failure', () => {
    const operation = wire.QueryOperation.QUERY_OPERATION_REPLACE;
    const read = new QueryRead(true);
    read.receive(metadata(operation)); read.receive(row('2', 0, operation)); read.receive(checkpoint(operation));
    read.receive(row('1', 0, operation)); expect(read.rows).toEqual([['2']]);
    read.receive(checkpoint(operation)); expect(read.rows).toEqual([['1']]);
    const invalid = row('9', 0, operation);
    invalid.getRows()!.setLimited(true);
    read.receive(invalid);
    expect(() => read.receive(checkpoint(operation))).toThrow('truncated');
    expect(read.rows).toEqual([['1']]); read.reconnect();
    invalid.getRows()!.setLimited(false).getRowsList()[0].setValuesList([new wire.QueryValue()]);
    read.receive(invalid);
    expect(() => read.receive(checkpoint(operation))).toThrow('unknown SQL value');
    expect(read.rows).toEqual([['1']]);
  });

  it('rejects changed store epochs, incomplete batches and explicit replay gaps', () => {
    const read = new QueryRead(); read.receive(metadata());
    expect(() => read.receive(queryFrame().setRecoveryEpoch('2'))).toThrow('epoch');
    const changed = queryFrame().setStoreUuid(Client.id(TRACE));
    expect(() => read.receive(changed)).toThrow('store');
    const missing = row('1'); missing.getRows()!.clearPositionsList();
    expect(() => read.receive(missing)).toThrow('positions');
    expect(() => read.receive(queryFrame().setError(new wire.QueryError().setCode('CursorExpired').setReason('Retained history expired.')))).toThrow('CursorExpired');
  });

  it('requires a global trace result in addition to each target terminal and checkpoint', () => {
    const read = new TraceRead(TRACE); read.receive(traceMetadata());
    const output = traceFrame().setOutput(new wire.TraceOutput().setKind('stdout').setBytes(new TextEncoder().encode('<script>not HTML</script>')));
    read.receive(output); expect(read.output).toBe('');
    const point = traceFrame().setCheckpoint(new wire.TraceCheckpoint()).setBookmark(new TextEncoder().encode('trace-bookmark'));
    read.receive(point); expect(read.output).toContain('<script>not HTML</script>');
    const first = read.output;
    read.reconnect(); read.receive(output); read.receive(point); expect(read.output).toBe(first);
    read.receive(traceFrame().setOrdinal(1).setTerminal(new wire.TraceTerminal().setReason('Completed').setCleanup('Verified')));
    read.receive(point); expect(read.terminals.size).toBe(1); expect(read.result).toBeUndefined();
    read.receive(traceFrame().setResult(new wire.TraceResult().setComplete(true).setCleanupComplete(true)));
    expect(read.result?.getComplete()).toBe(true);
    expect(() => read.receive(traceFrame().setTraceId(Client.id(STORE)))).toThrow('trace');
  });
});

describe('browser stream lifetime', () => {
  it('completes a one-shot read only after its final record', () => {
    const stream = new Stream<wire.QueryFrame>(); const open = vi.fn(() => stream.transport());
    const read = new QueryRead(false); const state = vi.fn(); const stop = new AbortController();
    Client.read(open, (frame: wire.QueryFrame) => read.receive(frame), () => Boolean(read.terminal), () => read.reconnect(), stop.signal, state);
    stream.emit('data', metadata()); stream.emit('data', row('1')); stream.emit('data', checkpoint());
    stream.emit('data', queryFrame().setTerminal(new wire.QueryTerminal().setReason('Completed')));
    stream.emit('end');
    expect(open).toHaveBeenCalledOnce(); expect(read.rows).toEqual([['1']]);
    expect(state).toHaveBeenLastCalledWith('Read ended with an explicit final record.');
    stop.abort();
  });

  it.each([
    { event: 'end', error: undefined },
    { event: 'error', error: { code: grpc.StatusCode.UNAVAILABLE, message: 'offline', metadata: {} } },
    { event: 'error', error: { code: grpc.StatusCode.UNKNOWN, message: DISCONNECTED, metadata: {} } },
  ])('keeps a one-shot read partial after $event without resuming its bookmark', ({ event, error }) => {
    vi.useFakeTimers();
    for (const operation of [wire.QueryOperation.QUERY_OPERATION_APPEND, wire.QueryOperation.QUERY_OPERATION_REPLACE]) {
      const stream = new Stream<wire.QueryFrame>(); const open = vi.fn(() => stream.transport());
      const read = new QueryRead(false); const state = vi.fn(); const stop = new AbortController();
      Client.read(open, (frame: wire.QueryFrame) => read.receive(frame), () => Boolean(read.terminal), () => read.reconnect(), stop.signal, state);
      stream.emit('data', metadata(operation)); stream.emit('data', row('1', 0, operation)); stream.emit('data', checkpoint(operation));
      stream.emit(event, error); vi.advanceTimersByTime(10000);
      expect(open).toHaveBeenCalledOnce(); expect(read.rows).toEqual([['1']]);
      expect(read.bookmark).not.toBe(''); expect(read.terminal).toBe('');
      expect(state).toHaveBeenLastCalledWith(expect.stringContaining('Partial read:'));
      stop.abort();
    }
  });

  it('cancels reads and ignores old-scope frames without a capture cancellation call', () => {
    const stream = new Stream<wire.QueryFrame>();
    const stop = new AbortController(); const receive = vi.fn(); const state = vi.fn();
    Client.read(() => stream.transport(), receive, () => false, vi.fn(() => true), stop.signal, state);
    stream.emit('data', metadata()); expect(receive).toHaveBeenCalledTimes(1);
    stop.abort(); stream.emit('data', row('2')); stream.emit('end');
    expect(receive).toHaveBeenCalledTimes(1); expect(stream.cancel).toHaveBeenCalledOnce();
  });

  it.each([
    { code: grpc.StatusCode.UNAVAILABLE, message: 'offline', metadata: {} },
    { code: grpc.StatusCode.UNKNOWN, message: DISCONNECTED, metadata: {} },
  ])('reconnects code $code from the last complete bookmark and discards partial output', (error) => {
    vi.useFakeTimers();
    const first = new Stream<wire.QueryFrame>(); const next = new Stream<wire.QueryFrame>();
    const read = new QueryRead(true); const open = vi.fn().mockReturnValueOnce(first.transport()).mockReturnValue(next.transport());
    const stop = new AbortController();
    Client.read(open, (frame: wire.QueryFrame) => read.receive(frame), () => Boolean(read.terminal), () => read.reconnect(), stop.signal, vi.fn());
    first.emit('data', metadata()); first.emit('data', row('1')); first.emit('data', checkpoint());
    const saved = read.bookmark;
    first.emit('data', row('2', 1)); first.emit('error', error);
    first.emit('data', checkpoint()); expect(read.rows).toEqual([['1']]);
    vi.advanceTimersByTime(1000); expect(open).toHaveBeenCalledTimes(2); expect(read.bookmark).toBe(saved);
    next.emit('data', metadata()); next.emit('data', row('2', 1)); next.emit('data', checkpoint());
    expect(read.rows).toEqual([['1'], ['2']]); stop.abort();
  });

  it.each([
    { code: grpc.StatusCode.UNKNOWN, message: 'Application read failed.', metadata: {} },
    { code: grpc.StatusCode.UNKNOWN, message: 'Http response at 400 or 500 level, http status code: 401', metadata: {} },
    { code: grpc.StatusCode.UNKNOWN, message: DISCONNECTED, metadata: { 'grpc-status': '2' } },
    { code: grpc.StatusCode.UNAUTHENTICATED, message: 'expired', metadata: {} },
    { code: grpc.StatusCode.PERMISSION_DENIED, message: 'revoked', metadata: {} },
    { code: grpc.StatusCode.OUT_OF_RANGE, message: 'retained history expired', metadata: {} },
  ])('does not reconnect code $code: $message', (error) => {
    vi.useFakeTimers();
    const stream = new Stream<wire.QueryFrame>(); const open = vi.fn(() => stream.transport());
    const receive = vi.fn(); const state = vi.fn(); const stop = new AbortController();
    Client.read(open, receive, () => false, vi.fn(() => true), stop.signal, state);
    stream.emit('error', error);
    stream.emit('data', metadata()); vi.advanceTimersByTime(10000);
    expect(open).toHaveBeenCalledOnce(); expect(receive).not.toHaveBeenCalled();
    expect(state).toHaveBeenLastCalledWith(`Partial read: ${Client.error(error)}`);
    expect(Client.error({ code: grpc.StatusCode.OUT_OF_RANGE })).toContain('Replay gap');
    stop.abort();
  });

  it.each(['end', 'error'])('stops after three retries without treating %s as success', (event) => {
    vi.useFakeTimers();
    const streams = Array.from({ length: 4 }, () => new Stream<wire.TraceFrame>());
    let index = 0; const state = vi.fn(); const stop = new AbortController();
    Client.read(() => streams[index++].transport(), vi.fn(), () => false, vi.fn(() => true), stop.signal, state);
    const error = { code: grpc.StatusCode.UNKNOWN, message: DISCONNECTED, metadata: {} };
    streams[0].emit(event, error); vi.advanceTimersByTime(1000);
    streams[1].emit(event, error); vi.advanceTimersByTime(2000);
    streams[2].emit(event, error); vi.advanceTimersByTime(3000);
    streams[3].emit(event, error);
    expect(state).toHaveBeenLastCalledWith(expect.stringContaining(event === 'end' ? 'without a final result' : DISCONNECTED));
    expect(index).toBe(4); stop.abort();
  });
});
