// TOONFLOW_CHECKOUT=/path/to/Toonflow-app node --test integrations/toonflow/test-provider.cjs
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const root = process.env.TOONFLOW_CHECKOUT;
if (!root) throw new Error('Set TOONFLOW_CHECKOUT to an installed Toonflow-app checkout');
const localRequire = createRequire(path.join(root, 'package.json'));
const { transform } = localRequire('sucrase');
const { VM } = localRequire('vm2');
function load(file, mocks = {}) {
  const exports = {};
  const code = transform(fs.readFileSync(path.join(__dirname, file), 'utf8'), { transforms: ['typescript', 'imports'] }).code;
  vm.runInNewContext(code, { exports, process, Buffer, setInterval, clearInterval, setTimeout,
    require: name => name in mocks ? mocks[name] : localRequire(name) });
  return exports;
}
const { LocalQueue, normalize } = load('vgenLocal.ts');
const model = { modelName: 'h3-8step' };
const input = { prompt: 'A sea', duration: 1.625, resolution: '768p', aspectRatio: '16:9',
  mode: 'text', audio: true, referenceList: [], vgenRequestId: 'instance:video:1',
  vgenContext: { instance_id: 'instance', project_id: 1, script_id: 2, video_id: 3 } };
function fixture(t, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vgen-cli-test-'));
  const calls = [];
  const runner = async args => {
    calls.push(args);
    if (args[0] === 'preflight') return { state: options.preflight || 'ready' };
    if (args[0] === 'submit') {
      if (options.unknown) throw new Error('lost response');
      return { id: 'tsk_test123' };
    }
    if (args[0] === 'show') {
      if (options.offline) throw new Error('offline');
      return { state: 'succeeded' };
    }
    if (args[0] === 'get') {
      if (options.downloadFails) { options.downloadFails = false; throw new Error('retry download'); }
      const output = args.find(x => x.startsWith('--output-dir=')).slice('--output-dir='.length);
      fs.mkdirSync(output, { recursive: true });
      const result = path.join(output, 'clip.mp4');
      fs.writeFileSync(result, 'test-video');
      return { outputs: [{ path: result }] };
    }
    assert.fail(args);
  };
  const q = new LocalQueue(root, runner);
  t.after(async () => { if (!options.closed) await q.close(); fs.rmSync(root, { recursive: true, force: true }); });
  return { q, root, calls, runner, options };
}

test('provider metadata has no address or key fields', () => {
  const exports = {};
  new VM({ sandbox: { exports }, eval: false, wasm: false }).run(
    transform(fs.readFileSync(path.join(__dirname, 'provider.ts'), 'utf8'), { transforms: ['typescript'] }).code);
  assert.equal(exports.vendor.inputs.length, 0);
  assert.equal(Object.keys(exports.vendor.inputValues).length, 0);
});

test('direct queue submits, polls and downloads without HTTP', async t => {
  const { q, calls } = fixture(t);
  const job = q.add(input, model);
  await q.tick();
  assert.equal(q.get(job.id).state, 'submitted');
  await q.tick();
  assert.equal(q.get(job.id).state, 'succeeded');
  assert.equal(fs.readFileSync(q.get(job.id).result, 'utf8'), 'test-video');
  assert.equal(await q.generate(input, model), Buffer.from('test-video').toString('base64'));
  assert.deepEqual(calls.map(c => c[0]), ['preflight', 'submit', 'show', 'get']);
});

test('a versioned video-reference workflow uses its own parameter schema', async t => {
  const { q, calls } = fixture(t);
  const model = { modelName: 'vgen/minimax-h3-face-reference@2.0.1',
    workflowRef: 'vgen/minimax-h3-face-reference@2.0.1', workflowDigest: null,
    mode: ['videoReference'], audio: false,
    durationResolutionMap: [{ duration: [5.167], resolution: ['default'] }],
    parameterDefaults: { seed: -1, start_time: 0, strength: 1 } };
  const image = Buffer.from([137,80,78,71,13,10,26,10]).toString('base64');
  const video = Buffer.concat([Buffer.from([0,0,0,24]), Buffer.from('ftypisom'), Buffer.alloc(16)]).toString('base64');
  const request = { ...input, vgenRequestId: 'face:1', duration: 5.167, resolution: 'default',
    mode: 'videoReference', referenceList: [{ type: 'image', base64: image }, { type: 'video', base64: video }] };
  const row = q.add(request, model); await q.tick();
  const args = calls.find(c => c[0] === 'submit');
  assert.equal(q.get(row.id).state, 'submitted');
  assert.ok(args.includes('--workflow=vgen/minimax-h3-face-reference@2.0.1'));
  assert.ok(args.some(a => a.startsWith('--video=')));
  assert.ok(args.some(a => a.startsWith('--image=')));
  assert.ok(!args.some(a => a.startsWith('--parameter=frames=')));
});

test('duplicate requests and overlapping ticks submit only once', async t => {
  const { q, calls } = fixture(t);
  const first = q.add(input, model);
  assert.equal(q.add(input, model).id, first.id);
  assert.throws(() => q.add({ ...input, prompt: 'different' }, model), /不同内容/);
  await Promise.all([q.tick(), q.tick(), q.tick()]);
  await q.tick();
  assert.equal(calls.filter(c => c[0] === 'submit').length, 1);
});

test('known tasks survive restart and interrupted submission is quarantined', async t => {
  const f = fixture(t);
  const first = f.q.add(input, model);
  await f.q.tick();
  const unknown = f.q.add({ ...input, vgenRequestId: 'unknown' }, model);
  f.q.update(unknown.id, { state: 'submitting' });
  await f.q.close(); f.options.closed = true;
  const q = new LocalQueue(f.root, f.runner);
  try {
    assert.equal(q.get(unknown.id).state, 'needs_attention');
    await q.tick();
    assert.equal(q.get(first.id).state, 'succeeded');
    assert.equal(f.calls.filter(c => c[0] === 'submit').length, 1);
  } finally { await q.close(); }
});

test('preflight failure prevents submission and uses a useful message', async t => {
  const { q, calls } = fixture(t, { preflight: 'worker_offline_or_busy' });
  const job = q.add(input, model);
  await q.tick();
  assert.equal(q.get(job.id).state, 'failed');
  assert.match(q.get(job.id).error, /生成电脑当前离线/);
  assert.equal(calls.length, 1);
});

test('ambiguous submission is not retried automatically', async t => {
  const { q, calls } = fixture(t, { unknown: true });
  const job = q.add(input, model);
  await q.tick(); await q.tick();
  assert.equal(q.get(job.id).state, 'needs_attention');
  assert.equal(calls.filter(c => c[0] === 'submit').length, 1);
});

test('transient downloads retry without submitting again', async t => {
  const { q, calls } = fixture(t, { downloadFails: true });
  const job = q.add(input, model);
  await q.tick(); await q.tick(); await q.tick();
  assert.equal(q.get(job.id).state, 'succeeded');
  assert.equal(calls.filter(c => c[0] === 'submit').length, 1);
});

test('first and last images are private files; shell-looking prompt stays a positional value', async t => {
  const { q, calls } = fixture(t);
  const base64 = Buffer.from([137,80,78,71,13,10,26,10]).toString('base64');
  const special = { ...input, prompt: '-prompt; $(echo no)', aspectRatio: '9:16', mode: 'startEndRequired',
    referenceList: [{ type: 'image', base64 }, { type: 'image', base64 }] };
  q.add(special, model); await q.tick();
  const args = calls.find(c => c[0] === 'submit');
  assert.deepEqual(Array.from(args.slice(-2)), ['--', special.prompt]);
  assert.ok(args.includes('--parameter=width=768'));
  for (const flag of ['--image=', '--last-image=']) {
    const file = args.find(a => a.startsWith(flag)).slice(flag.length);
    assert.equal(fs.readFileSync(file).toString('base64'), base64);
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  }
});

test('unsupported duration, audio-off and invalid image counts are rejected', () => {
  for (const overrides of [{ duration: 5 }, { audio: false }, { mode: 'singleImage' },
    { mode: 'startEndRequired' }, { mode: 'videoReference', referenceList: [{ type: 'video', base64: 'abc' }] }, { referenceList: [{ type: 'video', base64: 'abc' }] }]) {
    assert.throws(() => normalize({ ...input, ...overrides }, model));
  }
});

test('a second consumer cannot reset a live queue', async t => {
  const { q, root, runner } = fixture(t);
  q.add(input, model);
  assert.throws(() => new LocalQueue(root, runner), /已有 Toonflow 实例/);
});

test('CLI process uses argv, configured profile, no shell, and redacts raw stderr', async () => {
  let argv;
  const { runCLI } = load('vgenLocal.ts', { 'node:child_process': { execFile: (file, args, options, cb) => {
    argv = args;
    assert.equal(options.shell, false);
    cb(new Error('private'), '', '600001 VALIDATION_FAILED: PRIVATE_CONTENT');
  } } });
  await assert.rejects(runCLI(['submit', '--', '-prompt; $(bad)']), error => {
    assert.match(error.message, /VALIDATION_FAILED/);
    assert.ok(!error.message.includes('PRIVATE_CONTENT'));
    return true;
  });
  assert.deepEqual(Array.from(argv.slice(-2)), ['--', '-prompt; $(bad)']);
});

test('recovery imports completed project video without address, token, or network', async () => {
  const rows = [{ id: 3, projectId: 1, scriptId: 2, state: '生成失败', filePath: '/1/video/result.mp4' }];
  const writes = [];
  let context;
  const util = {
    getPath: () => '/test/toonflow',
    oss: { writeFile: async (file, content) => writes.push({ file, content }) },
    db: () => ({ where: condition => ({
      first: async () => rows.find(r => Object.entries(condition).every(([k, v]) => r[k] === v)),
      update: async values => Object.assign(rows[0], values),
    }) }),
  };
  class Queue {
    rows() { return [{ state: 'succeeded', result: 'local.mp4', request: JSON.stringify({ context }) }]; }
  }
  const module = load('vgenRecovery.ts', { '@/utils': util, '@/utils/vgenLocal': { LocalQueue: Queue },
    'node:fs': { readFileSync: () => Buffer.from('restored') } });
  const enriched = module.vgenContext({}, { projectId: 1, relatedObjects: '{"videoId":3,"scriptId":2}' });
  context = enriched.vgenContext;
  await module.recoverVgenVideos();
  assert.equal(rows[0].state, '生成成功');
  assert.equal(writes[0].content, Buffer.from('restored').toString('base64'));
  await module.recoverVgenVideos();
  assert.equal(writes.length, 1);
});
