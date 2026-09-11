import fs from 'node:fs';
import path from 'node:path';
import { Client } from 'pg';

const root = new URL('./bundle/', import.meta.url).pathname;
const db = process.env.DATABASE_URL;
if (!db) throw new Error('DATABASE_URL_REQUIRED');

const result = { startedAt: new Date().toISOString(), stages: [], status: 'RUNNING' };
const logStage = (name, status, detail={}) => {
  const x = {name,status,at:new Date().toISOString(),...detail};
  result.stages.push(x); console.log('BCIS_GATE_STAGE', JSON.stringify(x));
};
const clean = s => s.replace(/^\\set\s+.*$/gm,'').replace(/^\\echo\s+.*$/gm,'');
const sql = rel => clean(fs.readFileSync(path.join(root, rel), 'utf8'));
const one = async (rel, client=null) => {
  const own = !client; const c = client ?? new Client({connectionString:db, ssl:{rejectUnauthorized:false}});
  if (own) await c.connect();
  try { await c.query(sql(rel)); logStage(rel,'PASS'); }
  catch(e){ logStage(rel,'FAIL',{code:e.code,message:e.message}); throw e; }
  finally { if (own) await c.end(); }
};

const main = async () => {
  const guard = new Client({connectionString:db, ssl:{rejectUnauthorized:false}}); await guard.connect();
  try {
    const q = await guard.query("select to_regclass('public.tenants') as t");
    if (q.rows[0].t) throw new Error('NON_EMPTY_TARGET_REFUSED');
  } finally { await guard.end(); }

  for (const f of [
    'migrations/001_initial.sql','migrations/002_cost_chain_provenance.sql',
    'migrations/003_baseline_audit_hardening.sql','migrations/005_idempotency_auth_concurrency.sql',
    'migrations/006_sync_offline_foundation.sql','migrations/009_rc_v1_1_schema_consolidation.sql'
  ]) await one(f);

  await one('tests/assert_schema_v11.sql');
  await one('tests/golden_seed_v02.sql');
  await one('tests/assert_golden_v02.sql');
  await one('tests/assert_negative_constraints.sql');

  const validate = new Client({connectionString:db, ssl:{rejectUnauthorized:false}}); await validate.connect();
  try {
    await validate.query('ALTER TABLE sync_conflicts VALIDATE CONSTRAINT sync_conflict_resolution_complete_ck');
    await validate.query('ALTER TABLE cost_categories VALIDATE CONSTRAINT cost_categories_ccs09_cor_ck');
    logStage('deferred_constraints','PASS');
  } finally { await validate.end(); }

  await one('tests/concurrency_prepare.sql');
  const attemptSql = sql('tests/concurrency_attempt.sql');
  const attempts = await Promise.all(Array.from({length:25}, async (_,i) => {
    const c = new Client({connectionString:db, ssl:{rejectUnauthorized:false}}); await c.connect();
    try { await c.query(attemptSql); return {i:i+1,ok:true}; }
    catch(e){ return {i:i+1,ok:false,code:e.code,message:e.message}; }
    finally { await c.end(); }
  }));
  const successes = attempts.filter(x=>x.ok).length;
  console.log('BCIS_CONCURRENCY_ATTEMPTS', JSON.stringify({successes,attempts}));
  if (successes !== 1) throw new Error(`CONCURRENCY_PROCESS_COUNT_FAIL:${successes}`);
  await one('tests/concurrency_assert.sql');

  await one('tests/rls_fixture.sql');
  await one('migrations/010_oidc_rls_foundation.sql');
  try {
    await one('tests/rls_role_setup.sql');
  } catch (e) {
    if (['42501','0LP01'].includes(e.code)) throw new Error('RLS_NON_OWNER_ROLE_SETUP_BLOCKED_BY_MANAGED_DB_PRIVILEGES');
    throw e;
  }
  const rls = new Client({connectionString:db, ssl:{rejectUnauthorized:false}}); await rls.connect();
  try {
    await rls.query('SET ROLE bcis_wave0_app');
    await rls.query(sql('tests/rls_attack_tests.sql'));
    logStage('tests/rls_attack_tests.sql','PASS');
  } catch(e) { logStage('tests/rls_attack_tests.sql','FAIL',{code:e.code,message:e.message}); throw e; }
  finally { await rls.end(); }

  result.status='PASS'; result.finishedAt=new Date().toISOString();
  console.log('BCIS_WAVE0_RESULT', JSON.stringify(result));
};

main().catch(e=>{
  result.status='FAIL'; result.finishedAt=new Date().toISOString(); result.error={message:e.message,code:e.code};
  console.error('BCIS_WAVE0_RESULT', JSON.stringify(result)); process.exit(1);
});
