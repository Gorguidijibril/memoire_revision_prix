import assert from 'node:assert/strict';
import { authorize } from './authz.mjs';

const tenant = '11111111-1111-4111-8111-111111111111';
const project = '22222222-2222-4222-8222-222222222222';
const claims = {
  iss: 'https://bcis-wave0-oidc-selftest.onrender.com',
  sub: 'user-1',
  tenant_id: tenant,
  roles: ['ESTIMATOR','REVIEWER','APPROVER','ADMIN'],
  country_scope: ['SN'],
  project_scope: [project],
  classification_ceiling: 'CONFIDENTIAL',
};
const memberships = [
  {tenant_id:tenant, role_code:'ESTIMATOR', country_scope:'SN', project_scope:project, classification_ceiling:'CONFIDENTIAL', status:'ACTIVE'},
  {tenant_id:tenant, role_code:'REVIEWER', country_scope:'SN', project_scope:project, classification_ceiling:'CONFIDENTIAL', status:'ACTIVE'},
  {tenant_id:tenant, role_code:'APPROVER', country_scope:'SN', project_scope:project, classification_ceiling:'CONFIDENTIAL', status:'ACTIVE'},
  {tenant_id:tenant, role_code:'ADMIN', country_scope:null, project_scope:null, classification_ceiling:'CRITICAL', status:'ACTIVE'},
];
const req = (action, overrides={}) => ({action, tenant_id:tenant, country_code:'SN', project_id:project, ...overrides});
const res = (overrides={}) => ({tenant_id:tenant, classification:'CONFIDENTIAL', created_by_subject:'other-user', ...overrides});

const cases = [
  ['estimator calculate allow', claims, memberships, req('CALCULATE'), res(), true],
  ['approver approve allow', claims, memberships, req('APPROVE'), res(), true],
  ['self approve deny', claims, memberships, req('APPROVE'), res({created_by_subject:'user-1'}), false],
  ['token tenant mismatch deny', {...claims,tenant_id:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'}, memberships, req('READ'), res(), false],
  ['token country mismatch deny', {...claims,country_scope:['CI']}, memberships, req('READ'), res(), false],
  ['token project mismatch deny', {...claims,project_scope:['other']}, memberships, req('READ'), res(), false],
  ['empty token country scope deny', {...claims,country_scope:[]}, memberships, req('READ'), res(), false],
  ['missing token country scope deny', {...claims,country_scope:undefined}, memberships, req('READ'), res(), false],
  ['empty token project scope deny', {...claims,project_scope:[]}, memberships, req('READ'), res(), false],
  ['missing token project scope deny', {...claims,project_scope:undefined}, memberships, req('READ'), res(), false],
  ['token classification ceiling deny', {...claims,classification_ceiling:'INTERNAL'}, memberships, req('READ'), res(), false],
  ['suspended membership deny', {...claims,roles:['ESTIMATOR']}, memberships.map(m=>m.role_code==='ESTIMATOR'?{...m,status:'SUSPENDED'}:m), req('CALCULATE'), res(), false],
  ['expired membership deny', {...claims,roles:['ESTIMATOR']}, memberships.map(m=>m.role_code==='ESTIMATOR'?{...m,valid_to:'2020-01-01T00:00:00Z'}:m), req('CALCULATE'), res(), false],
  ['membership project mismatch deny', {...claims,roles:['ESTIMATOR']}, memberships.map(m=>m.role_code==='ESTIMATOR'?{...m,project_scope:'other'}:m), req('CALCULATE'), res(), false],
  ['empty membership country scope deny', {...claims,roles:['ESTIMATOR']}, memberships.map(m=>m.role_code==='ESTIMATOR'?{...m,country_scope:null}:m), req('CALCULATE'), res(), false],
  ['empty membership project scope deny', {...claims,roles:['ESTIMATOR']}, memberships.map(m=>m.role_code==='ESTIMATOR'?{...m,project_scope:null}:m), req('CALCULATE'), res(), false],
  ['membership classification ceiling deny', {...claims,roles:['ESTIMATOR']}, memberships.map(m=>m.role_code==='ESTIMATOR'?{...m,classification_ceiling:'INTERNAL'}:m), req('CALCULATE'), res(), false],
  ['admin alone no business access', {...claims,roles:['ADMIN'],classification_ceiling:'CRITICAL'}, memberships, req('READ'), res({classification:'INTERNAL'}), false],
  ['context constraint deny', claims, memberships, req('READ',{context_checks:[{code:'FOUR_EYES',pass:false}]}), res(), false],
];

for (const [name,c,m,r,resource,expected] of cases) {
  const out = authorize({claims:c,memberships:m,request:r,resource,now:new Date('2026-09-11T23:00:00Z')});
  assert.equal(out.allowed, expected, `${name}: ${JSON.stringify(out)}`);
  console.log(JSON.stringify({case:name,allowed:out.allowed,reasons:out.reasons}));
}
console.log(JSON.stringify({event:'AUTHZ_SELFTEST_PASS',cases:cases.length}));
