const CLASS_ORDER = Object.freeze({
  PUBLIC: 0,
  INTERNAL: 1,
  CONFIDENTIAL: 2,
  VERY_CONFIDENTIAL: 3,
  STRATEGIC: 4,
  CRITICAL: 5,
});

const ROLE_ACTIONS = Object.freeze({
  ESTIMATOR: new Set(['READ','CREATE','UPDATE','CALCULATE']),
  REVIEWER: new Set(['READ','CALCULATE','VALIDATE']),
  APPROVER: new Set(['READ','VALIDATE','APPROVE']),
  ADMIN: new Set([]),
});

const asArray = (v) => v == null ? [] : Array.isArray(v) ? v : [v];
const activeAt = (m, now) => {
  if (m.status !== 'ACTIVE') return false;
  const t = now instanceof Date ? now : new Date(now);
  if (m.valid_from && new Date(m.valid_from) > t) return false;
  if (m.valid_to && new Date(m.valid_to) <= t) return false;
  return true;
};
const within = (value, scope) => scope == null || scope === '' || scope === value;
const claimAllows = (value, scopeClaim) => {
  const xs = asArray(scopeClaim);
  return xs.length === 0 || xs.includes(value);
};
const ceilingAllows = (assetClass, ...ceilings) => {
  if (!(assetClass in CLASS_ORDER)) return false;
  return ceilings.every((c) => c in CLASS_ORDER && CLASS_ORDER[assetClass] <= CLASS_ORDER[c]);
};

export function authorize({ claims, memberships, request, resource, now = new Date() }) {
  const reasons = [];
  if (!claims || !claims.sub || !claims.iss) reasons.push('TOKEN_IDENTITY_MISSING');
  if (!request?.action || !request?.tenant_id) reasons.push('REQUEST_CONTEXT_MISSING');
  if (!resource?.classification) reasons.push('RESOURCE_CLASSIFICATION_MISSING');
  if (reasons.length) return { allowed: false, reasons, matchedMemberships: [] };

  if (claims.tenant_id !== request.tenant_id) reasons.push('TOKEN_TENANT_MISMATCH');
  if (resource.tenant_id && resource.tenant_id !== request.tenant_id) reasons.push('RESOURCE_TENANT_MISMATCH');
  if (!claimAllows(request.country_code, claims.country_scope)) reasons.push('TOKEN_COUNTRY_SCOPE_DENY');
  if (!claimAllows(request.project_id, claims.project_scope)) reasons.push('TOKEN_PROJECT_SCOPE_DENY');
  if (!ceilingAllows(resource.classification, claims.classification_ceiling)) reasons.push('TOKEN_CLASSIFICATION_DENY');
  if (reasons.length) return { allowed: false, reasons, matchedMemberships: [] };

  const tokenRoles = new Set(asArray(claims.roles));
  const candidates = (memberships || []).filter((m) =>
    m.tenant_id === request.tenant_id &&
    activeAt(m, now) &&
    tokenRoles.has(m.role_code) &&
    within(request.org_scope_id, m.org_scope_id) &&
    within(request.country_code, m.country_scope) &&
    within(request.project_id, m.project_scope) &&
    ceilingAllows(resource.classification, m.classification_ceiling)
  );

  if (!candidates.length) return { allowed: false, reasons: ['NO_ACTIVE_MEMBERSHIP_INTERSECTION'], matchedMemberships: [] };

  const actionCandidates = candidates.filter((m) => ROLE_ACTIONS[m.role_code]?.has(request.action));
  if (!actionCandidates.length) return { allowed: false, reasons: ['ROLE_ACTION_DENY'], matchedMemberships: candidates };

  if (['VALIDATE','APPROVE'].includes(request.action) && resource.created_by_subject && resource.created_by_subject === claims.sub) {
    return { allowed: false, reasons: ['SOD_SELF_REVIEW_OR_APPROVAL_DENY'], matchedMemberships: actionCandidates };
  }

  for (const check of asArray(request.context_checks)) {
    if (check && check.pass === false) return { allowed: false, reasons: [`CONTEXT_DENY:${check.code || 'UNSPECIFIED'}`], matchedMemberships: actionCandidates };
  }

  return {
    allowed: true,
    reasons: ['ALLOW'],
    matchedMemberships: actionCandidates,
    effectiveRoles: [...new Set(actionCandidates.map((m) => m.role_code))],
  };
}

export { CLASS_ORDER, ROLE_ACTIONS };
