import { audit } from "../audit.js";

const WAF_RULES = [
  { id: "WAF-XSS-01", name: "XSS Script/Event Handler", rx: /(<\s*script\b|javascript\s*:|on(error|load|click|mouseover|focus)\s*=)/i },
  { id: "WAF-SQLI-01", name: "SQL Injection Pattern", rx: /(\b(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|or\s+1\s*=\s*1)\b|--\s*$|;\s*shutdown)/i },
  { id: "WAF-TRAVERSAL-01", name: "Path Traversal", rx: /(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e)/i },
  { id: "WAF-CMDI-01", name: "OS Command Injection", rx: /(\|\s*(bash|sh|nc|curl|wget|powershell)|;\s*(rm\s+-rf|cat\s+\/etc\/passwd))/i },
  { id: "WAF-PROTO-01", name: "Prototype Pollution", rx: /("__proto__"|"constructor"\s*:\s*\{\s*"prototype")/i },
];

function flattenStrings(val, depth = 0, out = []) {
  if (depth > 6 || out.length > 100) throw new Error("WAF_LIMIT");
  if (typeof val === "string") {
    out.push(val);
  } else if (Array.isArray(val)) {
    for (const item of val) flattenStrings(item, depth + 1, out);
  } else if (val && typeof val === "object") {
    for (const [k, v] of Object.entries(val)) {
      out.push(k);
      flattenStrings(v, depth + 1, out);
    }
  }
  return out;
}

/**
 * Memeriksa payload yang dikirim dari frontend klien sebelum menerbitkan Security Passport.
 * Mengembalikan { blocked: boolean, rule?: object }
 */
export function inspectPayloadWaf(req, payloadSample) {
  let strings;
  try { strings = flattenStrings(payloadSample); }
  catch { return { blocked: true, rule: { id: "WAF-LIMIT", name: "Payload too complex" } }; }
  for (const text of strings) {
    for (const rule of WAF_RULES) {
      if (rule.rx.test(text)) {
        audit("waf_blocked", req, { ruleId: rule.id, ruleName: rule.name, });
        return { blocked: true, rule: { id: rule.id, name: rule.name } };
      }
    }
  }
  return { blocked: false };
}