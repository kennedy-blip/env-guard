const $ = (selector) => document.querySelector(selector);
const state = { templates: [], activeTemplate: null, findings: [], online: false };

const fallbackTemplates = [
  { id:"payments-production", name:"Payments & Webhook Gateway (production)", targetEnv:"production", requiredKeys:["APP_ENV","APP_URL","DATABASE_URL","PAYMENT_SECRET","PORT","DEBUG"], rules:[{key:"APP_ENV",format:"ENUM",allowed:["production"]},{key:"APP_URL",format:"URL_HTTPS"},{key:"DATABASE_URL",format:"POSTGRES_DSN"},{key:"PAYMENT_SECRET",format:"SECRET_MIN_LEN",min:32},{key:"PORT",format:"INTEGER_RANGE",min:1,max:65535},{key:"DEBUG",format:"ENUM",allowed:["false"]}], rawEnvText:"APP_ENV=production\nAPP_URL=https://api.example.com\nDATABASE_URL=postgres://app:replace-me@db.example.com:5432/payments\nPAYMENT_SECRET=replace-with-a-strong-random-secret-value\nPORT=8080\nDEBUG=false" },
  { id:"analytics-staging", name:"Analytics & Data Worker (staging)", targetEnv:"staging", requiredKeys:["APP_ENV","DATABASE_URL","REDIS_URL","WORKER_CONCURRENCY"], rules:[{key:"APP_ENV",format:"ENUM",allowed:["staging"]},{key:"DATABASE_URL",format:"POSTGRES_DSN"},{key:"REDIS_URL",format:"URL"},{key:"WORKER_CONCURRENCY",format:"INTEGER_RANGE",min:1,max:64}], rawEnvText:"APP_ENV=staging\nDATABASE_URL=postgres://worker:replace-me@staging-db.example.com:5432/analytics\nREDIS_URL=redis://cache.example.com:6379/0\nWORKER_CONCURRENCY=4" },
  { id:"local-dev", name:"Local Dev API Service (development)", targetEnv:"development", requiredKeys:["APP_ENV","APP_URL","DATABASE_URL","DEBUG","PORT"], rules:[{key:"APP_ENV",format:"ENUM",allowed:["development"]},{key:"APP_URL",format:"URL"},{key:"DATABASE_URL",format:"POSTGRES_DSN"},{key:"DEBUG",format:"ENUM",allowed:["true","false"]},{key:"PORT",format:"INTEGER_RANGE",min:1,max:65535}], rawEnvText:"APP_ENV=development\nAPP_URL=http://localhost:3000\nDATABASE_URL=postgres://dev:dev@localhost:5432/app\nDEBUG=true\nPORT=3000" }
];

function parseEnv(text) {
  const result = {};
  text.split(/\r?\n/).forEach((line) => {
    const clean = line.trim().replace(/^export\s+/, "");
    if (!clean || clean.startsWith("#")) return;
    const index = clean.indexOf("=");
    if (index < 1) return;
    const key = clean.slice(0,index).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) return;
    result[key] = clean.slice(index+1).trim().replace(/^(['"])(.*)\1$/, "$2");
  });
  return result;
}
function mask(value) {
  if (!value) return "(empty)";
  if (/\s/.test(value)) return "[masked]";
  if (value.length <= 4) return "*".repeat(value.length);
  return value.slice(0,2) + "*".repeat(Math.min(value.length-6,12)) + value.slice(-4);
}
function weakSecret(key,value) {
  if (!/(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)/i.test(key)) return false;
  return value.length < 16 || /(changeme|replace-me|replace_with|your_|example|placeholder|password|secret)/i.test(value);
}
function localValidate(targetEnv, rawEnvText, requiredKeys, rules) {
  const entries = parseEnv(rawEnvText), findings = [];
  requiredKeys.forEach(key => { if (!(key in entries)) findings.push({key,severity:"FAIL",code:"MISSING_REQUIRED",message:"Required variable is missing.",suggestion:"Add this key to the environment bundle."}); });
  Object.entries(entries).forEach(([key,value]) => {
    const rule = rules.find(item => item.key === key) || {};
    const f = {key,masked:mask(value),severity:"PASS",code:"PASS",message:"Value passed configured checks.",suggestion:"No action required."};
    if (weakSecret(key,value)) Object.assign(f,{severity:"FAIL",code:"WEAK_OR_PLACEHOLDER_SECRET",message:"Secret appears short, predictable, or is a placeholder.",suggestion:"Use a unique randomly generated secret stored in a secret manager."});
    else if (targetEnv === "production" && ((/^(DEBUG|ENABLE_)/.test(key) && value.toLowerCase()==="true") || /localhost|127\.0\.0\.1/i.test(value))) Object.assign(f,{severity:"FAIL",code:"ENV_MISMATCH",message:"Development-only value detected in production.",suggestion:"Use production endpoints and disable debug-only flags."});
    else if (["URL","URL_HTTPS"].includes(rule.format)) { try { const u=new URL(value); if (!["http:","https:"].includes(u.protocol) || (rule.format==="URL_HTTPS" && u.protocol!=="https:")) throw Error(); } catch { Object.assign(f,{severity:"FAIL",code:"INVALID_URL_OR_DSN",message:"URL is malformed or does not use the required scheme.",suggestion:"Provide a valid URL; use HTTPS for production endpoints."}); } }
    else if (rule.format==="POSTGRES_DSN" && !/^postgres(ql)?:\/\/[^@]+@[^/]+\/.+/.test(value)) Object.assign(f,{severity:"FAIL",code:"INVALID_URL_OR_DSN",message:"PostgreSQL connection string is malformed.",suggestion:"Use postgres://user:password@host:5432/database."});
    else if (rule.format==="INTEGER_RANGE" && (!/^\d+$/.test(value) || +value<rule.min || +value>rule.max)) Object.assign(f,{severity:"FAIL",code:"OUT_OF_RANGE_INT",message:"Integer is outside the contract range.",suggestion:"Set a numeric value within the contract range."});
    else if (rule.format==="SECRET_MIN_LEN" && value.length<rule.min) Object.assign(f,{severity:"FAIL",code:"WEAK_OR_PLACEHOLDER_SECRET",message:"Secret does not meet the minimum length.",suggestion:"Generate a longer random secret."});
    else if (rule.format==="ENUM" && rule.allowed?.length && !rule.allowed.includes(value)) Object.assign(f,{severity:"FAIL",code:"ENV_MISMATCH",message:"Value is not one of the contract's allowed options.",suggestion:"Choose one of the declared values."});
    findings.push(f);
    if (!requiredKeys.includes(key) && !rules.some(item=>item.key===key)) findings.push({key,masked:mask(value),severity:"WARN",code:"UNDECLARED_KEY",message:"Variable is not declared in this contract.",suggestion:"Add it to the contract or remove it if unused."});
  });
  const score=Math.max(0,100-findings.reduce((n,f)=>n+(f.severity==="FAIL"?18:f.severity==="WARN"?7:0),0));
  return {score,verdict:score<60?"BLOCKED":score<90?"WARN":"READY",findings,checkedKeys:Object.keys(entries).length,targetEnv};
}
async function api(path, options={}) {
  const response=await fetch(path,{...options,headers:{"Content-Type":"application/json",...(options.headers||{})}});
  if(!response.ok) throw new Error("API request failed ("+response.status+")");
  return response.json();
}
function showToast(message) { $("#toast").textContent=message; }
function renderChecklist(template) {
  $("#contract-checklist").innerHTML="";
  (template?.rules||[]).forEach(rule=>{const el=document.createElement("span");el.className="check-item";el.textContent=rule.key+" · "+rule.format;$("#contract-checklist").append(el);});
  if (!template?.rules?.length) $("#contract-checklist").textContent="No rules defined.";
}
function selectTemplate(id) {
  const template=state.templates.find(item=>item.id===id)||state.templates[0];
  if(!template)return;
  state.activeTemplate=template;
  $("#preset-select").value=template.id;
  $("#environment").value=template.targetEnv;
  $("#env-editor").value=template.rawEnvText;
  renderChecklist(template); updateLineCount();
}
function updateLineCount(){ $("#line-count").textContent=$("#env-editor").value.split(/\r?\n/).length+" lines"; }
function renderResults(result) {
  $("#empty-state").hidden=true; $("#findings").innerHTML="";
  $("#score").textContent=result.score; $("#score-meter").style.width=result.score+"%";
  $("#score-meter").style.background=result.verdict==="BLOCKED"?"var(--rose)":result.verdict==="WARN"?"var(--amber)":"var(--green)";
  $("#verdict").textContent=result.verdict; $("#verdict").className="status status-"+result.verdict.toLowerCase();
  $("#checked-count").textContent=result.checkedKeys+" keys inspected"; $("#finding-total").textContent=result.findings.length+" FINDINGS";
  result.findings.forEach(f=>{
    const card=document.createElement("article");card.className="finding";
    const top=document.createElement("div");top.className="finding-top";
    const key=document.createElement("strong");key.className="finding-key";key.textContent=f.key;
    const meta=document.createElement("div");meta.className="finding-meta";
    const code=document.createElement("span");code.className="finding-code";code.textContent=f.code;
    const severity=document.createElement("span");severity.className="severity severity-"+f.severity;severity.textContent=f.severity;
    meta.append(code,severity);top.append(key,meta);card.append(top);
    if(f.masked){const value=document.createElement("div");value.className="finding-value";value.textContent="VALUE  "+f.masked;card.append(value);}
    const message=document.createElement("div");message.className="finding-message";message.textContent=f.message;
    const suggestion=document.createElement("div");suggestion.className="finding-suggestion";suggestion.textContent="↳ "+f.suggestion;
    card.append(message,suggestion);$("#findings").append(card);
  });
  if(!result.findings.length){$("#findings").textContent="No findings. All configured checks passed.";}
}
async function validate() {
  const payload={targetEnv:$("#environment").value,rawEnvText:$("#env-editor").value,requiredKeys:state.activeTemplate?.requiredKeys||[],rules:state.activeTemplate?.rules||[]};
  $("#validate").disabled=true;$("#validate").textContent="Validating…";
  try {
    const result=state.online?await api("/api/validate",{method:"POST",body:JSON.stringify(payload)}):localValidate(payload.targetEnv,payload.rawEnvText,payload.requiredKeys,payload.rules);
    renderResults(result);showToast(state.online?"Validation completed by Go engine.":"Offline fallback validation completed.");
  } catch(error) { const result=localValidate(payload.targetEnv,payload.rawEnvText,payload.requiredKeys,payload.rules);renderResults(result);showToast("API unavailable — local fallback used."); }
  finally {$("#validate").disabled=false;$("#validate").innerHTML='Validate Config <span>→</span>';}
}
function sanitizedExample() {
  const values=parseEnv($("#env-editor").value);
  return Object.keys(values).map(key=>{const secret=/(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)/i.test(key);return key+"="+(secret?"<GENERATE_SECRET>":values[key].includes("localhost")?"http://localhost:PORT":values[key].includes("postgres")?"postgres://USER:PASSWORD@HOST:5432/DATABASE":values[key].includes("https://")?"https://YOUR_HOST":values[key]);}).join("\n");
}
async function init() {
  try {const health=await api("/api/health");state.online=health.status==="ok";$("#engine-status").textContent="EnvGuard Go Engine: Active • Secret & Schema Guard Ready";}
  catch {state.online=false;$("#engine-status").textContent="Local fallback validator • Go API offline";}
  try {const data=await api("/api/templates");state.templates=data.templates||fallbackTemplates;}
  catch {state.templates=fallbackTemplates;}
  $("#preset-select").innerHTML="";
  state.templates.forEach(t=>{const option=document.createElement("option");option.value=t.id;option.textContent=t.name;$("#preset-select").append(option);});
  selectTemplate(state.templates[0]?.id);
}
$("#preset-select").addEventListener("change",e=>selectTemplate(e.target.value));
$("#environment").addEventListener("change",e=>{if(state.activeTemplate)state.activeTemplate.targetEnv=e.target.value;});
$("#env-editor").addEventListener("input",updateLineCount);
$("#validate").addEventListener("click",validate);
$("#load-production").addEventListener("click",()=>{const item=state.templates.find(t=>t.targetEnv==="production")||state.templates[0];selectTemplate(item.id);showToast("Production contract loaded.");});
$("#inject-broken").addEventListener("click",()=>{$("#environment").value="production";$("#env-editor").value="APP_ENV=development\nAPP_URL=http://localhost:3000\nDATABASE_URL=not-a-dsn\nPAYMENT_SECRET=changeme\nPORT=99999\nDEBUG=true\nUNTRACKED_FLAG=yes";updateLineCount();showToast("Sample misconfigurations injected. Run validation.");});
$("#copy-example").addEventListener("click",async()=>{try{await navigator.clipboard.writeText(sanitizedExample());showToast("Sanitized .env.example copied.");}catch{showToast("Clipboard access unavailable in this browser.");}});
$("#save-contract").addEventListener("click",async()=>{if(!state.activeTemplate){showToast("Select a contract first.");return;}const item={...state.activeTemplate,targetEnv:$("#environment").value,rawEnvText:$("#env-editor").value};try{if(state.online){await api("/api/templates",{method:"POST",body:JSON.stringify(item)});showToast("Contract saved in this server instance.");}else{showToast("Offline: custom contract is available for this session only.");}}catch{showToast("Could not save contract. Serverless memory is ephemeral.");}});
init();
