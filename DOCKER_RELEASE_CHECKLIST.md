# Docker Release Regression Checklist (Windows / PowerShell)

Goal: a fast, repeatable validation of every new SecureShare release on local Docker.

## 0) Update code from GitHub

```powershell
git fetch --all --tags
git pull --ff-only
```

**PASS:** no conflicts, repository is up to date with `origin/main`.

---

## 1) Clean Docker reset

```powershell
docker compose down --remove-orphans
docker image rm secureshare-app-secureshare:latest -f
```

**PASS:** previous container and image are removed.

---

## 2) Clean build without cache

```powershell
docker compose build --no-cache
```

**PASS:** build finishes successfully (`Built`).

---

## 3) Start stack and run health check

```powershell
docker compose up -d
docker compose ps
(Invoke-WebRequest -Uri http://localhost:3000/api/health -UseBasicParsing).Content
```

**PASS:**
- `docker compose ps` shows the container as `Up` (target state: `healthy`),
- `/api/health` returns JSON with `"status":"ok"`.

---

## 4) Smoke test: create/get/burn (no password, viewLimit=1)

Run the E2E script inside the container:

```powershell
docker compose exec -T secureshare node -e "const base='http://localhost:3000'; const crypto=require('crypto'); (async()=>{ const health=await (await fetch(base+'/api/health')).json(); const challenge=await (await fetch(base+'/api/pow/challenge')).json(); const resource=challenge.resource, salt=challenge.salt, difficulty=challenge.difficulty; const target='0'.repeat(difficulty); let nonce=0; while(true){ const header='1:'+difficulty+':'+resource+':'+salt+':'+nonce; const hash=crypto.createHash('sha256').update(header).digest('hex'); const bin=hash.split('').map(h=>parseInt(h,16).toString(2).padStart(4,'0')).join(''); if(bin.startsWith(target)) break; nonce++; } const createRes=await fetch(base+'/api/secrets',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({encryptedData:'smoke-test-payload',passwordHash:null,salt:null,expirationHours:1,viewLimit:1,powNonce:String(nonce),powSalt:salt})}); const created=await createRes.json(); const id=created.id; const fetched=await (await fetch(base+'/api/secrets/'+id)).json(); const burnRes=await fetch(base+'/api/secrets/'+id+'/burn',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({passwordHash:null})}); const burned=await burnRes.json(); const after=await fetch(base+'/api/secrets/'+id); console.log(JSON.stringify({health:health.status,id,fetchedHasPassword:fetched.hasPassword,burned:burned.burned,postBurnFetchStatus:after.status},null,2)); })().catch(e=>{ console.error(e); process.exit(1);});"
```

**PASS:**
- `health: "ok"`,
- `burned: true`,
- `postBurnFetchStatus: 404`.

---

## 5) Smoke test: password + brute-force protection (3 failed attempts)

```powershell
docker compose exec -T secureshare node -e "const base='http://localhost:3000'; const crypto=require('crypto'); const assert=(cond,msg)=>{ if(!cond) throw new Error(msg); }; async function solvePow(){ const challenge=await (await fetch(base+'/api/pow/challenge')).json(); const {resource,salt,difficulty}=challenge; const target='0'.repeat(difficulty); let nonce=0; while(true){ const header='1:'+difficulty+':'+resource+':'+salt+':'+nonce; const hash=crypto.createHash('sha256').update(header).digest('hex'); const bin=hash.split('').map(h=>parseInt(h,16).toString(2).padStart(4,'0')).join(''); if(bin.startsWith(target)) return {nonce:String(nonce),salt,difficulty}; nonce++; } } async function createSecret({encryptedData,passwordHash,salt,expirationHours,viewLimit}){ const pow=await solvePow(); const res=await fetch(base+'/api/secrets',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({encryptedData,passwordHash,salt,expirationHours,viewLimit,powNonce:pow.nonce,powSalt:pow.salt})}); const body=await res.json(); assert(res.ok,'Create failed: '+JSON.stringify(body)); return {id:body.id,powDifficulty:pow.difficulty}; } async function getSecret(id){ const res=await fetch(base+'/api/secrets/'+id); const body=await res.json().catch(()=>({})); return {status:res.status,body}; } async function burnSecret(id,passwordHash){ const res=await fetch(base+'/api/secrets/'+id+'/burn',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({passwordHash})}); const body=await res.json().catch(()=>({})); return {status:res.status,body}; } (async()=>{ const testSalt='client-salt-smoke'; const correctHash='correct-hash'; const wrongHash='wrong-hash'; const createdA=await createSecret({encryptedData:'pw-secret-happy-path',passwordHash:correctHash,salt:testSalt,expirationHours:1,viewLimit:1}); const burnA=await burnSecret(createdA.id,correctHash); const afterA=await getSecret(createdA.id); const createdB=await createSecret({encryptedData:'pw-secret-bruteforce',passwordHash:correctHash,salt:testSalt,expirationHours:1,viewLimit:5}); const wrong1=await burnSecret(createdB.id,wrongHash); const wrong2=await burnSecret(createdB.id,wrongHash); const wrong3=await burnSecret(createdB.id,wrongHash); const afterB=await getSecret(createdB.id); console.log(JSON.stringify({happyPath:{burnStatus:burnA.status,burned:burnA.body.burned,postBurnStatus:afterA.status},bruteForce:{attemptStatuses:[wrong1.status,wrong2.status,wrong3.status],thirdAttemptError:wrong3.body.error,postDeleteStatus:afterB.status},result:'PASS'},null,2)); })().catch(e=>{ console.error('TEST FAILED:',e.message); process.exit(1); });"
```

**PASS:**
- happy path: `burnStatus=200`, `burned=true`, `postBurnStatus=404`,
- brute-force: `attemptStatuses=[401,401,401]`, third attempt returns permanent deletion message, `postDeleteStatus=404`.

---

## 6) Post-check: stats and logs

```powershell
docker compose exec -T secureshare npm run stats
docker compose logs --tail=40 secureshare
```

**PASS:**
- `stats` executes without errors,
- logs include expected events (`SECRET_CREATED`, `FAILED_ATTEMPT`, `SECRET_DELETED`).

---

## 7) Cleanup after test

```powershell
docker compose down --remove-orphans
```

**PASS:** stack is stopped and removed.

---

## Critical release conditions (go / no-go)

Release is **NO-GO** if any of the following occurs:
- container does not reach `Up` / `healthy`,
- `/api/health` does not return `status=ok`,
- create/get/burn flow fails expected behavior,
- brute-force protection does not delete secret after 3 failed attempts,
- `npm run stats` fails inside the container.
