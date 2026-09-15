// Posts — the client. Served to the browser; never run in the Worker.
import * as C from '/crypto.js';

const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function show(h){$('#dlgbody').innerHTML=h;dlg.showModal()}

let TOKEN=localStorage.getItem('posts.token'), ID=null, STATE=null, FEED=null, CONTACTS={}, PENDING={}, ATTACH={}, SHOWN=[];
const api=(p,o={})=>fetch(p,{...o,headers:{...(o.headers||{}),authorization:'Bearer '+TOKEN}}).then(r=>r.json());

/* ---- local store: keys never leave here ---- */
const db=()=>new Promise((ok,no)=>{const r=indexedDB.open('posts',1);
  r.onupgradeneeded=()=>{r.result.createObjectStore('kv')};r.onsuccess=()=>ok(r.result);r.onerror=()=>no(r.error)});
const get=async k=>{const d=await db();return new Promise(ok=>{const q=d.transaction('kv').objectStore('kv').get(k);q.onsuccess=()=>ok(q.result);q.onerror=()=>ok(null)})};
const put=async (k,v)=>{const d=await db();return new Promise(ok=>{const t=d.transaction('kv','readwrite');t.objectStore('kv').put(v,k);t.oncomplete=ok})};

/* ---- boot ---- */
async function boot(){
  if(!await C.supported()){ $('#list').innerHTML='<div class=empty>This browser has no Ed25519 in WebCrypto. Posts needs it.</div>'; return }

  if(!TOKEN){
    const r=await fetch('/api/register',{method:'POST'}).then(r=>r.json());
    if(r.error){ show('<h3>Already claimed</h3><p>Paste the owner secret for this deployment.</p><input id=tk style="width:100%"><p style="text-align:left"><button class=p id=usebtn>Use it</button></p>');
      $('#usebtn').onclick=()=>{localStorage.setItem('posts.token',$('#tk').value.trim());location.reload()}; return }
    TOKEN=r.secret; localStorage.setItem('posts.token',TOKEN);
    show('<h3>Save your owner secret</h3><p>Shown once. It is the only way back in.</p><div class=k>'+esc(r.secret)+'</div>');
  }

  ID=await get('identity');
  if(!ID){ ID=await C.newKeys(); await put('identity',ID); }
  CONTACTS=(await get('contacts'))||{};

  await refresh();
  await publishContact();

  await showMe();
}

/* ---- publish the signed contact record ---- */
async function publishContact(){
  const pub=STATE.hooks.find(h=>h.kind==='public'&&h.status==='active');
  if(!pub) return;
  const rec=await C.makeContact(location.origin+'/h/'+pub.hook, ID);
  await fetch('/api/contact',{method:'PUT',headers:{authorization:'Bearer '+TOKEN},body:JSON.stringify(rec)});
}

/* ---- sidebar ---- */
async function refresh(){
  STATE=await api('/api/state');
  const feedOf=id=>STATE.feeds.find(f=>f.id===id)||{name:'?'};
  const row=(f,sub,hook)=>'<div class="src'+(FEED===f.id?' on':'')+'" data-f="'+f.id+'">'+
    '<div><b>'+esc(f.name)+'</b><small>'+esc(sub)+(f.arrive==='daily'?' · daily':'')+'</small></div>'+
    (hook?'<button class=manage data-h="'+esc(hook)+'" title="Manage">⋯</button>':'<span class=pill>'+(f.n||0)+'</span>')+
    '</div>';
  const live=STATE.hooks.filter(h=>h.status!=='dead');
  $('#srcs').innerHTML=
    '<div class="src'+(FEED==='*'?' on':'')+'" data-f="*"><div><b>All</b><small>everything, newest first</small></div></div>'+
    '<div class=sec>Private</div>'+live.map(h=>row(feedOf(h.feed),
        h.status==='retired'?'retiring':(h.kind==='public'?'public hook':h.label||'hook'), h.hook)).join('')+
    '<div class=sec>Subscribed</div>'+(STATE.sources.map(s=>row(feedOf(s.feed),'public feed')).join('')||'<div class=src><small style="padding:0 4px">nothing yet</small></div>')+
    (Object.keys(CONTACTS).length?'<div class=sec>People</div>'+Object.entries(CONTACTS).map(([k,c])=>'<div class=src data-c="'+esc(k)+'"><div><b>'+esc(c.petname)+'</b><small>'+esc(c.fingerprint)+'</small></div></div>').join(''):'');
  $('#srcs').querySelectorAll('[data-f]').forEach(el=>el.onclick=()=>openFeed(el.dataset.f));
  $('#srcs').querySelectorAll('[data-c]').forEach(el=>el.onclick=()=>composeTo(el.dataset.c));
  $('#srcs').querySelectorAll('.manage').forEach(b=>b.onclick=e=>{e.stopPropagation();manage(b.dataset.h)});
}

/* ---- managing a hook: this is where "delete and they are gone" lives ---- */
const FIELDS=['sender','subject','body'];
const ACTIONS=[['tag','tag it'],['important','mark it important'],['feed','send it to feed'],['ignore','ignore it']];

async function manage(hookWords){
  const h=STATE.hooks.find(x=>x.hook===hookWords); if(!h) return;
  const feed=STATE.feeds.find(f=>f.id===h.feed)||{};
  const url=location.origin+'/h/'+h.hook;
  const isPublic=h.kind==='public';

  show('<h3>'+esc(feed.name||h.label||'Hook')+'</h3>'+
    '<div class=k>'+esc(url)+'</div>'+
    '<p style="font-size:.85rem;color:var(--dim)">'+
      (isPublic
        ? 'Your public hook. It carries first contact only, so rotating it disturbs no conversation you have replied to.'
        : 'One sender. Delete it and they are gone for good — every other hook is untouched.')+
    '</p>'+

    '<p style="margin-top:1.2rem"><b>Arrives</b> '+
      '<select id=arr><option value=each'+(feed.arrive!=='daily'?' selected':'')+'>item by item</option>'+
      '<option value=daily'+(feed.arrive==='daily'?' selected':'')+'>once a day</option></select></p>'+

    '<p style="margin-top:1.2rem"><b>Rules</b><br><span style="color:var(--dim);font-size:.85rem">'+
      'Read top to bottom. The first match wins, so exactly one ever applies.</span></p>'+
    '<div id=rules></div>'+
    '<p><button id=addrule>Add a rule</button> <button id=saverules>Save rules</button></p>'+

    '<p style="margin-top:1.4rem;border-top:1px solid var(--line);padding-top:1rem">'+
      '<button id=retire>'+(isPublic?'Rotate':'Retire for 90 days')+'</button> '+
      '<button id=kill style="color:var(--accent)">Delete permanently</button></p>');

  let rules=(h.rules||[]).slice();
  const draw=()=>{
    $('#rules').innerHTML=rules.map((r,n)=>
      '<p style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">if '+
      '<select data-r="'+n+'" data-k=field>'+FIELDS.map(f=>'<option'+(r.field===f?' selected':'')+'>'+f+'</option>').join('')+'</select>'+
      ' contains <input data-r="'+n+'" data-k=value value="'+esc(r.value)+'" style="width:8rem">'+
      ' then <select data-r="'+n+'" data-k=action>'+ACTIONS.map(([v,l])=>'<option value="'+v+'"'+(r.then.action===v?' selected':'')+'>'+l+'</option>').join('')+'</select>'+
      '<input data-r="'+n+'" data-k=avalue value="'+esc(r.then.value||'')+'" style="width:6rem" placeholder="…">'+
      '<button data-del="'+n+'">×</button></p>').join('')||'<p style="color:var(--dim);font-size:.85rem">No rules.</p>';

    $('#rules').querySelectorAll('[data-r]').forEach(el=>el.onchange=el.oninput=()=>{
      const r=rules[el.dataset.r], k=el.dataset.k;
      if(k==='field') r.field=el.value;
      else if(k==='value') r.value=el.value;
      else if(k==='action') r.then.action=el.value;
      else r.then.value=el.value;
    });
    $('#rules').querySelectorAll('[data-del]').forEach(b=>b.onclick=()=>{rules.splice(b.dataset.del,1);draw()});
  };
  draw();

  $('#addrule').onclick=()=>{rules.push({field:'subject',op:'contains',value:'',then:{action:'tag',value:''}});draw()};
  $('#saverules').onclick=async()=>{
    await api('/api/hooks/'+encodeURIComponent(h.hook)+'/rules',{method:'POST',
      headers:{'content-type':'application/json'},body:JSON.stringify({rules})});
    h.rules=rules; $('#saverules').textContent='Saved';
  };

  $('#arr').onchange=async()=>{
    await api('/api/feeds/'+h.feed+'/arrive',{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({arrive:$('#arr').value})});
    await refresh();
  };

  $('#retire').onclick=async()=>{
    const r=await api('/api/hooks/'+encodeURIComponent(h.hook)+'/retire',{method:'POST',
      headers:{'content-type':'application/json'},body:JSON.stringify({days:90})});
    await refresh();
    if(r.replacement){ await publishContact();
      show('<h3>Rotated</h3><p>Your contact page now carries a new hook. Anyone holding the old one for the next ninety days still gets through, flagged — after that it is gone.</p><div class=k>'+
           esc(location.origin+'/h/'+r.replacement)+'</div>');
    } else show('<h3>Retiring</h3><p>It still accepts until '+esc((r.until||'').slice(0,10))+', flagged as an old hook. Then it is gone.</p>');
  };

  $('#kill').onclick=async()=>{
    if(!confirm('Delete this hook? Anything sent to it afterwards is refused, permanently. This cannot be undone.')) return;
    await api('/api/hooks/'+encodeURIComponent(h.hook),{method:'DELETE'});
    await refresh(); FEED=null;
    $('#list').innerHTML='<div class=empty>Deleted. That sender is gone for good.</div>';
    dlg.close();
  };
}

/* ---- settings: the keys are the account, so this is where they live ---- */
async function showMe(){
  $('#me').innerHTML='your fingerprint<br><span class=fp>'+esc(await C.fingerprint(ID.signPub))+'</span><br>'+
    '<a href="/c" target="_blank">contact page →</a> · <a href="#" id=settings>settings</a>';
  $('#settings').onclick=e=>{e.preventDefault();openSettings()};
}

async function openSettings(){
  const fp=await C.fingerprint(ID.signPub);
  show('<h3>Settings</h3>'+
    '<p>Your fingerprint. Read it to someone through another channel to check they have the right you.</p>'+
    '<div class=k>'+esc(fp)+'</div>'+
    '<p style="margin-top:1.4rem"><b>Back up your keys</b><br><span style="color:var(--dim);font-size:.85rem">'+
    'Wrapped under a passphrase before it leaves this device. Lose the keys and the account is gone — nothing on any server can bring it back.</span></p>'+
    '<p><input id=bpass type=password placeholder="passphrase" style="width:60%"> <button id=bdo>Download</button></p>'+
    '<p style="margin-top:1rem"><b>Restore</b><br><span style="color:var(--dim);font-size:.85rem">Replaces the keys on this device.</span></p>'+
    '<p><input id=rfile type=file accept="application/json" style="width:55%"> <input id=rpass type=password placeholder="passphrase" style="width:35%"> <button id=rdo>Restore</button></p>'+
    '<p style="margin-top:1rem"><b>Rotate your key</b><br><span style="color:var(--dim);font-size:.85rem">'+
    'Publishes a new key signed by the old one, so people who already trust you follow it. Anyone who has not seen the old key sees only the new one.</span></p>'+
    '<p><button id=rotdo>Rotate</button></p>');

  $('#bdo').onclick=async()=>{
    const pass=$('#bpass').value; if(pass.length<8) return alert('Use at least 8 characters.');
    const blob=await C.backup(ID,pass);
    const a=document.createElement('a');
    a.href=URL.createObjectURL(new Blob([JSON.stringify(blob,null,2)],{type:'application/json'}));
    a.download='posts-keys.json'; a.click();
  };

  $('#rdo').onclick=async()=>{
    const f=$('#rfile').files[0]; if(!f) return alert('Choose a backup file.');
    try{
      const restored=await C.restore(JSON.parse(await f.text()), $('#rpass').value);
      ID=restored; await put('identity',ID); await publishContact(); await showMe();
      dlg.close();
    }catch(e){ alert('Could not restore: '+e.message) }
  };

  $('#rotdo').onclick=async()=>{
    if(!confirm('Rotate your account key? Contacts who already trust the old one will follow it automatically.')) return;
    const next=await C.newKeys();
    const pub=STATE.hooks.find(h=>h.kind==='public'&&h.status==='active');
    const rec=await C.rotateContact(location.origin+'/h/'+pub.hook, next, ID);
    await fetch('/api/contact',{method:'PUT',headers:{authorization:'Bearer '+TOKEN},body:JSON.stringify(rec)});
    ID=next; await put('identity',ID); await showMe();
    dlg.close();
    show('<h3>Rotated</h3><p>Your new fingerprint:</p><div class=k>'+esc(await C.fingerprint(ID.signPub))+'</div>'+
         '<p style="font-size:.85rem;color:var(--dim)">Old messages still verify against the old key. New ones use this.</p>');
  };
}

/* ---- the bar: a filter over what is already decrypted, on this device ---- */
function terms(q){ return q.toLowerCase().split(/\s+/).filter(Boolean) }

function applyFilter(){
  const q=($('#filter')?.value||'').trim();
  const t=terms(q);
  const items=[...$('#list').querySelectorAll('.item')];

  // Sources: hide any whose name does not match, so the sidebar narrows too.
  $('#srcs').querySelectorAll('.src').forEach(el=>{
    const name=(el.textContent||'').toLowerCase();
    el.classList.toggle('hide', t.length>0 && !t.every(w=>name.includes(w)));
  });

  let shown=0;
  items.forEach((el,n)=>{
    const hay=SHOWN[n]||'';
    const hit=t.length===0||t.every(w=>hay.includes(w));
    el.classList.toggle('hide',!hit);
    if(hit) shown++;
  });

  if(t.length) highlight(t); else clearHighlight();
  $('#fcount').textContent = t.length ? shown+' of '+items.length : (items.length?items.length+' items':'');
}

function clearHighlight(){
  $('#list').querySelectorAll('mark').forEach(m=>m.replaceWith(document.createTextNode(m.textContent)));
}
function highlight(t){
  clearHighlight();
  const esc1=w=>w.replace(/[^a-z0-9\s]/gi,c=>'\\'+c);
  const rx=new RegExp('('+t.map(esc1).join('|')+')','gi');
  const walk=el=>{
    for(const node of [...el.childNodes]){
      if(node.nodeType===3){
        if(!rx.test(node.nodeValue)) continue;
        const span=document.createElement('span');
        span.innerHTML=esc(node.nodeValue).replace(rx,'<mark>$1</mark>');
        node.replaceWith(...span.childNodes);
      }else if(node.nodeType===1&&node.tagName!=='MARK'&&node.tagName!=='BUTTON') walk(node);
    }
  };
  $('#list').querySelectorAll('.item:not(.hide)').forEach(walk);
}

/* ---- attachments: encrypted here, uploaded as ciphertext ---- */
async function uploadFiles(files){
  const out=[];
  for(const f of files||[]){
    const {bytes,meta}=await C.sealBytes(new Uint8Array(await f.arrayBuffer()));
    const up=await fetch('/api/blobs',{method:'POST',headers:{authorization:'Bearer '+TOKEN},body:bytes});
    if(!up.ok){ alert(f.name+' is too large'); continue }
    const {url}=await up.json();
    // meta carries the file key — it only ever travels inside the sealed body.
    out.push({name:f.name,media_type:f.type||'application/octet-stream',url,...meta});
  }
  return out.length?out:undefined;
}

async function download(att){
  const ct=await fetch(att.url).then(r=>r.arrayBuffer());
  const plain=await C.openBytes(new Uint8Array(ct), att);   // checks the hash first
  const url=URL.createObjectURL(new Blob([plain],{type:att.media_type}));
  const a=document.createElement('a'); a.href=url; a.download=att.name||'attachment'; a.click();
  setTimeout(()=>URL.revokeObjectURL(url),5000);
}

/* ---- posting to a hook, healing a dead one (§5) ---- */
async function postTo(contact, envelope){
  const body=JSON.stringify(envelope);
  const send=url=>fetch(url,{method:'POST',headers:{'content-type':'application/json'},body});
  let r=await send(contact.hook);
  if(r.status!==410) return {r,contact};

  // Dead hook. Re-read their contact page; follow it only if the record is
  // still signed by the key we already trust.
  if(!contact.contact_url) return {r,contact,healed:false};
  try{
    const rec=await fetch(contact.contact_url,{cache:'no-store'}).then(x=>x.json());
    const res=await C.acceptContact(rec, contact.key);
    if(!res.ok) return {r,contact,healed:false,why:res.why};
    contact.hook=res.hook; contact.box=res.box||contact.box;
    CONTACTS[contact.key]=contact; await put('contacts',CONTACTS);
    r=await send(contact.hook);
    return {r,contact,healed:true};
  }catch(e){ return {r,contact,healed:false,why:e.message} }
}

/* ---- reading, decrypting as we go ---- */
async function openFeed(id){
  FEED=id; await refresh(); $('#compose').className='';
  const r=await api('/api/items?feed='+id);
  if(!r.items.length){ $('#list').innerHTML='<div class=empty>Nothing here yet.</div>'; return }
  const out=[], rows=[];
  for(const i of r.items){
    let body=i.body, subject=i.subject, lock='';
    if(i.enc){
      try{
        const envelope=JSON.parse(i.body);
        const pt=await C.open(envelope, ID);          // verifies, then decrypts
        body=pt.text||''; subject=pt.subject||subject; lock=' <span class=lock>decrypted</span>';
        if(envelope.type==='first_contact'&&envelope.reply_hook){
          PENDING[i.id]={hook:envelope.reply_hook,key:envelope.from_key,box:envelope.from_box};
          lock+=' <button data-reply="'+i.id+'">Reply</button>';
        }
        if(pt.attachments&&pt.attachments.length){
          ATTACH[i.id]=pt.attachments;
          body+='\\n'+pt.attachments.map((a,n)=>'📎 '+a.name+' ('+Math.round((a.size||0)/1024)+' KB)').join('\\n');
          lock+=' '+pt.attachments.map((a,n)=>'<button data-att="'+i.id+':'+n+'">Save '+esc(a.name)+'</button>').join(' ');
        }
        if(envelope.grant){
          const got=await C.acceptGrant(envelope.grant, envelope.from_key);
          if(got){ await adoptGrant(envelope.from_key, got); lock+=' <span class=lock>private hook received</span>' }
        }
      }catch(e){ body='['+e.message+']'; lock=' <span class=lock>encrypted</span>' }
    }
    rows.push((subject+' '+(i.sender||'')+' '+(i.feed_name||'')+' '+body).toLowerCase());
    out.push('<div class=item><h3>'+esc(subject||'(no subject)')+'</h3><div class=meta>'+esc(i.sender||'')+
      ' · '+esc(i.created.slice(0,16).replace('T',' '))+(i.flags?' · '+esc(i.flags):'')+lock+
      (i.feed_name&&FEED==='*'?' · '+esc(i.feed_name):'')+'</div><pre>'+esc(body).slice(0,6000)+'</pre></div>');
  }
  SHOWN=rows;
  $('#list').innerHTML=out.join('');
  applyFilter();
  $('#list').querySelectorAll('[data-reply]').forEach(b=>b.onclick=()=>startConversation(b.dataset.reply));
  $('#list').querySelectorAll('[data-att]').forEach(b=>b.onclick=async()=>{
    const [id,n]=b.dataset.att.split(':');
    b.disabled=true; b.textContent='…';
    try{ await download(ATTACH[id][n]); b.textContent='Saved' }
    catch(e){ b.textContent=e.message }   // a hash mismatch must be visible
  });
}

/* ---- replying: mint them a hook and move the thread off the public one ---- */
async function startConversation(itemId){
  const them=PENDING[itemId]; if(!them) return;
  const petname=prompt('Name this contact'); if(!petname) return;

  const conv=await api('/api/conversations',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({their_hook:them.hook,their_key:them.key,petname})});

  const keys=(await get('convkeys'))||{};
  keys[conv.id]=keys[conv.id]||await C.newKeys();
  await put('convkeys',keys);

  CONTACTS[them.key]={petname,key:them.key,box:them.box,hook:them.hook,conversation:conv.id,
                      fingerprint:await C.fingerprint(them.key)};
  await put('contacts',CONTACTS);

  const grant=await C.grantHook(conv.my_hook_url, conv.id, keys[conv.id]);
  const body=prompt('Reply to '+petname)||'';
  const env=await C.seal({text:body}, them.box, keys[conv.id], {grant, conversation:conv.id});
  const {r,healed}=await postTo(CONTACTS[them.key], env);

  await refresh();
  show('<h3>'+esc(petname)+'</h3><p>They now have a hook of their own — this thread has left your public hook. Delete it and they are gone for good.</p><div class=k>'+
       esc(conv.my_hook_url)+'</div><p style="font-size:.85rem;color:var(--dim)">reply sent: '+esc(r.status)+(healed?' (their hook had moved; followed it)':'')+'</p>');
}

/* ---- a grant arriving from the other side ---- */
async function adoptGrant(theirKey, hookUrl){
  const c=CONTACTS[theirKey]; if(!c||c.hook===hookUrl) return;
  c.hook=hookUrl; CONTACTS[theirKey]=c; await put('contacts',CONTACTS);
}

/* ---- adding: a feed URL, or someone's contact page ---- */
async function add(){
  const v=$('#addurl').value.trim(); if(!v) return;
  $('#addurl').value='';
  const guess=v.replace(/\/$/,'')+(/contact\.json$/.test(v)?'':'/contact.json');
  try{
    const rec=await fetch(guess).then(r=>r.ok?r.json():null);
    if(rec&&rec.hook&&rec.key){
      const known=CONTACTS[rec.key];
      const res=await C.acceptContact(rec, known?known.key:null);
      if(!res.ok){ show('<h3>Refused</h3><p>'+esc(res.why)+'. The record is not signed by the key this contact already had, so it is not followed.</p>'); return }
      const petname=prompt('Name this contact', known?known.petname:'someone');
      if(!petname) return;
      CONTACTS[rec.key]={petname,key:rec.key,box:rec.box,hook:rec.hook,contact_url:guess,fingerprint:rec.fingerprint};
      await put('contacts',CONTACTS); await refresh();
      show('<h3>'+esc(petname)+'</h3><p>Check this fingerprint with them through another channel.</p><div class=k>'+esc(rec.fingerprint)+'</div>');
      return;
    }
  }catch(e){}
  await api('/api/sources',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({url:v})});
  await refresh();
}

/* ---- writing to a contact ---- */
function composeTo(key){
  const c=CONTACTS[key]; FEED=null;
  $('#list').innerHTML='<div class=empty>Writing to '+esc(c.petname)+'.<br><span class=fp>'+esc(c.fingerprint)+'</span></div>';
  $('#compose').className='on';
  $('#compose').innerHTML='<input id=subj placeholder="subject" style="max-width:10rem"><textarea id=msg rows=1 placeholder="message"></textarea><input type=file id=file style="flex:0 0 auto;max-width:9rem"><button class=p id=send>Send</button>';
  $('#send').onclick=async()=>{
    const attachments=await uploadFiles($('#file').files);
    const keys=(await get('convkeys'))||{};
    let env;
    if(c.conversation && keys[c.conversation]){
      // An established thread: seal with its key, no reply hook needed.
      env=await C.seal({subject:$('#subj').value,text:$('#msg').value,attachments}, c.box, keys[c.conversation], {conversation:c.conversation});
    }else{
      const conv=await C.newKeys();                     // fresh key: unlinkable
      const mine=STATE.hooks.find(h=>h.kind==='public'&&h.status==='active');
      env=await C.firstContact({subject:$('#subj').value,text:$('#msg').value,attachments}, c.box, conv,
                               location.origin+'/h/'+mine.hook);
    }
    const {r,healed,why}=await postTo(c, env);
    if(r.status===410){
      $('#list').innerHTML='<div class=empty>Their hook is gone'+(why?' — '+esc(why):'')+'.<br>Nothing was delivered.</div>';
      return;
    }
    $('#msg').value=''; $('#subj').value=''; $('#file').value='';
    $('#list').innerHTML='<div class=empty>Sent'+(healed?' — their hook had moved, followed it':'')+'.</div>';
  };
}

/* ---- hooks ---- */
async function mint(){
  const label=prompt('What is this hook for?'); if(!label) return;
  const r=await api('/api/hooks',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({label})});
  show('<h3>'+esc(label)+'</h3><p>Give this to exactly one sender. Delete it and they are gone for good.</p><div class=k>'+esc(r.url)+'</div>');
  await refresh();
}

$('#filter').addEventListener('input',applyFilter);
$('#filter').addEventListener('keydown',e=>{ if(e.key==='Escape'){ e.target.value=''; applyFilter() } });
window.add=add; window.mint=mint; window.manage=manage;
boot();
