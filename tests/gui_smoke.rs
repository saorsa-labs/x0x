//! GUI smoke tests.
//!
//! Verifies the embedded HTML GUI serves correctly and calls only
//! endpoints that exist in the ENDPOINTS registry.
//!
//! Run with: cargo nextest run --test gui_smoke -- --ignored

use std::collections::HashSet;
use x0x::api::ENDPOINTS;

/// Verify the GUI HTML file contains expected content.
#[test]
fn gui_html_contains_brand() {
    let html = include_str!("../src/gui/x0x-gui.html");
    assert!(
        html.contains("x0x"),
        "GUI HTML should contain the brand name 'x0x'"
    );
}

/// Verify the GUI HTML is valid (starts with doctype or html tag).
#[test]
fn gui_html_is_valid() {
    let html = include_str!("../src/gui/x0x-gui.html");
    let lower = html.trim().to_lowercase();
    assert!(
        lower.starts_with("<!doctype") || lower.starts_with("<html"),
        "GUI HTML should start with <!DOCTYPE or <html"
    );
}

/// Verify the GUI direct-send composer exposes the require_ack toggle.
///
/// Closes the historical parity gap `Send + receive-ACK / GUI` by proving
/// the composer (a) renders the checkbox and (b) wires it to
/// `require_ack_ms` on the `/direct/send` body.
#[test]
fn gui_dm_composer_exposes_require_ack_toggle() {
    let html = include_str!("../src/gui/x0x-gui.html");
    assert!(
        html.contains(r#"id="dm-require-ack""#),
        "DM composer should include the require_ack checkbox (id=dm-require-ack)"
    );
    assert!(
        html.contains("require_ack_ms"),
        "sendDm() must include `require_ack_ms` in the /direct/send body when checked"
    );
}

/// Verify the embedded Files app requires an explicit recipient selection.
///
/// This prevents a privacy/safety regression where file sends silently target
/// the first contact in the address book.
#[test]
fn gui_files_requires_explicit_recipient_selection() {
    let html = include_str!("../src/gui/x0x-gui.html");
    assert!(
        html.contains(r#"id="file-recipient""#),
        "Files app should expose an explicit recipient select"
    );
    assert!(
        html.contains("selectedFileRecipient()"),
        "Files send path should read the selected recipient"
    );
    assert!(
        html.contains("Select a recipient before sending files"),
        "Files app should warn before sending without a recipient"
    );
    assert!(
        !html.contains("contacts[0].agent_id"),
        "Files app must not auto-send to the first contact"
    );
}

/// Verify named-group roster role controls can both promote and demote.
#[test]
fn gui_named_group_roster_exposes_demote_role_binding() {
    let html = include_str!("../src/gui/x0x-gui.html");
    assert!(
        html.contains("Demote to member"),
        "Roster actions should expose a Demote to member control"
    );
    assert!(
        html.contains(r#"data-nag-role="admin""#),
        "Promote control should carry desired admin role"
    );
    assert!(
        html.contains(r#"data-nag-role="member""#),
        "Demote control should carry desired member role"
    );
    assert!(
        html.contains("data-nag-role-agent"),
        "Role controls should carry a separate target agent id"
    );
    let compact = compact_html(html);
    assert!(
        compact.contains(
            "nagSetRole(gid,btn.getAttribute('data-nag-role-agent'),btn.getAttribute('data-nag-role'))"
        ),
        "Role binding should pass target id and desired role from button attributes"
    );
    assert!(
        !compact.contains("getAttribute('data-nag-role'),'admin'"),
        "Role binding must not hard-code all role changes to admin"
    );
}

/// Verify named-group roster management controls are hidden on the caller row.
#[test]
fn gui_named_group_roster_hides_self_management_actions() {
    let html = include_str!("../src/gui/x0x-gui.html");
    let compact = compact_html(html);
    assert!(
        compact.contains("constisSelf=m.agent_id===myAid;"),
        "Roster renderer should identify the caller's own row"
    );
    assert!(
        compact.contains("constmanage=canManage&&!isSelf;"),
        "Ban/Promote/Demote/Unban actions should be disabled for the caller's own row"
    );
}

/// Verify that API paths called from the GUI exist in ENDPOINTS.
///
/// Extracts `api("/path"...)` calls from the JavaScript and checks each
/// against the ENDPOINTS registry. This catches the GUI calling endpoints
/// that were removed or renamed.
#[test]
fn gui_api_paths_exist_in_registry() {
    let html = include_str!("../src/gui/x0x-gui.html");
    let endpoint_paths: HashSet<&str> = ENDPOINTS.iter().map(|e| e.path).collect();

    let unmatched = unmatched_gui_api_paths(html, &endpoint_paths);

    assert!(
        unmatched.is_empty(),
        "\nGUI calls {} API paths not found in ENDPOINTS:\n  {}",
        unmatched.len(),
        unmatched.join("\n  ")
    );
}

/// Verify the GUI HTML has a reasonable size (not empty, not truncated).
#[test]
fn gui_html_reasonable_size() {
    let html = include_str!("../src/gui/x0x-gui.html");
    assert!(
        html.len() > 1000,
        "GUI HTML is suspiciously small ({} bytes)",
        html.len()
    );
    assert!(
        html.len() < 500_000,
        "GUI HTML is suspiciously large ({} bytes)",
        html.len()
    );
}

/// Verify the GUI HTML contains key UI elements.
#[test]
fn gui_has_key_elements() {
    let html = include_str!("../src/gui/x0x-gui.html");

    // Should have a script section (it's a single-page app)
    assert!(html.contains("<script"), "GUI should contain <script> tags");

    // Should have a style section
    assert!(
        html.contains("<style") || html.contains("style="),
        "GUI should contain styles"
    );

    // Should reference the API somehow
    assert!(
        html.contains("api(") || html.contains("fetch("),
        "GUI should make API calls"
    );
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn unmatched_gui_api_paths(html: &str, endpoint_paths: &HashSet<&str>) -> Vec<String> {
    let mut unmatched = Vec::new();

    for path in extract_gui_api_paths(html) {
        if !endpoint_paths.contains(path.as_str()) && !matches_parameterized(&path, endpoint_paths)
        {
            unmatched.push(path);
        }
    }

    unmatched.sort();
    unmatched.dedup();
    unmatched
}

fn compact_html(html: &str) -> String {
    html.split_whitespace().collect()
}

fn extract_gui_api_paths(html: &str) -> Vec<String> {
    let mut gui_paths = Vec::new();

    for line in html.lines() {
        let trimmed = line.trim();
        let mut search_from = 0;
        while let Some(pos) = trimmed[search_from..].find("api(") {
            let start = search_from + pos + "api(".len();
            if let Some(path) = extract_path(&trimmed[start..]) {
                if path.starts_with('/') {
                    gui_paths.push(path);
                }
            }
            search_from = start;
        }
    }

    gui_paths
}

fn extract_path(s: &str) -> Option<String> {
    let arg = first_api_arg(s)?;
    Some(normalize_path(arg))
}

fn first_api_arg(args: &str) -> Option<&str> {
    let bytes = args.as_bytes();
    let mut depth = 0usize;
    let mut in_str: Option<u8> = None;
    let mut i = 0usize;

    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
        } else {
            match c {
                b'\'' | b'"' | b'`' => in_str = Some(c),
                b'(' | b'{' | b'[' => depth += 1,
                b')' if depth == 0 => return Some(args[..i].trim()),
                b')' | b'}' | b']' => depth = depth.saturating_sub(1),
                b',' if depth == 0 => return Some(args[..i].trim()),
                _ => {}
            }
        }
        i += 1;
    }

    let arg = args.trim();
    if arg.is_empty() {
        None
    } else {
        Some(arg)
    }
}

fn normalize_path(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut normalized = String::new();
    let mut i = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' => i = append_quoted_literal(path, i, &mut normalized),
            b'`' => i = append_template_literal(path, i, &mut normalized),
            b'+' | b' ' | b'\n' | b'\r' | b'\t' => i += 1,
            _ => {
                normalized.push_str(":id");
                i = skip_dynamic_operand(bytes, i);
            }
        }
    }

    if let Some(index) = normalized.find('?') {
        normalized.truncate(index);
    }
    normalized
}

fn append_quoted_literal(expr: &str, start: usize, normalized: &mut String) -> usize {
    let bytes = expr.as_bytes();
    let quote = bytes[start];
    let mut i = start + 1;

    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' {
            if let Some(next) = bytes.get(i + 1) {
                normalized.push(*next as char);
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if c == quote {
            return i + 1;
        }
        if c == b'$' && bytes.get(i + 1) == Some(&b'{') {
            normalized.push_str(":id");
            i = skip_template_placeholder(bytes, i + 2);
            continue;
        }
        normalized.push(c as char);
        i += 1;
    }

    i
}

fn append_template_literal(expr: &str, start: usize, normalized: &mut String) -> usize {
    let bytes = expr.as_bytes();
    let mut i = start + 1;

    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                if let Some(next) = bytes.get(i + 1) {
                    normalized.push(*next as char);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            b'`' => return i + 1,
            b'$' if bytes.get(i + 1) == Some(&b'{') => {
                normalized.push_str(":id");
                i = skip_template_placeholder(bytes, i + 2);
            }
            c => {
                normalized.push(c as char);
                i += 1;
            }
        }
    }

    i
}

fn skip_dynamic_operand(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0usize;
    let mut in_str: Option<u8> = None;
    let mut i = start;

    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
        } else {
            match c {
                b'\'' | b'"' | b'`' => in_str = Some(c),
                b'(' | b'{' | b'[' => depth += 1,
                b')' | b'}' | b']' => depth = depth.saturating_sub(1),
                b'+' if depth == 0 => return i,
                _ => {}
            }
        }
        i += 1;
    }

    i
}

fn skip_template_placeholder(bytes: &[u8], start: usize) -> usize {
    let mut depth = 1usize;
    let mut in_str: Option<u8> = None;
    let mut i = start;

    while i < bytes.len() && depth > 0 {
        let c = bytes[i];
        if let Some(q) = in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
        } else {
            match c {
                b'\'' | b'"' | b'`' => in_str = Some(c),
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
        }
        i += 1;
    }

    i
}

fn matches_parameterized(path: &str, endpoints: &HashSet<&str>) -> bool {
    let path_parts: Vec<&str> = path.split('/').collect();
    for ep_path in endpoints {
        let ep_parts: Vec<&str> = ep_path.split('/').collect();
        if path_parts.len() == ep_parts.len() {
            let matches = path_parts
                .iter()
                .zip(ep_parts.iter())
                .all(|(p, e)| e.starts_with(':') || p == e);
            if matches {
                return true;
            }
        }
    }
    false
}

#[test]
fn gui_api_path_checker_rejects_unknown_literal_path() {
    let endpoint_paths: HashSet<&str> = ["/health"].into_iter().collect();

    assert_eq!(
        unmatched_gui_api_paths(
            "api('/health'); api('/definitely-missing');",
            &endpoint_paths
        ),
        vec![String::from("/definitely-missing")]
    );
}

#[test]
fn gui_api_path_checker_accepts_concatenated_parameterized_paths() {
    let endpoint_paths: HashSet<&str> = ["/stores/:id/:key", "/agent/card"].into_iter().collect();
    let html = r#"
        api('/stores/'+storeId+'/channels_index');
        api('/agent/card?display_name='+encodeURIComponent(name)+'&include_groups=true');
    "#;

    assert!(
        unmatched_gui_api_paths(html, &endpoint_paths).is_empty(),
        "concatenated and query-bearing GUI paths should normalize to registered endpoints"
    );
}

/// Exercise the actual owner API helper with offline HTTP and tab-storage fakes.
/// Bounds auth recovery without retrying successful mutations or other failures.
#[test]
fn gui_owner_token_recovery_is_bounded() {
    let output = std::process::Command::new("node")
        .arg("-e")
        .arg(r#"const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const html=fs.readFileSync(process.env.X0X_GUI_HTML_PATH,'utf8');
const start=html.indexOf('function readOwnerToken()');
const end=html.indexOf('const DEFAULT_SYMPHONY_DAEMON_URL=',start);
assert(start>=0&&end>start,'owner API helper section exists');
const source=html.slice(start,end);
const ok={status:200,data:{ok:true}};
const unauthorized={status:401,data:{ok:false,error:'invalid bearer'}};
const durable={status:403,data:{ok:false,error:'requires the durable API token'}};
const denied={status:403,data:{ok:false,error:'blocked'}};
const cases=[
 {name:'valid saved owner',owner:'owner',responses:[ok],tokens:['owner'],saved:'owner'},
 {name:'ordinary session',responses:[ok],tokens:['session']},
 {name:'rejected owner falls back to session',owner:'stale',responses:[unauthorized,ok],tokens:['stale','session']},
 {name:'rejected owner prompts once when durable required',owner:'stale',responses:[unauthorized,durable,ok],answers:[' fresh '],tokens:['stale','session','fresh'],saved:'fresh'},
 {name:'rejected prompted token is forgotten',responses:[durable,unauthorized],answers:['wrong'],tokens:['session','wrong'],status:401},
 {name:'cancel after rejected owner',owner:'stale',responses:[unauthorized,durable],answers:[null],tokens:['stale','session'],status:403},
 {name:'blank after rejected owner',owner:'stale',responses:[unauthorized,durable],answers:['  '],tokens:['stale','session'],status:403},
 {name:'generic forbidden is not retried',owner:'owner',responses:[denied],tokens:['owner'],saved:'owner',status:403},
 {name:'network failure is not retried',owner:'owner',responses:[{networkError:true}],tokens:['owner'],saved:'owner',status:null},
 {name:'server failure is not retried',owner:'owner',responses:[{status:500,data:{ok:false}}],tokens:['owner'],saved:'owner',status:500},
 {name:'invalid session does not prompt',responses:[unauthorized],tokens:['session'],status:401},
 {name:'newer owner survives stale response',owner:'stale',responses:[{...unauthorized,install:'newer'},ok],tokens:['stale','session'],saved:'newer'},
 {name:'newer owner survives rejected prompt response',responses:[durable,{...unauthorized,install:'newer'}],answers:['wrong'],tokens:['session','wrong'],saved:'newer',status:401},
 {name:'unavailable sessionStorage does not break prompt',responses:[durable,ok],answers:['fresh'],tokens:['session','fresh'],saved:'fresh',storageThrows:true},
 {name:'prompted token network failure does not retry',responses:[durable,{networkError:true}],answers:['fresh'],tokens:['session','fresh'],saved:'fresh',status:null},
 {name:'rejected fallback session stops',owner:'stale',responses:[unauthorized,unauthorized],tokens:['stale','session'],status:401},
 {name:'successful HTTP refusal does not retry',owner:'owner',responses:[{status:200,data:{ok:false,error:'not applied'}}],tokens:['owner'],saved:'owner'},
];
(async()=>{
 let failed=0;
 for(const c of cases){
  try{
   const stored=new Map(c.owner?[['x0x_owner_token',c.owner]]:[]);
   const calls=[],prompts=[];
   let context;
   const storage={
    getItem(k){if(c.storageThrows)throw Error('storage unavailable');return stored.get(k)||null},
    setItem(k,v){if(c.storageThrows)throw Error('storage unavailable');stored.set(k,v)},
    removeItem(k){if(c.storageThrows)throw Error('storage unavailable');stored.delete(k)},
   };
   context=vm.createContext({SESSION_TOKEN:'session',BASE:'http://127.0.0.1:12700',sessionStorage:storage,
    prompt(message){prompts.push(message);assert(prompts.length<2,'at most one prompt');return(c.answers||[])[prompts.length-1]},
    async fetch(url,opt){
     const i=calls.length;calls.push({url,opt});
     assert(i<c.responses.length,'no unexpected retry');
     const response=c.responses[i];
     if(response.install){context.installedOwner=response.install;vm.runInContext('OWNER_TOKEN=installedOwner',context);stored.set('x0x_owner_token',response.install)}
     if(response.networkError)throw Error('offline');
     return{status:response.status,ok:response.status>=200&&response.status<300,json:async()=>({...response.data})};
    }
   });
   vm.runInContext(source,context);
   const result=await vm.runInContext('ownerApi("/owner-action",{method:"POST",body:"requested-change"})',context);
   assert.deepEqual(calls.map(x=>x.opt.headers.Authorization?.replace('Bearer ','')),c.tokens,'bearers and bounded request count');
   assert.equal(prompts.length,(c.answers||[]).length,'prompt count');
   assert.equal(vm.runInContext('OWNER_TOKEN',context),c.saved||'','in-memory token');
   if(!c.storageThrows)assert.equal(stored.get('x0x_owner_token')||'',c.saved||'','tab token');
   assert.equal(result?result._http_status:null,c.status===undefined?200:c.status,'final status');
   for(const call of calls){assert.equal(call.url,'http://127.0.0.1:12700/owner-action');assert.equal(call.opt.method,'POST');assert.equal(call.opt.body,'requested-change')}
   console.log('PASS '+c.name);
  }catch(error){failed++;console.error('FAIL '+c.name+': '+error.message)}
 }
 console.log((cases.length-failed)+' passed; '+failed+' failed');
 process.exitCode=failed?1:0;
})();
"#)
        .env(
            "X0X_GUI_HTML_PATH",
            concat!(env!("CARGO_MANIFEST_DIR"), "/src/gui/x0x-gui.html"),
        )
        .output()
        .expect("Node is required for the offline GUI behavior check");
    assert!(
        output.status.success(),
        "owner-token behavior check failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn gui_spaces_community_hardening_invariants() {
    let html = include_str!("../src/gui/x0x-gui.html");
    // P0 XSS: Space description and DM contact label are HTML-escaped.
    assert!(
        html.contains("${esc(g.description||'No description')}"),
        "Space detail must escape g.description"
    );
    assert!(
        html.contains("esc(c.label||short(c.agent_id))"),
        "Sidebar DM list must escape c.label"
    );
    // P0 Invite reuse: never cache single-use invites across clicks.
    assert!(
        !html.contains("savedInvites"),
        "GUI must not cache single-use invites in savedInvites"
    );
    assert!(
        html.contains("copySpaceCard("),
        "Space detail should expose reusable Copy Group Card for discoverable spaces"
    );
    // P0 Destructive delete requires confirmation.
    let withdraw_start = html
        .find("async function nagWithdrawState(")
        .expect("nagWithdrawState exists");
    let withdraw_snippet = &html[withdraw_start..withdraw_start + 300];
    assert!(
        withdraw_snippet.contains("confirm("),
        "nagWithdrawState must require explicit user confirmation"
    );
    // P0 Private chat encrypts/decrypts via /groups/:id/secure/{encrypt,decrypt} and verifies edit/delete authors.
    assert!(
        html.contains("publishSpaceGossip(") && html.contains("decryptSpaceGossip("),
        "Private space gossip must encrypt and decrypt through the group secure plane"
    );
    let edit_start = html
        .find("function applyRemoteEdit(")
        .expect("applyRemoteEdit exists");
    assert!(
        html[edit_start..edit_start + 260].contains("msg.sender_id!==senderId"),
        "applyRemoteEdit must enforce sender ownership"
    );
    let del_start = html
        .find("function applyRemoteDelete(")
        .expect("applyRemoteDelete exists");
    assert!(
        html[del_start..del_start + 260].contains("msg.sender_id!==senderId"),
        "applyRemoteDelete must enforce sender ownership"
    );
    // P1 SignedPublic pagination, thread_root sends, and admin_only composer guard.
    assert!(
        html.contains("loadOlderSignedPublicMessages("),
        "SignedPublic chat must support loading older messages"
    );
    assert!(
        html.contains("Announcement space — only admins can post."),
        "SignedPublic admin_only spaces must gate the composer for non-admins"
    );
    // P2 Space apps: Feed uses group store, Web sandbox is empty, Discover supports open-join.
    assert!(
        html.contains("openSpacePageStore(sid,'feed')"),
        "Space Feed must use the policy-bound group store"
    );
    assert!(
        html.contains("iframe.setAttribute('sandbox','')"),
        "Web preview iframe must use a strict empty sandbox"
    );
    assert!(
        html.contains("data-nag-open-join"),
        "Discover cards must wire OpenJoin admission"
    );
    assert!(
        html.contains("data-nag-roster-search") && html.contains("data-nag-roster-filter"),
        "Manage roster must provide search and role/state filtering for large communities"
    );
    // Review hardening: reaction emoji XSS escape, escJs double-quote safety,
    // scoped roster listener binding, and fail-closed isEncryptedSpace.
    assert!(
        html.contains("esc(emoji)"),
        "Reaction emoji must be HTML-escaped before insertion into innerHTML"
    );
    assert!(
        html.contains("isSafeReactionEmoji(") && html.contains("isSafeRemoteId("),
        "Remote reaction emoji and message IDs must be validated before storage/rendering"
    );
    assert!(
        html.contains(r#".replace(/"/g,'\\u0022')"#),
        "escJs must encode double quotes as \\u0022 to prevent HTML attribute breakout"
    );
    assert!(
        html.contains("function nagBindRosterHandlers(panel,gid)"),
        "Roster re-renders must bind only the replaced roster panel, never host-wide admin buttons"
    );
    assert!(
        html.contains("function isCanonicalMsgId(id)")
            && html.contains("function upgradeSignedPublicMsgId(")
            && html.contains("function scheduleSignedPublicBackfill("),
        "SignedPublic live messages must gate Thread on canonical 64-hex msg_id and upgrade via REST backfill"
    );
    assert!(
        html.contains("chatHistory[chatKey]._pagedOlder=true"),
        "Backward pagination past 1,000 messages must preserve both older pages and the live tail"
    );
    assert!(
        html.contains("api('/groups/'+encSeg(data.groupId)+'/join-status')"),
        "Space detail join-status path must encode groupId"
    );
}

/// Offline Node behavior test for SignedPublic live msg_id upgrade, backward
/// pagination past 1,000 entries, and exhausted-history cursor preservation.
#[test]
fn gui_signed_public_live_msg_id_upgrade_and_backward_pagination_behavior() {
    let output = std::process::Command::new("node")
        .arg("-e")
        .arg(r#"const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const html=fs.readFileSync(process.env.X0X_GUI_HTML_PATH,'utf8');
const start=html.indexOf('let signedPublicPollTimer=null;');
const end=html.indexOf('// --- Space: Board ---',start);
assert(start>=0&&end>start,'SignedPublic chat section exists');
const source=html.slice(start,end);

function makeElem(tag){
  const el={
    tagName:tag.toUpperCase(),
    id:'',
    className:'',
    innerHTML:'',
    children:[],
    parentNode:null,
    scrollHeight:100,
    scrollTop:0,
    appendChild(child){child.parentNode=this;this.children.push(child);return child},
    replaceWith(next){
      if(!this.parentNode)return;
      const idx=this.parentNode.children.indexOf(this);
      if(idx>=0){next.parentNode=this.parentNode;this.parentNode.children[idx]=next}
    },
    get firstChild(){return this.children[0]||null},
  };
  return el;
}

(async()=>{
  const stateMap=new Map([['agentId','aa'.repeat(32)],['view','space'],['spaceId','g1'],['spaceApp','chat']]);
  const chatMsgsEl=makeElem('div');
  chatMsgsEl.id='chat-msgs';
  const lsStore=new Map();
  let apiQueue=[];
  const ctx=vm.createContext({
    S:{get:k=>stateMap.get(k),set:(k,v)=>stateMap.set(k,v)},
    LS:{get:(k,d)=>lsStore.has(k)?lsStore.get(k):d,set:(k,v)=>lsStore.set(k,v)},
    currentSpaceConfidentiality:'signed_public',
    signedPublicPagination:{},
    chatHistory:{},
    msgCache:{},
    threadReplies:{},
    threadCache:{},
    deletedMsgs:{},
    editedMsgs:{},
    EMOJI_QUICK:['👍'],
    encSeg:s=>encodeURIComponent(String(s)),
    esc:s=>String(s),
    escJs:s=>String(s),
    renderMd:s=>String(s),
    fmtTime:()=>'12:00',
    short:s=>String(s).slice(0,8),
    getContactTrust:()=>'',
    getReactions:()=>({}),
    isSafeReactionEmoji:()=>true,
    resolveSpaceSenderName:(_sid,aid)=>aid.slice(0,8),
    getChatKeyFromContext:()=>'g1_general',
    cacheMsg(m){if(m&&m.id)ctx.msgCache[m.id]=m},
    updateLoadOlderBar(){},
    renderSidebar(){},
    toast(msg){throw new Error('unexpected toast: '+msg)},
    apiError:r=>(r&&r.error)||'err',
    setTimeout,clearTimeout,
    document:{
      createElement:makeElem,
      getElementById(id){
        if(id==='chat-msgs')return chatMsgsEl;
        return chatMsgsEl.children.find(c=>c.id===id)||null;
      },
    },
    async api(path){
      assert(apiQueue.length>0,'unexpected api call: '+path);
      return apiQueue.shift()(path);
    },
  });
  vm.runInContext(source,ctx);
  const {signedPublicSeen,signedPublicIdByKey}=vm.runInContext('({signedPublicSeen,signedPublicIdByKey})',ctx);

  // 1. WS message arrives without msg_id: gets temporary colon id and NO Thread button.
  const rawWs={author_agent_id:'bb'.repeat(32),timestamp:5000,signature:'abcdef1234567890',body:'hello live'};
  const normWs=ctx.normalizeSignedPublicMsg('g1',rawWs);
  assert(!ctx.isCanonicalMsgId(normWs.msg.id),'WS fallback id is not 64-hex');
  signedPublicSeen.add(normWs.dedupKey);
  signedPublicIdByKey.set(normWs.dedupKey,normWs.msg.id);
  ctx.addChatMsg('g1_general',normWs.msg);
  assert.equal(chatMsgsEl.children.length,1);
  assert(!chatMsgsEl.children[0].innerHTML.includes('openThreadById'),'Thread button hidden before canonical msg_id');

  // 2. REST poll returns the same message with canonical 64-hex msg_id: upgrades in place.
  const canonicalId='0123456789abcdef'.repeat(4);
  apiQueue.push(()=>({ok:true,messages:[{...rawWs,msg_id:canonicalId}],has_more:false,next_before:null}));
  await ctx.signedPublicPoll('g1',true);
  assert.equal(ctx.chatHistory['g1_general'][0].id,canonicalId,'chatHistory id upgraded');
  assert.equal(ctx.msgCache[canonicalId].text,'hello live','msgCache upgraded');
  assert.equal(chatMsgsEl.children[0].id,'msg-'+canonicalId,'DOM id upgraded');
  assert(chatMsgsEl.children[0].innerHTML.includes("openThreadById('g1','"+canonicalId+"')"),'Thread button enabled with canonical 64-hex id');

  // 3. Backward pagination past 1,000 entries preserves both the newly loaded older page AND the live tail + LS cache.
  ctx.chatHistory['g1_general']=Array.from({length:1000},(_,i)=>({
    id:String(i+1000).padStart(64,'0'),
    text:'recent-'+i,
    sender_id:'bb'.repeat(32),
    sender_name:'bob',
    timestamp:20000+i,
    signed_public:true,
  }));
  ctx.signedPublicPagination['g1']={hasMore:true,nextBefore:20000,loading:false,exhausted:false};
  const olderId='fedcba9876543210'.repeat(4);
  apiQueue.push(path=>{
    assert(path.includes('before=20000'),'requests cursor 20000');
    return {ok:true,messages:[{author_agent_id:'cc'.repeat(32),timestamp:1000,signature:'oldsig123456',body:'very-old',msg_id:olderId}],has_more:false,next_before:null};
  });
  await ctx.loadOlderSignedPublicMessages('g1');
  assert.equal(ctx.chatHistory['g1_general'].length,1001,'grows past 1000 without dropping live tail');
  assert.equal(ctx.chatHistory['g1_general'][0].id,olderId,'older page kept at index 0');
  assert.equal(ctx.chatHistory['g1_general'][1000].text,'recent-999','live tail preserved');
  assert.equal(lsStore.get('chat_g1_general').length,200,'LS keeps 200 newest');
  assert.equal(lsStore.get('chat_g1_general')[199].text,'recent-999','LS tail stays newest message');
  assert.equal(ctx.signedPublicPagination['g1'].hasMore,false,'hasMore cleared');
  assert.equal(ctx.signedPublicPagination['g1'].exhausted,true,'marked exhausted');

  // 4. Live message arriving after backward pagination appends without evicting older page or corrupting LS.
  const liveAfterId='abcdef0123456789'.repeat(4);
  ctx.addChatMsg('g1_general',{id:liveAfterId,text:'brand-new',sender_id:'dd'.repeat(32),sender_name:'dave',timestamp:99999,signed_public:true});
  assert.equal(ctx.chatHistory['g1_general'].length,1002,'live message appended');
  assert.equal(ctx.chatHistory['g1_general'][0].id,olderId,'older page still present after live message');
  assert.equal(ctx.chatHistory['g1_general'][1001].id,liveAfterId,'live message at tail');
  assert.equal(lsStore.get('chat_g1_general')[199].id,liveAfterId,'LS tail updated to newest live message');

  // 5. Subsequent poll must NOT resurrect hasMore after history is exhausted.
  apiQueue.push(()=>({ok:true,messages:[],has_more:true,next_before:15000}));
  await ctx.signedPublicPoll('g1',false);
  assert.equal(ctx.signedPublicPagination['g1'].hasMore,false,'exhausted stays false across polls');
  console.log('ALL SIGNED PUBLIC GUI CHECKS PASSED');
})();
"#)
        .env(
            "X0X_GUI_HTML_PATH",
            concat!(env!("CARGO_MANIFEST_DIR"), "/src/gui/x0x-gui.html"),
        )
        .output()
        .expect("Node is required for the offline GUI behavior check");
    assert!(
        output.status.success(),
        "SignedPublic GUI behavior check failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
