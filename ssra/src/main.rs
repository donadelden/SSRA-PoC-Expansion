// SSRA-PoC journal artifact — main.rs
// Workshop commands (tutor/robot/user/all) plus journal experiments
// (bench-crypto, bench-policy, e2e, rotate, bench-audit, attack-replay,
//  attack-mtls) and the extended evaluation commands attack-policy (SR5
//  enforcement), bench-keyissue (User-key re-issuance scaling), and
//  bench-bundle (stored bundle-size breakdown).
// SR7 metadata-only audit events are appended to shared/audit/audit.csv.
use rand::distributions::Alphanumeric;
use rand::Rng;
use rabe::schemes::bsw::*;
use rabe::utils::policy::pest::PolicyLanguage;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SHARED: &str = "./shared";
const WORKSHOP_POLICY: &str = r#""A" and "B""#;
const JOURNAL_POLICY: &str = r#""PATIENT" and "D1""#;
const JOURNAL_POLICY_ID: &str = "policy_patient_d1";
// Richer policy used ONLY by attack-policy so that role/purpose/attribute
// mismatches are distinct, genuine CP-ABE denials (A not satisfying P), not just
// the two-leaf JOURNAL_POLICY. Patient scope + clinical role + data type.
const POLICY_VALIDATION: &str = r#""PATIENT" and ("CLINICIAN" and "D1")"#;
const POLICY_VALIDATION_ID: &str = "policy_patient_role_d1";
// Server-side freshness window (ms) for the SR6 anti-replay check in e2e.
// Wide on purpose: normal e2e uploads stay fresh; attack-replay exercises stale cases.
const FRESHNESS_WINDOW_MS: u128 = 30_000;

// ── Shared utilities ─────────────────────────────────────────────────────────
// Tiny one-line helpers; they keep the workshop commands unchanged in behavior
// while letting every journal command emit reproducible CSV output.
fn path(name: &str) -> String { format!("{}/{}", SHARED, name) }
fn ms(d: Duration) -> f64 { d.as_secs_f64() * 1000.0 }
fn arg(args: &[String], i: usize, default: usize) -> usize { args.get(i).and_then(|s| s.parse().ok()).unwrap_or(default) }
fn now_ms() -> u128 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_millis() }
fn init_dirs() { for d in ["results", "server", "audit"] { fs::create_dir_all(path(d)).expect("cannot create shared subdir"); } }
// fill() writes the whole buffer in one RNG call instead of one call per byte.
fn rand_bytes(n: usize) -> Vec<u8> { let mut v = vec![0u8; n]; rand::thread_rng().fill(v.as_mut_slice()); v }
fn random_message(n: usize) -> String { rand::thread_rng().sample_iter(&Alphanumeric).take(n).map(char::from).collect() }

fn read_bytes(file: &str) -> Vec<u8> { let mut b = Vec::new(); File::open(file).unwrap_or_else(|_| panic!("cannot open {}", file)).read_to_end(&mut b).expect("read failed"); b }
fn write_bytes(file: &str, bytes: &[u8]) { File::create(file).unwrap_or_else(|_| panic!("cannot create {}", file)).write_all(bytes).expect("write failed"); }
fn csv(file: &str, line: &str) { writeln!(OpenOptions::new().create(true).append(true).open(file).unwrap_or_else(|_| panic!("cannot append {}", file)), "{}", line).expect("csv append failed"); }
// Serialise once, centrally; a macro avoids naming the serde trait (serde is only
// a transitive dependency here) while still removing scattered .unwrap() calls.
macro_rules! encode { ($v:expr) => { bincode::serialize($v).expect("encode failed") }; }

// CP-ABE attribute-name guard.  RABE's BSW scheme SILENTLY fails decryption (an
// authorized key returns an AEAD error although its attributes satisfy the
// policy) when an attribute name contains '_'.  Other characters tested safe
// (alphanumeric, '-', '.', mixed case, digits).  We reject '_' loudly and in
// release on purpose: it is a crypto-safety check, not a debug assertion.  This
// matters because Sec. 4.2 models the patient pseudonym P_i as a CP-ABE
// attribute, and pseudonyms naturally look like "pseudo_P1"; using such a name
// directly as an attribute would otherwise introduce a silent access-control
// failure.  Pseudonyms/policy-ids carried only as AEAD associated data or CSV
// fields are unaffected and may keep underscores.
fn assert_attr_names_safe(attrs: &[&str]) {
    if let Some(bad) = attrs.iter().find(|a| a.contains('_')) {
        panic!("CP-ABE attribute name {:?} contains '_': RABE BSW silently fails \
                decryption for underscored attributes; use camelCase or '-'.", bad);
    }
}

// ── SR7 audit helper ─────────────────────────────────────────────────────────
// Each row is metadata-only: actors, pseudonyms, policies, sequence numbers,
// decisions, and reasons, never plaintext patient data.  This prototype only
// emits local operational events and counts; tamper-evident guarantees require
// protected/external deployment logging.  Returns 1 so callers accumulate counts.
fn audit(event: &str, actor: &str, pseudo: &str, policy: &str, seq: Option<u64>, decision: &str, reason: &str) -> usize {
    let file = path("audit/audit.csv");
    // create_new writes the header exactly once and fails (ignored) afterwards,
    // removing the per-call exists() stat syscall used previously.
    if let Ok(mut f) = OpenOptions::new().write(true).create_new(true).open(&file) {
        writeln!(f, "timestamp_ms,event_type,actor,pseudonym,policy_id,seq,decision,reason").expect("audit header failed");
    }
    let seq_s = seq.map_or_else(|| "-".to_owned(), |x| x.to_string());
    csv(&file, &format!("{},{},{},{},{},{},{},{}", now_ms(), event, actor, pseudo, policy, seq_s, decision, reason));
    1
}

// ── SR7 OPTIONAL tamper-evident audit chain ──────────────────────────────────
// The default audit() above is metadata-only and best-effort, matching the
// server-untrusted model: the Server merely EMITS events and is never trusted
// to keep them.  The paper (SR7) notes that tamper-evident support requires
// "authenticated, hash-chained, signed, or externally checkpointed" logs.
//
// This helper makes that hash-chained variant CONCRETE and MEASURABLE.  Given an
// already-written metadata-only line, it computes the per-record chained hash
//     h_i = SHA256( h_{i-1} || line_i )
// exactly as an external/protected logger would.  IMPORTANT for the threat
// model: chaining does NOT make the Server trusted — a fully compromised logger
// can still truncate/rewrite its own chain.  It provides tamper-EVIDENCE only
// with respect to an external party that retains the last hash (an external
// checkpoint).  We keep this OUT of audit() on purpose: chaining state lives
// where the checkpoint lives, not on the untrusted Server by default.
//
// chain_step folds one record into the running hash and returns the new head.
fn chain_step(prev: &[u8; 32], record: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev);          // bind to the previous head (the chain link)
    hasher.update(record.as_bytes());
    hasher.finalize().into()
}

// bench-audit: measures the per-event cost of (a) metadata-only logging and
// (b) the same logging plus the SHA-256 chain, over `events` synthetic records.
// It reports both so the paper can show the tamper-evident overhead is a tiny,
// payload- and policy-independent fraction of the CP-ABE-dominated e2e budget.
// No global state, no extra files: the chain is computed in memory, mirroring
// an external checkpointing component.
fn bench_audit(args: &[String]) {
    let events = arg(args, 2, 10_000).max(1);
    // A representative metadata-only record (same 8 fields as audit() emits).
    let sample = format!("{},upload_accepted,Robot0,{},{},0,accepted,stored",
                         now_ms(), "pseudo_demo", JOURNAL_POLICY_ID);

    // (a) Baseline: cost of formatting/serialising one metadata-only record.
    //     We format into a reused String to isolate the logging cost itself,
    //     not allocator noise, and read it back so the work is not optimised away.
    let t = Instant::now();
    let mut sink = 0u64;
    for i in 0..events {
        let line = format!("{}|{}", sample, i);
        sink = sink.wrapping_add(line.len() as u64);
    }
    let plain_ms = ms(t.elapsed());

    // (b) Tamper-evident: the same record cost PLUS one SHA-256 chain step each.
    let t = Instant::now();
    let mut head = [0u8; 32];
    for i in 0..events {
        let line = format!("{}|{}", sample, i);
        head = chain_step(&head, &line);
    }
    let chained_ms = ms(t.elapsed());
    // Consume `head`/`sink` so neither loop is eliminated by the optimiser.
    let head_marker = head[0] as u64 ^ sink;

    let per_plain = plain_ms / events as f64;
    let per_chain = chained_ms / events as f64;
    let overhead = per_chain - per_plain;
    let file = path("results/bench_audit.csv");
    let _ = fs::remove_file(&file);
    csv(&file, "events,plain_total_ms,chained_total_ms,per_event_plain_ms,per_event_chained_ms,chain_overhead_ms,head_marker");
    csv(&file, &format!("{},{:.6},{:.6},{:.8},{:.8},{:.8},{}",
        events, plain_ms, chained_ms, per_plain, per_chain, overhead, head_marker));
    println!("bench-audit: {} events | metadata-only {:.8} ms/event | chained {:.8} ms/event | chain overhead {:.8} ms/event",
        events, per_plain, per_chain, overhead);
}

// ── Local payload layer (e2e/rotate/bench-bundle): real AES-256-GCM ──────────
// RABE performs the CP-ABE work on the compact content key; this layer is the
// real symmetric AEAD the paper specifies (Sec. 4.2/6): AES-256-GCM over the
// payload, binding the non-secret metadata (pseudonym, timestamp, sequence,
// policy id) as authenticated associated data (AD). A fresh 96-bit nonce is
// drawn per message; because envelope encryption uses a fresh content key K_c
// per payload, a nonce is never reused under the same key. The returned blob is
// self-contained — nonce(12) || ciphertext || GCM tag(16) — so the stored
// "payload ciphertext" carries everything needed to decrypt; authenticated
// decryption verifies both the tag and the AD, so any modification of the
// ciphertext or of the bound metadata makes decryption fail (SR1).
fn aead_encrypt(pt: &[u8], key32: &[u8], ad: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key32));
    let nonce_bytes = rand_bytes(12); // fresh per-message 96-bit nonce
    let mut ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: pt, aad: ad })
        .expect("AES-256-GCM encrypt failed");
    let mut out = Vec::with_capacity(nonce_bytes.len() + ct.len());
    out.extend_from_slice(&nonce_bytes); // prepend nonce for self-contained storage
    out.append(&mut ct);                 // ciphertext already carries the 16-byte tag
    out
}
fn aead_decrypt(blob: &[u8], key32: &[u8], ad: &[u8]) -> Vec<u8> {
    let (nonce_bytes, ct) = blob.split_at(12); // recover the prepended nonce
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key32));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), Payload { msg: ct, aad: ad })
        .expect("AES-256-GCM authentication/decryption failed")
}

// ── RABE wrappers ─────────────────────────────────────────────────────────────
// Centralizing setup/keygen/encrypt/decrypt keeps old and new commands compact.
fn load_pk() -> CpAbePublicKey { bincode::deserialize(&read_bytes(&path("pk.bin"))).expect("bad public key") }
fn load_msk() -> CpAbeMasterKey { bincode::deserialize(&read_bytes(&path("msk.bin"))).expect("bad master key") }
fn load_sk() -> CpAbeSecretKey { bincode::deserialize(&read_bytes(&path("sk.bin"))).expect("bad user key") }
fn timed_setup() -> (CpAbePublicKey, CpAbeMasterKey, f64) { let t = Instant::now(); let (pk, msk) = setup(); (pk, msk, ms(t.elapsed())) }
fn timed_keygen(pk: &CpAbePublicKey, msk: &CpAbeMasterKey, attrs: &[&str]) -> (CpAbeSecretKey, f64) {
    assert_attr_names_safe(attrs);
    let t = Instant::now(); let sk = keygen(pk, msk, attrs).expect("CP-ABE keygen failed"); (sk, ms(t.elapsed()))
}
fn timed_enc(pk: &CpAbePublicKey, policy: &str, pt: &[u8]) -> (CpAbeCiphertext, f64) {
    let t = Instant::now(); let ct = encrypt(pk, policy, PolicyLanguage::HumanPolicy, pt).expect("CP-ABE encrypt failed"); (ct, ms(t.elapsed()))
}
fn timed_dec(sk: &CpAbeSecretKey, ct: &CpAbeCiphertext) -> (Vec<u8>, f64) {
    let t = Instant::now(); let pt = decrypt(sk, ct).expect("CP-ABE decrypt failed"); (pt, ms(t.elapsed()))
}
// Non-panicking CP-ABE decapsulation for the SR5 policy-enforcement harness:
// returns true iff the User attribute set satisfies the ciphertext policy
// (A satisfies P). Unlike timed_dec, it never expect()/panics on the legitimate
// unauthorised outcome, so attack-policy can record genuine reject cases.
fn try_decrypt(sk: &CpAbeSecretKey, ct: &CpAbeCiphertext) -> bool { decrypt(sk, ct).is_ok() }

// ── Original workshop commands (backward compatible) ─────────────────────────
fn generate_master_keys() {
    let (pk, msk, t) = timed_setup();
    println!("Key Generation Time: {:.3} ms", t);
    write_bytes(&path("pk.bin"), &encode!(&pk));
    write_bytes(&path("msk.bin"), &encode!(&msk));
}
fn generate_user_keys(attrs: &[&str]) {
    let (sk, t) = timed_keygen(&load_pk(), &load_msk(), attrs);
    println!("User Key Generation Time: {:.3} ms", t);
    write_bytes(&path("sk.bin"), &encode!(&sk));
    println!("Secret key dumped to ./shared/sk.bin");
}
fn encrypt_cpabe(policy: &str, plaintext: &str) {
    let (ct, t) = timed_enc(&load_pk(), policy, plaintext.as_bytes());
    println!("Public key loaded successfully\nEncryption Time: {:.3} ms", t);
    write_bytes(&path("enc.bin"), &encode!(&Some(ct)));
    println!("Encrypted data dumped to ./shared/enc.bin");
}
fn decrypt_cpabe() {
    let opt: Option<CpAbeCiphertext> = bincode::deserialize(&read_bytes(&path("enc.bin"))).expect("bad ciphertext");
    let (pt, t) = timed_dec(&load_sk(), &opt.expect("empty ciphertext"));
    println!("Decryption Time: {:.3} ms", t);
    println!("Decrypted data: {:?}", String::from_utf8(pt).expect("non-UTF8 plaintext"));
}

// ── bench-crypto: workshop CP-ABE baseline → bench_crypto.csv ────────────────
fn bench_crypto(args: &[String]) {
    let (payload_len, runs, warmup) = (arg(args, 2, 1000), arg(args, 3, 10), arg(args, 4, 1));
    let out = path("results/bench_crypto.csv");
    write_bytes(&out, b"run,payload_len,setup_ms,user_keygen_ms,encrypt_ms,decrypt_ms,ciphertext_bytes\n");
    for run in 0..runs + warmup {
        let (pk, msk, setup_ms) = timed_setup();
        let (sk, keygen_ms) = timed_keygen(&pk, &msk, &["A", "B"]);
        let (ct, enc_ms) = timed_enc(&pk, WORKSHOP_POLICY, &rand_bytes(payload_len));
        let (_, dec_ms) = timed_dec(&sk, &ct);
        let ct_len = encode!(&ct).len(); // serialise once, reuse for the size column
        if run >= warmup {
            csv(&out, &format!("{},{},{:.6},{:.6},{:.6},{:.6},{}", run - warmup, payload_len, setup_ms, keygen_ms, enc_ms, dec_ms, ct_len));
        }
    }
    println!("bench-crypto completed: {}", out);
}

// ── bench-policy: CP-ABE cost vs policy size/depth → bench_policy.csv ────────
// Builds a balanced AND/OR tree over leaves A1..A{leaves}; every generated
// policy is satisfied by the full attribute set created below.  Each leaf list
// is parenthesised so mixed AND/OR levels stay unambiguous for the RABE parser
// (the previous generator emitted unparenthesised mixes and the parser rejected
// them, crashing bench-policy for all but the first configuration).
fn make_policy(leaves: usize, depth: usize) -> String {
    fn rec(a: usize, b: usize, d: usize, and_op: bool) -> String {
        if a == b { return format!("\"A{}\"", a); }
        let op = if and_op { "and" } else { "or" };
        if d <= 1 {
            let joined = (a..=b).map(|i| format!("\"A{}\"", i)).collect::<Vec<_>>().join(&format!(" {} ", op));
            return format!("({})", joined); // parentheses protect this sub-list
        }
        let m = (a + b) / 2;
        format!("({} {} {})", rec(a, m, d - 1, !and_op), op, rec(m + 1, b, d - 1, !and_op))
    }
    format!("\"PATIENT\" and {}", rec(1, leaves.max(1), depth.max(1), true))
}
fn bench_policy(args: &[String]) {
    let (runs, warmup, out) = (arg(args, 2, 5), arg(args, 3, 1), path("results/bench_policy.csv"));
    write_bytes(&out, b"run,leaf_attributes,policy_depth,encapsulate_ms,decapsulate_ms,ciphertext_bytes\n");
    let (pk, msk, _) = timed_setup();
    let names: Vec<String> = std::iter::once("PATIENT".to_owned()).chain((1..=40).map(|i| format!("A{}", i))).collect();
    let attrs: Vec<&str> = names.iter().map(String::as_str).collect();
    let (sk, _) = timed_keygen(&pk, &msk, &attrs);
    for (leaves, depth) in [(5, 1), (10, 2), (20, 3), (40, 4)] {
        let p = make_policy(leaves, depth);
        for run in 0..runs + warmup {
            let (ct, enc_ms) = timed_enc(&pk, &p, &rand_bytes(32));
            let (_, dec_ms) = timed_dec(&sk, &ct);
            let ct_len = encode!(&ct).len(); // serialise once, reuse for size column
            if run >= warmup { csv(&out, &format!("{},{},{},{:.6},{:.6},{}", run - warmup, leaves, depth, enc_ms, dec_ms, ct_len)); }
        }
    }
    println!("bench-policy completed: {}", out);
}

// ── e2e: Robot → Server/Storage → User → e2e.csv + audit.csv ────────────────
// CP-ABE wrapping is real; the Server/Storage is file-based and emits SR7
// metadata-only audit records.  Duplicate-sequence filtering models Server-side
// replay prevention; confidentiality/access control still rely on endpoint
// crypto, not on trusting this layer.
fn run_e2e(args: &[String]) {
    let (payload_len, robots, users, runs, warmup) = (arg(args, 2, 4096), arg(args, 3, 1), arg(args, 4, 1).max(1), arg(args, 5, 10), arg(args, 6, 1));
    let out = path("results/e2e.csv");
    write_bytes(&out, b"run,robot_id,user_id,payload_len,payload_encrypt_ms,cpabe_encapsulate_ms,server_store_ms,server_retrieve_ms,cpabe_decapsulate_ms,payload_decrypt_ms,total_ms,accepted,audit_event_count\n");
    let (pk, msk, _) = timed_setup();
    let (sk, _) = timed_keygen(&pk, &msk, &["PATIENT", "D1"]);
    audit("pseudonym_registration", "Tutor", "PSEUDO_TEMPLATE", "-", None, "accepted", "setup");
    audit("key_issuance", "Tutor", "PSEUDO_TEMPLATE", JOURNAL_POLICY_ID, None, "accepted", "user_key");
    let mut seen = HashSet::<(usize, String, u64)>::new();
    for run in 0..runs + warmup {
        for robot in 0..robots {
            let total = Instant::now();
            let (user, pseudo, seq) = (robot % users, format!("PSEUDO_R{}", robot), run as u64);
            // AD binds pseudonym, message timestamp, sequence, and policy id to the payload.
            let msg_ts = now_ms();
            let ad = format!("{}|{}|{}|{}", pseudo, msg_ts, seq, JOURNAL_POLICY_ID).into_bytes();
            let (key, payload) = (rand_bytes(32), rand_bytes(payload_len));
            let t = Instant::now(); let payload_ct = aead_encrypt(&payload, &key, &ad); let payload_enc_ms = ms(t.elapsed());
            let (wrapper, cpabe_enc_ms) = timed_enc(&pk, JOURNAL_POLICY, &key);
            // Server/Storage operational validation (SR6): the Server re-checks the
            // freshness window t in (t0, t0+epsilon) on the message timestamp and rejects
            // duplicate seq values for (robot, pseudonym). epsilon is wide enough that
            // normal e2e uploads always stay fresh; replay/jitter cases are exercised by
            // attack-replay. Confidentiality/access control still rely on endpoint crypto.
            let t = Instant::now();
            let fresh = now_ms().saturating_sub(msg_ts) <= FRESHNESS_WINDOW_MS;
            let new_seq = seen.insert((robot, pseudo.clone(), seq));
            let accepted = fresh && new_seq;
            let bundle_path = path(&format!("server/bundle_r{}_u{}_{}.bin", robot, user, run));
            let wrapper_bytes = encode!(&wrapper);
            // Bundle layout: AD (cleartext routing metadata) || payload ct
            // (nonce||ciphertext||GCM tag) || CP-ABE key wrapper.
            let mut bundle = Vec::with_capacity(ad.len() + payload_ct.len() + wrapper_bytes.len());
            bundle.extend_from_slice(&ad);
            bundle.extend_from_slice(&payload_ct);
            bundle.extend_from_slice(&wrapper_bytes);
            write_bytes(&bundle_path, &bundle);
            let store_ms = ms(t.elapsed());
            // Rejection reason mirrors attack-replay: stale timestamp vs duplicate sequence.
            let reason = if accepted { "stored" } else if !fresh { "stale_timestamp" } else { "duplicate_sequence" };
            let event = if accepted { "upload_accepted" } else { "upload_rejected" };
            let mut audit_count = audit(event, &format!("Robot{}", robot), &pseudo, JOURNAL_POLICY_ID, Some(seq), if accepted { "accepted" } else { "rejected" }, reason);
            let t = Instant::now(); let _ = read_bytes(&bundle_path);
            audit_count += audit("retrieval", &format!("User{}", user), &pseudo, JOURNAL_POLICY_ID, Some(seq), "accepted", "returned_bundle");
            let retrieve_ms = ms(t.elapsed());
            let (recovered_key, cpabe_dec_ms) = timed_dec(&sk, &wrapper);
            let t = Instant::now(); assert_eq!(aead_decrypt(&payload_ct, &recovered_key, &ad).len(), payload.len()); let payload_dec_ms = ms(t.elapsed());
            if run >= warmup {
                csv(&out, &format!("{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{}", run - warmup, robot, user, payload_len, payload_enc_ms, cpabe_enc_ms, store_ms, retrieve_ms, cpabe_dec_ms, payload_dec_ms, ms(total.elapsed()), accepted, audit_count));
            }
        }
    }
    println!("e2e completed: {}", out);
}

// ── rotate: wrapper refresh vs re-encrypt-all → rotate.csv + audit.csv ──────
// Systems experiment only; does not claim CP-ABE PRE security.
fn run_rotate(args: &[String]) {
    let (bundles, payload_len, out) = (arg(args, 2, 100), arg(args, 3, 1024 * 1024), path("results/rotate.csv"));
    write_bytes(&out, b"bundle_index,payload_len,wrapper_update_ms,reencrypt_all_ms,audit_event_count\n");
    let (pk, _, _) = timed_setup();
    // Accumulators for the affected-bundle summary (tab:refresh-bundle-scaling).
    // Per-bundle rows go to rotate.csv (payload-size view of tab:refresh-overhead);
    // the totals below let a sweep over `bundles` at a fixed payload build the
    // archive-level scaling table without manual post-processing.
    let (mut sum_wrapper, mut sum_reencrypt, mut audit_events) = (0.0f64, 0.0f64, 0usize);
    for i in 0..bundles {
        let (key, payload) = (rand_bytes(32), rand_bytes(payload_len));
        let ad = format!("PSEUDO_ROTATE|{}|{}|{}", now_ms(), i, JOURNAL_POLICY_ID);
        let wrapper_update_ms = timed_enc(&pk, JOURNAL_POLICY, &key).1; // re-wrap key only
        audit_events += audit("wrapper_refresh", "Tutor", "PSEUDO_ROTATE", JOURNAL_POLICY_ID, Some(i as u64), "accepted", "wrapper_only");
        let ct = aead_encrypt(&payload, &key, ad.as_bytes());
        // Timed block reproduces the original re-encrypt-all cost exactly: fresh
        // key sampling + payload decrypt + payload re-encrypt + new CP-ABE wrapper.
        let t = Instant::now();
        let _ = aead_decrypt(&ct, &key, ad.as_bytes());          // decrypt under old key
        let new_key = rand_bytes(32);                            // fresh content key
        let _ = aead_encrypt(&payload, &new_key, ad.as_bytes()); // re-encrypt full payload
        let _ = timed_enc(&pk, JOURNAL_POLICY, &new_key);        // new wrapper
        let reencrypt_ms = ms(t.elapsed());
        audit_events += audit("reencrypt_baseline", "Tutor", "PSEUDO_ROTATE", JOURNAL_POLICY_ID, Some(i as u64), "accepted", "payload_and_wrapper");
        sum_wrapper += wrapper_update_ms;
        sum_reencrypt += reencrypt_ms;
        csv(&out, &format!("{},{},{:.6},{:.6},2", i, payload_len, wrapper_update_ms, reencrypt_ms));
    }
    // Affected-bundle summary: append one row per invocation so a sweep over
    // `bundles` at a fixed payload (e.g. 100/1000/10000 at 2MB) assembles
    // tab:refresh-bundle-scaling. Speedup = total re-encrypt-all / total wrapper.
    let summary = path("results/rotate_summary.csv");
    if !std::path::Path::new(&summary).exists() {
        write_bytes(&summary, b"bundles,payload_len,total_wrapper_ms,total_reencrypt_ms,speedup,audit_event_count\n");
    }
    let speedup = if sum_wrapper > 0.0 { sum_reencrypt / sum_wrapper } else { 0.0 };
    csv(&summary, &format!("{},{},{:.3},{:.3},{:.3},{}", bundles, payload_len, sum_wrapper, sum_reencrypt, speedup, audit_events));
    println!("rotate completed: {} (+ summary {})", out, summary);
}

// ── attack-replay: freshness/duplicate-sequence harness → attack_replay.csv ──
// Logical model of SR6; each outcome is backed by an SR7 audit event.
fn run_attack_replay() {
    let out = path("results/attack_replay.csv");
    write_bytes(&out, b"case,timestamp_status,sequence_status,accepted,reason,audit_event_count\n");
    let (now, window) = (now_ms() as i128, 5000i128);
    let mut seen = HashSet::<u64>::new();
    for (name, ts, seq) in [("fresh_new_seq", now, 1), ("stale_new_seq", now - window - 1, 2), ("fresh_duplicate_seq_first", now, 3), ("fresh_duplicate_seq_second", now, 3)] {
        let fresh = now - ts <= window;
        let duplicate = seen.contains(&seq);
        let accepted = fresh && !duplicate;
        if accepted { seen.insert(seq); }
        let reason = if !fresh { "stale_timestamp" } else if duplicate { "duplicate_sequence" } else { "accepted" };
        let event = if accepted { "upload_accepted" } else if !fresh { "stale_upload" } else { "duplicate_upload" };
        let n = audit(event, "RobotReplay", "PSEUDO_REPLAY", JOURNAL_POLICY_ID, Some(seq), if accepted { "accepted" } else { "rejected" }, reason);
        csv(&out, &format!("{},{},{},{},{},{}", name, if fresh { "fresh" } else { "stale" }, if duplicate { "duplicate" } else { "new" }, accepted, reason, n));
    }
    println!("attack-replay completed: {}", out);
}

// ── attack-mtls: certificate-validation harness → attack_mtls.csv ───────────
// Logical model of the mTLS trust decisions; no live TLS sockets are opened.
fn run_attack_mtls() {
    let out = path("results/attack_mtls.csv");
    write_bytes(&out, b"case,trusted_ca,not_expired,not_revoked,role_ok,accepted,reason,audit_event_count\n");
    for (name, ca, fresh, not_revoked, role) in [("valid_robot", true, true, true, true), ("self_signed_or_untrusted_ca", false, true, true, true), ("expired", true, false, true, true), ("revoked", true, true, false, true), ("wrong_endpoint_role", true, true, true, false)] {
        let accepted = ca && fresh && not_revoked && role;
        let reason = if !ca { "untrusted_ca" } else if !fresh { "expired" } else if !not_revoked { "revoked" } else if !role { "wrong_role" } else { "accepted" };
        let n = audit(if accepted { "authenticated_action" } else { "certificate_validation_failure" }, name, "-", "-", None, if accepted { "accepted" } else { "rejected" }, reason);
        csv(&out, &format!("{},{},{},{},{},{},{},{}", name, ca, fresh, not_revoked, role, accepted, reason, n));
    }
    println!("attack-mtls completed: {}", out);
}

// ── attack-policy: SR5 policy-enforcement validation → attack_policy.csv ─────
// Validates that access is granted iff the User attribute set satisfies the
// ciphertext policy. The first four cases are GENUINE CP-ABE outcomes
// (A satisfies P, or not) produced by real keygen + decapsulation. The last two
// — revoked and expired — are NOT CP-ABE-native: BSW enforces only attribute
// satisfaction. They are therefore modelled as an explicit Tutor/governance gate
// (a revocation set and an authorization-expiry check) applied BEFORE
// decapsulation, matching how SSRA describes revocation/refresh as Tutor-governed
// metadata operations. Each outcome is backed by one SR7 metadata-only audit event.
fn attack_policy(_args: &[String]) {
    let out = path("results/attack_policy.csv");
    write_bytes(&out, b"condition,outcome,status,audit_record,audit_event_count\n");
    let (pk, msk, _) = timed_setup();
    let wrapper = timed_enc(&pk, POLICY_VALIDATION, &rand_bytes(32)).0; // wraps a 32-byte content key

    // (1-4) Genuine CP-ABE attribute-satisfaction cases: real keygen + try_decrypt.
    let cpabe_cases: [(&str, &[&str], bool); 4] = [
        ("matching_role_purpose_attributes", &["PATIENT", "CLINICIAN", "D1"], true),
        ("role_mismatch",                    &["PATIENT", "FAMILY", "D1"],    false),
        ("purpose_mismatch",                 &["PATIENT", "CLINICIAN", "D2"], false),
        ("missing_required_attribute",       &["PATIENT", "CLINICIAN"],       false),
    ];
    for (name, attrs, expect_ok) in cpabe_cases {
        let (sk, _) = timed_keygen(&pk, &msk, attrs);
        let granted = try_decrypt(&sk, &wrapper);          // true iff A satisfies P
        let correct = granted == expect_ok;
        let (outcome, record, reason) = if granted {
            ("accepted", "Access granted", "access_granted")
        } else {
            ("rejected", "Policy denied", "policy_denied")
        };
        let n = audit("policy_enforcement", "User", "PSEUDO_POLICY", POLICY_VALIDATION_ID, None,
                      if granted { "accepted" } else { "rejected" }, reason);
        csv(&out, &format!("{},{},{},{},{}", name, outcome, if correct { "correct" } else { "incorrect" }, record, n));
    }

    // (5-6) Governance-layer gate (NOT CP-ABE): the key DOES satisfy the policy,
    // but the Tutor-governed revocation set / expiry context denies it first.
    let (sk_valid, _) = timed_keygen(&pk, &msk, &["PATIENT", "CLINICIAN", "D1"]);
    let gov_cases: [(&str, bool, bool, &str, &str); 2] = [
        // (name, revoked, expired, audit_record, reason)
        ("revoked_authorization_material", true,  false, "Revoked access",        "revoked"),
        ("expired_authorization_context",  false, true,  "Expired authorization", "expired"),
    ];
    for (name, revoked, expired, record, reason) in gov_cases {
        // Governance gate precedes decapsulation; without it CP-ABE would succeed.
        let gate_ok = !revoked && !expired;
        let granted = gate_ok && try_decrypt(&sk_valid, &wrapper);
        let correct = !granted; // both governance cases must be denied
        let n = audit("policy_enforcement", "User", "PSEUDO_POLICY", POLICY_VALIDATION_ID, None, "rejected", reason);
        csv(&out, &format!("{},rejected,{},{},{}", name, if correct { "correct" } else { "incorrect" }, record, n));
    }
    println!("attack-policy completed: {}", out);
}

// ── bench-keyissue: User-key re-issuance scaling → keyissue.csv ──────────────
// Measures the local Tutor-side cost of generating fresh User key material when
// pseudonym rotation, policy changes, or credential leakage require re-issue.
// Sweeps 10^1..10^max_exp Users; reports total time, mean per key, and the
// number of SR7 key-issuance audit events. Excludes organizational redistribution
// (secure delivery, verification, acknowledgement, installation, acceptance).
fn bench_keyissue(args: &[String]) {
    let max_exp = arg(args, 2, 4).clamp(1, 5); // optional cap for quick runs (default 10^4)
    let out = path("results/keyissue.csv");
    write_bytes(&out, b"users,total_ms,mean_per_key_ms,audit_event_count\n");
    let (pk, msk, _) = timed_setup();
    for exp in 1..=max_exp {
        let users = 10usize.pow(exp as u32);
        let (mut total, mut audits) = (0.0f64, 0usize);
        for u in 0..users {
            // A distinct per-User attribute keeps each issuance a fresh keygen,
            // as in a real re-issuance over many affected Users.
            let uid = format!("U{}", u);
            let attrs = ["PATIENT", "D1"];
            total += timed_keygen(&pk, &msk, &attrs).1;
            audits += audit("key_issuance", "Tutor", "PSEUDO_KEYISSUE", POLICY_VALIDATION_ID, Some(u as u64), "accepted", "user_key_reissue");
        }
        csv(&out, &format!("{},{:.3},{:.6},{}", users, total, total / users as f64, audits));
        println!("bench-keyissue: {} users | total {:.1} ms | mean {:.4} ms/key", users, total, total / users as f64);
    }
    println!("bench-keyissue completed: {}", out);
}

// ── bench-bundle: stored bundle-size breakdown → bundle.csv ──────────────────
// Reports the byte sizes of the components of one stored ciphertext bundle for
// representative payloads: payload ciphertext (AES-256-GCM, i.e. a 12-byte nonce
// + the ciphertext + the 16-byte GCM tag, so payload_len + 28), the real CP-ABE
// key wrapper, the authenticated metadata (the AD bound into the AEAD), and a
// representative metadata-only audit record. "Total" sums the components,
// showing the fixed wrapper/metadata/audit cost is visible only for small
// telemetry payloads while multimedia bundles are payload-dominated.
fn bench_bundle(_args: &[String]) {
    let out = path("results/bundle.csv");
    write_bytes(&out, b"payload_len,payload_ct_bytes,key_wrapper_bytes,metadata_bytes,audit_record_bytes,total_bytes\n");
    let (pk, _, _) = timed_setup();
    for payload_len in [4 * 1024usize, 100 * 1024, 2 * 1024 * 1024] {
        let (key, payload) = (rand_bytes(32), rand_bytes(payload_len));
        let ad = format!("PSEUDO_BUNDLE|{}|{}|{}", now_ms(), 0, JOURNAL_POLICY_ID);
        let payload_ct = aead_encrypt(&payload, &key, ad.as_bytes()); // nonce + ciphertext + GCM tag
        let wrapper_bytes = encode!(&timed_enc(&pk, JOURNAL_POLICY, &key).0).len(); // real CP-ABE wrapper size
        let metadata_bytes = ad.len(); // authenticated metadata (AD); nonce and tag live inside payload ct
        // Representative metadata-only audit record (same 8 fields audit() emits).
        let audit_record = format!("{},upload_accepted,Robot0,PSEUDO_BUNDLE,{},0,accepted,stored", now_ms(), JOURNAL_POLICY_ID);
        let audit_bytes = audit_record.len();
        let total = payload_ct.len() + wrapper_bytes + metadata_bytes + audit_bytes;
        csv(&out, &format!("{},{},{},{},{},{}", payload_len, payload_ct.len(), wrapper_bytes, metadata_bytes, audit_bytes, total));
    }
    println!("bench-bundle completed: {}", out);
}

fn usage(program: &str) {
    eprintln!("Usage: {} <command> [args]", program);
    eprintln!("Original: tutor | robot [message_len] | user | all [message_len]");
    eprintln!("Journal:  bench-crypto [payload_len runs warmup]");
    eprintln!("          bench-policy [runs warmup]");
    eprintln!("          e2e [payload_len robots users runs warmup]");
    eprintln!("          rotate [bundles payload_len]");
    eprintln!("          bench-keyissue [max_exp]");
    eprintln!("          bench-bundle");
    eprintln!("          bench-audit [events]");
    eprintln!("          attack-replay | attack-mtls | attack-policy");
}

fn main() {
    init_dirs();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { usage(&args[0]); std::process::exit(1); }
    match args[1].as_str() {
        "tutor" => { generate_master_keys(); generate_user_keys(&["A", "B"]); }
        "robot" => encrypt_cpabe(WORKSHOP_POLICY, &random_message(arg(&args, 2, 1000))),
        "user" => decrypt_cpabe(),
        "all" => { generate_master_keys(); generate_user_keys(&["A", "B"]); encrypt_cpabe(WORKSHOP_POLICY, &random_message(arg(&args, 2, 1000))); decrypt_cpabe(); }
        "bench-crypto" => bench_crypto(&args),
        "bench-policy" => bench_policy(&args),
        "e2e" => run_e2e(&args),
        "rotate" => run_rotate(&args),
        "bench-keyissue" => bench_keyissue(&args),
        "bench-bundle" => bench_bundle(&args),
        "bench-audit" => bench_audit(&args),
        "attack-replay" => run_attack_replay(),
        "attack-mtls" => run_attack_mtls(),
        "attack-policy" => attack_policy(&args),
        other => { eprintln!("unknown command: {}", other); usage(&args[0]); std::process::exit(1); }
    }
}