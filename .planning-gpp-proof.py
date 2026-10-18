import os
from pathlib import Path
import subprocess

mode = os.environ['GPP_MODE']
evidence = Path(os.environ['GPP_EVIDENCE'])
evidence.mkdir(parents=True, exist_ok=True)
for child in ('scratch', 'nextest-home'):
    (evidence / child).mkdir(exist_ok=True)
# Preserve namespace/capability checks; keep runtime scratch on durable home storage.
p = Path('scripts/ci/isolated-runtime.py')
s = p.read_text().replace('/tmp/x0x-runtime-home', str(evidence / 'runtime-home')).replace('/tmp/x0x-runtime-tmp', str(evidence / 'runtime-tmp'))
s = s.replace('Path(name).mkdir(mode=0o700)', 'Path(name).mkdir(mode=0o700, exist_ok=True)')
p.write_text(s)
p = Path('.config/nextest.toml')
p.write_text(p.read_text().replace('/tmp/x0x-nextest-home', str(evidence / 'nextest-home')))
p = Path('src/lib.rs')
fixed = p.read_text()
base = subprocess.check_output(['git', 'show', '67f1280bfff16f14a7085a0684fc7fdbcf3f7c59:src/lib.rs'], text=True)
s = base if mode.startswith(('baseline', 'barriers')) else fixed
names = ('suppressed_peer_inbound_redial_is_rejected', 'gossip_plane_peers_excludes_suppressed_transport_connected_peer')

def bounds(source, name):
    start = source.index('    async fn ' + name + '() {')
    return start, source.index('\n    }', start) + len('\n    }')

for name in names:
    start, end = bounds(s, name)
    test = s[start:end]
    a, b = bounds(fixed, name)
    reference = fixed[a:b]
    if mode.startswith('barriers'):
        # Same admission/old-generation barriers as the fix, without its close interlock.
        declarations = reference[reference.index('        let alice_peer ='):reference.index('        let bound =')]
        declarations += '        let bound = std::time::Duration::from_secs(5);\n'
        healthy = reference[reference.index('        // Finish the original'):reference.index('        let old_alice_generation =')]
        healthy += reference[reference.index('        let old_alice_generation ='):reference.index('        assert_eq!(\n            bob_network.peer_admission')]
        teardown = reference[reference.index('        // The local disconnect'):reference.index('        // Hold Alice')]
        if name.startswith('suppressed'):
            teardown = teardown[:teardown.index('        // Watch for any')]
        test = test.replace('        let bob_peer = ant_quic::PeerId(bob.machine_id().0);', '        let bob_peer = ant_quic::PeerId(bob.machine_id().0);\n' + declarations, 1)
        test = test.replace('        alice_network\n            .disconnect_with_reason', healthy + '        alice_network\n            .disconnect_with_reason', 1)
        anchor = '        // Watch for any' if name.startswith('suppressed') else '        // Drive the transient'
        test = test.replace(anchor, teardown + anchor, 1)
    if mode.endswith('delayed'):
        helper = '''
        async fn delayed_poll<F: std::future::Future>(future: F) -> F::Output {
            let mut future = std::pin::pin!(future);
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(20));
            std::future::poll_fn(|cx| {
                std::task::ready!(tick.poll_tick(cx));
                future.as_mut().poll(cx)
            }).await
        }
'''
        test = test.replace('() {', '() {' + helper, 1)
        if mode.startswith('fixed'):
            old = 'tokio::join!(bob_network.connect_addr(alice_addr), reached_rx)'
            new = 'tokio::join!(delayed_poll(bob_network.connect_addr(alice_addr)), reached_rx)'
        else:
            old = 'bob_network\n            .connect_addr(alice_addr)'
            new = 'delayed_poll(bob_network.connect_addr(alice_addr))'
        assert test.count(old) == 1
        test = test.replace(old, new)
    test = test.replace('() {', '''() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("x0x::connect=warn")
            .with_ansi(false).with_test_writer().try_init();
''', 1)
    if mode.startswith('fixed'):
        test = test.replace('        // Hold Alice', '        eprintln!("GPP_STATE old_generation_closed");\n        // Hold Alice', 1)
        test = test.replace('        resume_tx\n', '        eprintln!("GPP_STATE fresh_live_suppressed");\n        resume_tx\n', 1)
        test = test.replace('        let deadline =', '        eprintln!("GPP_STATE real_close_completed");\n        let deadline =', 1)
    test = test[:test.rindex('\n    }')] + '\n        eprintln!("GPP_STATE assertions_completed");' + test[test.rindex('\n    }'):]
    s = s[:start] + test + s[end:]
p.write_text(s)
(evidence / 'instrumentation.patch').write_text(subprocess.check_output(['git', 'diff'], text=True))
(evidence / 'source.txt').write_text(subprocess.check_output(['git', 'rev-parse', 'HEAD', 'HEAD^{tree}'], text=True))
