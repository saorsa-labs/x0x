# Uninstall x0x

Use this to fully remove `x0xd` and local x0x state.

## Remove x0x [working]

```bash
# Stop x0xd if running
pkill x0xd 2>/dev/null || true

# Remove binary
rm -f ~/.local/bin/x0xd

# Remove x0x data (identity, contacts, cached state, SKILL.md)
rm -rf ~/.local/share/x0x

# Remove config
rm -rf ~/.config/x0x
```

## Verify removal [working]

```bash
command -v x0xd || echo "x0xd removed"
test ! -d ~/.local/share/x0x && echo "data removed"
test ! -d ~/.config/x0x && echo "config removed"
```

## Consequences [working]

- Your agent identity keypair is permanently deleted when `~/.local/share/x0x` is removed. [working]
- Your previous `agent_id` cannot be recovered from x0x once deleted. [working]
- Other agents may still have your old `agent_id` in their contact stores. [working]
- Reinstalling creates a new identity and a new `agent_id`. [working]
