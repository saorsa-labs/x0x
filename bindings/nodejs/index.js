// x0x Node.js Bindings - Platform-Aware Loader
// This module detects the platform and loads the appropriate native binary or WASM fallback.

const os = require('os');

/**
 * Detect the current platform and architecture.
 * @returns {string} Platform identifier (e.g., 'darwin-arm64', 'linux-x64-gnu')
 */
function getPlatformId() {
  const platform = process.platform;
  const arch = process.arch;
  const glibc = getLibc();

  switch (platform) {
    case 'darwin':
      if (arch === 'arm64') return 'darwin-arm64';
      if (arch === 'x64') return 'darwin-x64';
      break;

    case 'linux':
      if (arch === 'x64') {
        return glibc === 'musl' ? 'linux-x64-musl' : 'linux-x64-gnu';
      }
      if (arch === 'arm64') return 'linux-arm64-gnu';
      break;

    case 'win32':
      if (arch === 'x64') return 'win32-x64-msvc';
      break;
  }

  return null;
}

/**
 * Detect libc version on Linux systems.
 * @returns {string} 'glibc', 'musl', or 'unknown'
 */
function getLibc() {
  const ldd = require('child_process').execSync('ldd --version 2>/dev/null || echo unknown', {
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'ignore'],
  }).toString();

  if (ldd.includes('musl')) return 'musl';
  if (ldd.includes('GLIBC') || ldd.includes('glibc')) return 'glibc';
  return 'unknown';
}

/**
 * Load the native bindings for the current platform.
 * Falls back to WASM if no native binary is available.
 * @throws {Error} If neither native nor WASM bindings can be loaded
 */
function loadBindings() {
  const platformId = getPlatformId();

  // Try to load native binding first
  if (platformId) {
    try {
      const bindingsModule = `@x0x/core-${platformId}`;
      return require(bindingsModule);
    } catch (err) {
      console.debug(`Native bindings for ${platformId} not available:`, err.message);
    }
  }

  // Fallback to WASM
  try {
    console.debug('Loading WASM fallback bindings');
    return require('@x0x/core-wasm32-wasi');
  } catch (err) {
    throw new Error(
      `Could not load x0x bindings for platform ${platformId || 'unknown'}. ` +
      `Neither native nor WASM bindings available. Error: ${err.message}`
    );
  }
}

// Load and export bindings
const bindings = loadBindings();

// Re-export all bindings
module.exports = bindings;

// Also provide platform info for debugging
module.exports.__platform__ = {
  getPlatformId,
  getLibc,
  detected: getPlatformId(),
};
