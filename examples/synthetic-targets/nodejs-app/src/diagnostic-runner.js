import { exec } from 'node:child_process';
import { request } from 'node:https';

export function runHostDiagnostic(userHost, callback) {
  // Intentional synthetic Node.js vulnerabilities for HegoSentinel CODE-001 test
  exec('ping -c 1 ' + userHost, callback);
}

export function createInsecureAgentOptions() {
  return {
    rejectUnauthorized: false
  };
}

