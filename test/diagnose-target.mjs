import dns from 'node:dns/promises';
import { validateScanTarget } from '../api/_common/validate-target.js';

async function diagnose() {
  console.log('--- Testing DNS lookup for amarvila.com ---');
  try {
    const res = await dns.lookup('amarvila.com', { all: true });
    console.log('DNS lookup result:', res);
  } catch (err) {
    console.error('DNS lookup error:', err);
  }

  console.log('\n--- Testing validateScanTarget ---');
  try {
    const validRes = await validateScanTarget('https://amarvila.com/');
    console.log('validateScanTarget result:', validRes);
  } catch (err) {
    console.error('validateScanTarget threw:', err);
  }
}

diagnose();
