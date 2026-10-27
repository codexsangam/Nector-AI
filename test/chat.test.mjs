/**
 * Nector AI Security Assistant — Automated Test Suite
 *
 * Verifies:
 * 1. Chat store session creation and history isolation
 * 2. Message bounds and clearing
 * 3. Input validation (empty messages, message length limits)
 * 4. Scan context binding and evidence injection
 * 5. Prompt sanitization
 * 6. Gemini configuration status and error handling
 */

import assert from 'node:assert';
import dotenv from 'dotenv';
dotenv.config();

import {
  getOrCreateSession,
  getChatHistory,
  appendMessage,
  clearConversation,
  updateSessionScanId,
  getSessionMeta,
} from '../api/_common/chat-store.js';
import {
  sendChatMessage,
  buildScanContext,
  sanitizeUserMessage,
} from '../api/_common/gemini-chat.js';
import { createScanRecord } from '../api/_common/scan-store.js';

let passed = 0;
let failed = 0;

function runTest(name, fn) {
  try {
    fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`[FAIL] ${name}: ${err.message}`);
    failed++;
  }
}

async function runAsyncTest(name, fn) {
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`[FAIL] ${name}: ${err.message}`);
    failed++;
  }
}

console.log('==================================================');
console.log('    NECTOR AI SECURITY ASSISTANT TEST SUITE       ');
console.log('==================================================\n');

// --- 1. Chat Store Tests ---
runTest('ChatStore: Creates new session with empty messages array', () => {
  const sessionId = 'test-session-1-' + Date.now();
  const session = getOrCreateSession(sessionId);
  assert.ok(session, 'Session must exist');
  assert.ok(Array.isArray(session.messages), 'Messages must be an array');
  assert.strictEqual(session.messages.length, 0, 'New session must have 0 messages');
});

runTest('ChatStore: Appends messages and maintains role mapping', () => {
  const sessionId = 'test-session-2-' + Date.now();
  appendMessage(sessionId, 'user', 'What is SQL Injection?');
  appendMessage(sessionId, 'model', 'SQL Injection is a code injection technique...');

  const history = getChatHistory(sessionId);
  assert.strictEqual(history.length, 2, 'History must contain 2 messages');
  assert.strictEqual(history[0].role, 'user');
  assert.strictEqual(history[0].content, 'What is SQL Injection?');
  assert.strictEqual(history[1].role, 'model');
});

runTest('ChatStore: Session isolation (sessions do not share history)', () => {
  const sessA = 'sess-iso-a-' + Date.now();
  const sessB = 'sess-iso-b-' + Date.now();

  appendMessage(sessA, 'user', 'Message for A');
  appendMessage(sessB, 'user', 'Message for B');

  const histA = getChatHistory(sessA);
  const histB = getChatHistory(sessB);

  assert.strictEqual(histA.length, 1);
  assert.strictEqual(histB.length, 1);
  assert.strictEqual(histA[0].content, 'Message for A');
  assert.strictEqual(histB[0].content, 'Message for B');
});

runTest('ChatStore: Clears conversation history', () => {
  const sessionId = 'test-session-clear-' + Date.now();
  appendMessage(sessionId, 'user', 'Hello');
  appendMessage(sessionId, 'model', 'Hi there');
  assert.strictEqual(getChatHistory(sessionId).length, 2);

  clearConversation(sessionId);
  assert.strictEqual(getChatHistory(sessionId).length, 0, 'History should be empty after clear');
});

runTest('ChatStore: Bounded history limit (trims oldest messages to limit of 20)', () => {
  const sessionId = 'test-session-limit-' + Date.now();
  for (let i = 0; i < 30; i++) {
    appendMessage(sessionId, i % 2 === 0 ? 'user' : 'model', `Msg ${i}`);
  }
  const history = getChatHistory(sessionId);
  assert.ok(history.length <= 20, `History length (${history.length}) should not exceed limit of 20`);
});

// --- 2. Input Validation Tests ---
await runAsyncTest('GeminiChat: Rejects empty or whitespace-only messages', async () => {
  const result = await sendChatMessage({
    sessionId: 'val-test-1',
    userMessage: '   ',
  });
  assert.strictEqual(result.success, false);
  assert.ok(result.error.toLowerCase().includes('empty'), 'Expected error to mention empty');
});

await runAsyncTest('GeminiChat: Rejects overly long messages (> 4000 chars)', async () => {
  const longMsg = 'A'.repeat(5000);
  const result = await sendChatMessage({
    sessionId: 'val-test-2',
    userMessage: longMsg,
  });
  assert.strictEqual(result.success, false);
  assert.ok(result.error.toLowerCase().includes('too long'), 'Expected error to mention too long');
});

// --- 3. Sanitization Tests ---
runTest('GeminiChat: Sanitizes control characters and strips null bytes', () => {
  const dirty = 'Hello\0World\x01\x02Test';
  const clean = sanitizeUserMessage(dirty);
  assert.strictEqual(clean, 'HelloWorldTest');
});

// --- 4. Scan Context Binding Tests ---
runTest('GeminiChat: Returns null when scan is null', () => {
  const ctx = buildScanContext(null, null);
  assert.strictEqual(ctx, null, 'Context must be null when scan is null');
});

runTest('GeminiChat: Injects finding context into scan context', () => {
  const mockScan = {
    id: 'scan-123',
    target: 'https://example.com',
    status: 'completed',
    scannerSource: 'nuclei',
    completedAt: '2026-10-25T12:00:00Z',
    stats: { critical: 0, high: 1, medium: 0, low: 0, informational: 0 },
    findings: [
      {
        id: 'finding-1',
        title: 'Missing Content Security Policy',
        severity: 'high',
        category: 'headers',
        evidence: 'CSP header not found',
        recommendation: 'Add CSP header in Nginx configuration',
      },
    ],
  };

  const ctx = buildScanContext(mockScan, 'finding-1');
  assert.ok(ctx.includes('Missing Content Security Policy'));
  assert.ok(ctx.includes('CSP header not found'));
  assert.ok(ctx.includes('Add CSP header in Nginx configuration'));
  assert.ok(ctx.includes('SCAN CONTEXT (UNTRUSTED DATA'));
});

// Summary
console.log('\n==================================================');
console.log(`TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log('==================================================\n');

if (failed > 0) {
  process.exit(1);
}
