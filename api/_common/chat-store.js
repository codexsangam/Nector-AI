/**
 * Nector AI Chat Store
 * In-memory conversation history per session/user.
 * No secrets (API keys, passwords, tokens) are ever stored here.
 * Conversations are keyed by sessionId (anonymous) and optionally linked to a scanId.
 * History is bounded to prevent unbounded memory growth and reduce API costs.
 */

const MAX_HISTORY_PER_SESSION = parseInt(process.env.NECTOR_CHAT_HISTORY_LIMIT || '20', 10);

// Map<sessionId, { messages: [{role, content, timestamp}], scanId, createdAt, updatedAt }>
const conversations = new Map();

// Prune old sessions older than 2 hours to prevent memory leaks
const SESSION_TTL_MS = 2 * 60 * 60 * 1000;

function pruneOldSessions() {
  const now = Date.now();
  for (const [sessionId, session] of conversations.entries()) {
    if (now - new Date(session.updatedAt).getTime() > SESSION_TTL_MS) {
      conversations.delete(sessionId);
    }
  }
}

/**
 * Get or create a conversation session.
 * @param {string} sessionId - Unique session identifier (e.g., from cookie or generated client-side)
 * @param {string|null} scanId - Optional scan to associate with this conversation
 */
export function getOrCreateSession(sessionId, scanId = null) {
  if (!conversations.has(sessionId)) {
    const now = new Date().toISOString();
    conversations.set(sessionId, {
      sessionId,
      scanId,
      messages: [],
      createdAt: now,
      updatedAt: now,
    });
  }
  return conversations.get(sessionId);
}

/**
 * Retrieve the current chat history for a session, formatted for Gemini API.
 * Returns only the last N turns to bound context size.
 */
export function getChatHistory(sessionId) {
  const session = conversations.get(sessionId);
  if (!session) return [];
  // Return last MAX_HISTORY_PER_SESSION messages
  return session.messages.slice(-MAX_HISTORY_PER_SESSION);
}

/**
 * Append a user or model message to the conversation.
 * Automatically evicts old messages beyond the limit.
 */
export function appendMessage(sessionId, role, content) {
  const session = getOrCreateSession(sessionId);
  session.messages.push({
    role, // 'user' | 'model'
    content,
    timestamp: new Date().toISOString(),
  });
  // Evict oldest messages if over limit
  if (session.messages.length > MAX_HISTORY_PER_SESSION) {
    session.messages = session.messages.slice(-MAX_HISTORY_PER_SESSION);
  }
  session.updatedAt = new Date().toISOString();
}

/**
 * Clear the conversation history for a session (but keep the session itself).
 */
export function clearConversation(sessionId) {
  const session = conversations.get(sessionId);
  if (session) {
    session.messages = [];
    session.updatedAt = new Date().toISOString();
  }
}

/**
 * Update the scan context associated with a session.
 */
export function updateSessionScanId(sessionId, scanId) {
  const session = conversations.get(sessionId);
  if (session) {
    session.scanId = scanId;
    session.updatedAt = new Date().toISOString();
  }
}

/**
 * Return a summary of the session (without message content) for debugging.
 */
export function getSessionMeta(sessionId) {
  const session = conversations.get(sessionId);
  if (!session) return null;
  return {
    sessionId: session.sessionId,
    scanId: session.scanId,
    messageCount: session.messages.length,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
  };
}

// Run pruning on a periodic schedule (every 30 minutes)
setInterval(pruneOldSessions, 30 * 60 * 1000);

export default {
  getOrCreateSession,
  getChatHistory,
  appendMessage,
  clearConversation,
  updateSessionScanId,
  getSessionMeta,
};
