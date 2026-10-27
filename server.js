import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import rateLimit from 'express-rate-limit';

import { shouldSkip } from './api/_common/check-skipper.js';
import { queueScan, retryAiExplanation } from './api/_common/scan-orchestrator.js';
import { getScanRecord, listScanRecords } from './api/_common/scan-store.js';
import { checkZapAvailable } from './api/_common/zap-runner.js';
import { checkNucleiAvailable } from './api/_common/nuclei-runner.js';
import { getGeminiConfig } from './api/_common/gemini-explainer.js';
import { sendChatMessage } from './api/_common/gemini-chat.js';
import { clearConversation } from './api/_common/chat-store.js';

// Load environment variables from .env file
dotenv.config();

// Log unexpected errors, instead of letting em crash everything
process.on('uncaughtException', (error) => console.error('Uncaught exception:', error));
process.on('unhandledRejection', (error) => console.error('Unhandled rejection:', error));

// Create the Express app
const app = express();

const trustProxy = process.env.TRUST_PROXY;
if (trustProxy) {
  const parsed = /^\d+$/.test(trustProxy)
    ? parseInt(trustProxy, 10)
    : trustProxy === 'true'
      ? true
      : trustProxy === 'false'
        ? false
        : trustProxy;
  app.set('trust proxy', parsed);
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const port = process.env.PORT || 3000; // The port to run the server on
const API_DIR = '/api'; // Name of the dir containing the lambda functions
const dirPath = path.join(__dirname, API_DIR); // Path to the lambda functions dir
const guiPath = path.join(__dirname, 'dist', 'client');
const placeholderFilePath = path.join(__dirname, 'public', 'placeholder.html');
const handlers = {}; // Will store list of API endpoints
const { version } = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf-8'));
const apiFiles = fs
  .readdirSync(dirPath, { withFileTypes: true })
  .filter((dirent) => dirent.isFile() && dirent.name.endsWith('.js'));
process.env.WC_SERVER = 'true'; // Tells middleware to return in non-lambda mode

// Enable CORS
app.use(
  cors({
    origin: process.env.API_CORS_ORIGIN || '*',
  }),
);

// Enable JSON and URL-encoded body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sits above the GUI catch-all, so it still answers even when the app itself is broken
app.get('/healthz', (req, res) => {
  res.set('Cache-Control', 'no-store'); // Stops a proxy handing a monitor a stale "ok"
  res.status(200).json({
    status: 'ok',
    // Routes register async, so we're listening a moment before they're actually live
    ready: Object.keys(handlers).length === apiFiles.length,
    version,
    uptime: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

// Define max requests within each time frame
const limits = [
  { timeFrame: 10 * 60, max: 100, messageTime: '10 minutes' },
  { timeFrame: 60 * 60, max: 250, messageTime: '1 hour' },
  { timeFrame: 12 * 60 * 60, max: 500, messageTime: '12 hours' },
];

// Construct a message to be returned if the user has been rate-limited
const makeLimiterResponseMsg = (retryAfter) => {
  const why =
    'This keeps the service running smoothly for everyone. ' +
    'You can get around these limits by running your own instance of Web Check.';
  return `You've been rate-limited, please try again in ${retryAfter} seconds.\n${why}`;
};

// Create rate limiters for each time frame
const limiters = limits.map((limit) =>
  rateLimit({
    windowMs: limit.timeFrame * 1000,
    limit: limit.max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: makeLimiterResponseMsg(limit.messageTime) },
  }),
);

// If rate-limiting enabled, then apply the limiters to the /api endpoint
if (process.env.API_ENABLE_RATE_LIMIT === 'true') {
  app.use(API_DIR, limiters);
}

// ==========================================
// Nector Security Scanning & AI API Routes
// ==========================================

// POST /api/scan: Submit target URL for background Nuclei + Gemini scan
app.post('/api/scan', async (req, res) => {
  try {
    const url = req.body?.url || req.query?.url;
    if (!url) {
      return res.status(400).json({ error: 'Missing required parameter: url' });
    }
    const result = await queueScan(url);
    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }
    return res.status(202).json(result);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/scan/:id: Query real-time status and findings of a scan
app.get('/api/scan/:id', (req, res) => {
  const scan = getScanRecord(req.params.id);
  if (!scan) {
    return res.status(404).json({ error: `Scan not found: ${req.params.id}` });
  }
  return res.json(scan);
});

// POST /api/scan/:id/retry-ai: Retry Gemini explanation for findings
app.post('/api/scan/:id/retry-ai', async (req, res) => {
  try {
    const findingId = req.body?.findingId;
    const result = await retryAiExplanation(req.params.id, findingId);
    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/scans: List recent scan jobs
app.get('/api/scans', (req, res) => {
  const limit = Math.min(100, parseInt(req.query.limit || '20', 10));
  return res.json(listScanRecords(limit));
});

// GET /api/scanner-status: Check availability of OWASP ZAP, Nuclei scanner, and Gemini AI
app.get('/api/scanner-status', async (req, res) => {
  const zap = await checkZapAvailable();
  const nuclei = await checkNucleiAvailable();
  const gemini = getGeminiConfig();
  return res.json({
    zap,
    nuclei,
    gemini: {
      configured: gemini.isConfigured,
      model: gemini.model,
    },
  });
});

// POST /api/chat: Nector AI Security Assistant chat endpoint
app.post('/api/chat', async (req, res) => {
  const { sessionId, message, scanId, findingId } = req.body || {};
  if (!sessionId || typeof sessionId !== 'string' || sessionId.length > 128) {
    return res.status(400).json({ error: 'Missing or invalid sessionId.' });
  }
  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'Missing message.' });
  }
  try {
    const result = await sendChatMessage({
      sessionId: sessionId.slice(0, 128),
      userMessage: message,
      scanId: scanId || null,
      findingId: findingId || null,
    });
    if (!result.success) {
      const statusCode = result.unconfigured ? 503 : 500;
      return res.status(statusCode).json({ error: result.error, unconfigured: result.unconfigured || false });
    }
    return res.json({ reply: result.reply, model: result.model });
  } catch (err) {
    return res.status(500).json({ error: 'Chat request failed: ' + err.message });
  }
});

// POST /api/chat/clear: Clear conversation history for a session
app.post('/api/chat/clear', (req, res) => {
  const { sessionId } = req.body || {};
  if (!sessionId || typeof sessionId !== 'string') {
    return res.status(400).json({ error: 'Missing sessionId.' });
  }
  clearConversation(sessionId.slice(0, 128));
  return res.json({ success: true });
});

// Read and register each API function as an Express routes
apiFiles.forEach(async (dirent) => {
  const routeName = dirent.name.split('.')[0];
  const route = `${API_DIR}/${routeName}`;

  const handlerModule = await import(pathToFileURL(path.join(dirPath, dirent.name)).href);
  const handler = handlerModule.default || handlerModule;
  handlers[route] = handler;

  app.get(route, async (req, res) => {
    try {
      await handler(req, res);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
});

const renderPlaceholderPage = async (res, msgId, logs) => {
  const errorMessages = {
    notCompiled:
      'Looks like the GUI app has not yet been compiled.<br />' +
      'Run <code>yarn build</code> to continue, then restart the server.',
    notCompiledSsrHandler:
      'Server-side rendering failed to initiate, as SSR handler not found.<br />' +
      'This can be fixed by running <code>yarn build</code>, then restarting the server.<br />',
    disabledGui:
      'Web-Check API is up and running!<br />Access the endpoints at ' +
      `<a href="${API_DIR}"><code>${API_DIR}</code></a>`,
  };
  const logOutput = logs ? `<div class="logs"><code>${logs}</code></div>` : '';
  const errorMessage = (errorMessages[msgId] || 'An mystery error occurred.') + logOutput;
  const placeholderContent = await fs.promises.readFile(placeholderFilePath, 'utf-8');
  const htmlContent = placeholderContent.replace('<!-- CONTENT -->', errorMessage);
  res.status(500).send(htmlContent);
};

// Create a single API endpoint to execute all lambda functions
app.get(API_DIR, async (req, res) => {
  const results = {};
  const { url } = req.query;
  const maxExecutionTime = process.env.PUBLIC_API_TIMEOUT_LIMIT || 60000;

  const executeHandler = async (handler, req) => {
    return new Promise(async (resolve, reject) => {
      try {
        const mockRes = {
          status: () => mockRes,
          json: (body) => resolve({ body }),
        };
        await handler({ ...req, query: { url } }, mockRes);
      } catch (err) {
        reject(err);
      }
    });
  };

  const timeout = (ms, jobName = null) => {
    return new Promise((_, reject) => {
      setTimeout(() => {
        reject(
          new Error(
            `Timed out after ${ms / 1000} seconds${jobName ? `, when executing ${jobName}` : ''}`,
          ),
        );
      }, ms);
    });
  };

  const handlerPromises = Object.entries(handlers).map(async ([route, handler]) => {
    const routeName = route.replace(`${API_DIR}/`, '');

    const { skip, reason } = shouldSkip(routeName, url);
    if (skip) {
      results[routeName] = { skipped: reason };
      return;
    }

    try {
      const result = await Promise.race([
        executeHandler(handler, req, res),
        timeout(maxExecutionTime, routeName),
      ]);
      results[routeName] = result.body;
    } catch (err) {
      results[routeName] = { error: err.message };
    }
  });

  await Promise.all(handlerPromises);
  res.json(results);
});

// Serve the Nector UI if present, or compiled Astro GUI, or placeholder
const nectorGuiPath = path.join(__dirname, 'threatforge');

if (process.env.DISABLE_GUI && process.env.DISABLE_GUI !== 'false') {
  app.get('/', async (req, res) => {
    renderPlaceholderPage(res, 'disabledGui');
  });
} else if (fs.existsSync(nectorGuiPath)) {
  // Serve the Nector UI directly from the same origin as API
  app.use(express.static(nectorGuiPath));
  app.get('/', (req, res) => {
    res.sendFile(path.join(nectorGuiPath, 'index.html'));
  });
  app.get('/check', (req, res) => {
    res.sendFile(path.join(nectorGuiPath, 'index.html'));
  });
} else if (fs.existsSync(guiPath)) {
  // GUI enabled, and Astro build files present
  app.use((req, res, next) => {
    if (req.path === '/' && process.env.BOSS_SERVER !== 'true') {
      return res.redirect(302, '/check');
    }
    next();
  });
  app.use(express.static('dist/client/'));
  app.use(async (req, res, next) => {
    const ssrHandlerPath = path.join(__dirname, 'dist', 'server', 'entry.mjs');
    import(pathToFileURL(ssrHandlerPath).href)
      .then(({ handler: ssrHandler }) => {
        ssrHandler(req, res, next);
      })
      .catch(async (err) => {
        renderPlaceholderPage(res, 'notCompiledSsrHandler', err.message);
      });
  });
} else {
  app.get('/', async (req, res) => {
    renderPlaceholderPage(res, 'notCompiled');
  });
}

// Anything left unhandled (which isn't an API endpoint), return a 404
app.use((req, res, next) => {
  if (!req.path.startsWith(`${API_DIR}/`)) {
    res.status(404).sendFile(path.join(__dirname, 'public', 'error.html'));
  } else {
    next();
  }
});

// Print nice welcome message to user
const printMessage = () => {
  console.log(
    `\x1b[36m\n` +
      '    _   _           _             \n' +
      '   | \\ | | ___  ___| |_ ___  _ __ \n' +
      "   |  \\| |/ _ \\/ __| __/ _ \\| '__|\\n" +
      '   | |\\  |  __/ (__| || (_) | |   \n' +
      '   |_| \\_|\\___|\\___|\\__\\___/|_|   \n' +
      `\x1b[0m\n`,
    `\x1b[1m\x1b[32m🚀 Nector is up and running at http://localhost:${port} \x1b[0m\n\n`,
    `\x1b[2m\x1b[36m🛡️  AI-Powered Website Security Assessment Platform\n`,
    `🔍 Scanner cascade: OWASP ZAP → Nuclei → Nector Built-in Engine\x1b[0m`,
  );
};

// Create server
app.listen(port, () => {
  printMessage();
});
