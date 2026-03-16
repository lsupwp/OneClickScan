const WebSocket = require('ws');

let wss = null;
const jobSubscriptions = new Map(); // jobId -> Set<ws>
const jobMessageBuffer = new Map(); // jobId -> Array<payload>
const JOB_BUFFER_LIMIT = 50;

function initWebSocket(server) {
  wss = new WebSocket.Server({ server });

  wss.on('connection', (ws) => {
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message.toString());
        if (data.type === 'subscribe' && data.jobId) {
          subscribe(ws, data.jobId);
          // ack + replay last messages (useful for race conditions)
          ws.send(JSON.stringify({ type: 'subscribed', jobId: data.jobId }));
          const buf = jobMessageBuffer.get(data.jobId);
          if (buf && buf.length) {
            for (const payload of buf) {
              if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify(payload));
              }
            }
          }
        }
      } catch {
        // ignore malformed messages
      }
    });

    ws.on('close', () => {
      for (const [, set] of jobSubscriptions.entries()) {
        set.delete(ws);
      }
    });
  });

  return wss;
}

function subscribe(ws, jobId) {
  if (!jobSubscriptions.has(jobId)) {
    jobSubscriptions.set(jobId, new Set());
  }
  jobSubscriptions.get(jobId).add(ws);
}

function broadcastToJob(jobId, payload) {
  if (!jobMessageBuffer.has(jobId)) jobMessageBuffer.set(jobId, []);
  const buf = jobMessageBuffer.get(jobId);
  buf.push(payload);
  if (buf.length > JOB_BUFFER_LIMIT) buf.splice(0, buf.length - JOB_BUFFER_LIMIT);

  const set = jobSubscriptions.get(jobId);
  if (!set) return;

  const data = JSON.stringify(payload);
  for (const ws of set) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data);
    }
  }
}

module.exports = {
  initWebSocket,
  broadcastToJob,
};

