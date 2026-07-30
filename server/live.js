/**
 * Live transfer: signalling for the direct P2P path, and a blind relay for when
 * P2P cannot be established.
 *
 * What the server does here: forwards opaque frames between exactly two
 * sockets. What it does not do: buffer the file, write anything to disk, or
 * hold a key. Frames pass through and are dropped on the floor. The payload is
 * already double-encrypted (passphrase container inside the hybrid-PQ session
 * channel), so the relay sees ciphertext under a key it never had a chance to
 * learn.
 *
 * Backpressure is credit-based end-to-end: the receiver grants the sender
 * permission to send N more frames. Those credits travel *inside* the encrypted
 * frames, so this server can neither read nor forge them - it only ever sees
 * opaque bytes. The effect is that in-flight memory here stays at a handful of
 * frames rather than a 2 GB file, which is the whole point.
 */

import { config } from './config.js';
import { isValidCode, socketIp } from './util.js';
import { checkCodeLookup, noteFailure, noteSuccess } from './guard.js';
import * as codes from './codes.js';

/** @type {Map<string, {code:string, hostId:string, guestId:string|null, ownerIp:string, createdAt:number, lastActivity:number}>} */
const rooms = new Map();
/** @type {Map<string, string>} socket id -> room code */
const socketRoom = new Map();
/** @type {Map<string, number>} ip -> rooms currently hosted */
const roomsByIp = new Map();
/** @type {Map<string, number>} ip -> sockets currently connected */
const socketsByIp = new Map();

/** Server refuses to hold more than this per socket before giving up. */
const MAX_SOCKET_BUFFER_BYTES = 8 * 1024 * 1024;

function allocateCode(socketId) {
  return codes.allocate('live', socketId);
}

function peerIdOf(room, socketId) {
  if (room.hostId === socketId) return room.guestId;
  if (room.guestId === socketId) return room.hostId;
  return null;
}

function closeRoom(io, room, reason, exceptSocketId = null) {
  for (const id of [room.hostId, room.guestId]) {
    if (!id) continue;
    socketRoom.delete(id);
    if (id === exceptSocketId) continue;
    io.to(id).emit('live:peer-left', { reason });
  }
  rooms.delete(room.code);
  codes.release(room.code);
  releaseRoomSlot(room.ownerIp);
}

function takeRoomSlot(ip) {
  const held = roomsByIp.get(ip) ?? 0;
  if (held >= config.liveRoomsPerIp) return false;
  roomsByIp.set(ip, held + 1);
  return true;
}

function releaseRoomSlot(ip) {
  const held = roomsByIp.get(ip);
  if (!held) return;
  if (held <= 1) roomsByIp.delete(ip);
  else roomsByIp.set(ip, held - 1);
}

/**
 * Forward a frame to the room peer. Returns false when there is no peer or the
 * peer is too far behind, in which case the sender is told to stop.
 */
function forward(io, socket, event, payload) {
  const code = socketRoom.get(socket.id);
  const room = code ? rooms.get(code) : null;
  if (!room) {
    socket.emit('live:error', { message: 'You are not in a live session' });
    return false;
  }
  room.lastActivity = Date.now();

  const peerId = peerIdOf(room, socket.id);
  if (!peerId) {
    socket.emit('live:error', { message: 'The other device is not connected' });
    return false;
  }

  const peer = io.sockets.sockets.get(peerId);
  if (!peer) {
    closeRoom(io, room, 'peer disconnected', socket.id);
    socket.emit('live:peer-left', { reason: 'peer disconnected' });
    return false;
  }

  // Safety valve. Credits should prevent this; if they somehow do not, drop the
  // session rather than let the relay accumulate a file in memory.
  const buffered = peer.conn?.writeBuffer?.length ?? 0;
  if (buffered > 256) {
    closeRoom(io, room, 'relay congested');
    return false;
  }

  peer.emit(event, payload);
  return true;
}

export function attachLive(io) {
  io.on('connection', (socket) => {
    const ip = socketIp(socket);

    /**
     * Sockets are free to open and each one is an independent identity for
     * anything keyed on the connection rather than the address. Capping them
     * per address is what stops guessing being parallelised across a thousand
     * cheap connections to sidestep the per-address throttle on `live:join`.
     */
    const open = (socketsByIp.get(ip) ?? 0) + 1;
    if (open > config.maxSocketsPerIp) {
      socket.emit('live:error', { message: 'Too many connections from this device.' });
      socket.disconnect(true);
      return;
    }
    socketsByIp.set(ip, open);
    socket.on('disconnect', () => {
      const held = socketsByIp.get(ip);
      if (!held) return;
      if (held <= 1) socketsByIp.delete(ip);
      else socketsByIp.set(ip, held - 1);
    });

    socket.on('live:host', (_payload, ack) => {
      if (socketRoom.has(socket.id)) {
        ack?.({ error: 'Already in a session' });
        return;
      }
      // Hosting reserves a code from the shared registry and holds it for the
      // room's idle lifetime, so one address must not be able to hoard them.
      if (!takeRoomSlot(ip)) {
        ack?.({ error: 'Too many open sessions from this device. Finish one first.' });
        return;
      }
      const code = allocateCode(socket.id);
      if (!code) {
        releaseRoomSlot(ip);
        ack?.({ error: 'Server is busy; try again' });
        return;
      }
      rooms.set(code, {
        code, hostId: socket.id, guestId: null, ownerIp: ip,
        createdAt: Date.now(), lastActivity: Date.now(),
      });
      socketRoom.set(socket.id, code);
      ack?.({ code });
    });

    socket.on('live:join', (payload, ack) => {
      const code = payload?.code;
      // Checked before the throttle, exactly as the HTTP path does: a malformed
      // code is not a guess at the space and must not consume anyone's budget.
      if (!isValidCode(code)) {
        ack?.({ error: 'Codes are six digits' });
        return;
      }
      if (socketRoom.has(socket.id)) {
        ack?.({ error: 'Already in a session' });
        return;
      }
      // The reason this exists: unthrottled, this event walks the entire 10^6
      // code space in minutes, and a successful guess takes the room's only
      // guest slot. It shares one budget with the HTTP lookup deliberately.
      const verdict = checkCodeLookup(ip, code);
      if (!verdict.allowed) {
        ack?.({ error: verdict.message, retryAfterSeconds: verdict.retryAfterSeconds });
        return;
      }
      const room = rooms.get(code);
      if (!room) {
        noteFailure(code);
        ack?.({ error: 'No live session with that code. Check the sender is still waiting.' });
        return;
      }
      // One receiver at a time, per the requirement. The code was real either
      // way, so this was not a guess and the attempt is refunded.
      if (room.guestId) {
        noteSuccess(ip, code);
        ack?.({ error: 'This transfer already has a receiver connected.' });
        return;
      }
      noteSuccess(ip, code);
      room.guestId = socket.id;
      room.lastActivity = Date.now();
      socketRoom.set(socket.id, code);
      ack?.({ ok: true });
      io.to(room.hostId).emit('live:peer-joined', {});
    });

    // Handshake and WebRTC negotiation. Opaque to the server.
    socket.on('live:signal', (payload) => {
      forward(io, socket, 'live:signal', payload);
    });

    // Relay path: encrypted file frames.
    socket.on('live:data', (payload) => {
      const size = payload?.byteLength ?? payload?.length ?? 0;
      if (size > config.relayMaxFrameBytes) {
        socket.emit('live:error', { message: 'Frame too large' });
        return;
      }
      forward(io, socket, 'live:data', payload);
    });

    socket.on('live:bye', () => {
      const code = socketRoom.get(socket.id);
      const room = code ? rooms.get(code) : null;
      if (room) closeRoom(io, room, 'the other device ended the session', socket.id);
      socketRoom.delete(socket.id);
    });

    socket.on('disconnect', () => {
      const code = socketRoom.get(socket.id);
      const room = code ? rooms.get(code) : null;
      socketRoom.delete(socket.id);
      if (room) closeRoom(io, room, 'the other device disconnected', socket.id);
    });
  });

  const timer = setInterval(() => {
    const now = Date.now();
    for (const room of [...rooms.values()]) {
      if (now - room.lastActivity > config.liveRoomIdleMs) {
        closeRoom(io, room, 'session timed out');
      }
    }
  }, 60_000);
  timer.unref();
}

export function liveStats() {
  return { rooms: rooms.size };
}
