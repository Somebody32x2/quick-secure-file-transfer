/**
 * Direct peer-to-peer via a WebRTC data channel.
 *
 * This is the preferred live path: the bytes never touch the server at all, and
 * on a shared LAN it is also by far the fastest. When it cannot be established
 * - symmetric NAT, blocked UDP, no WebRTC in the WebView - the caller falls
 * back to the encrypted relay. There is deliberately no TURN server configured
 * by default: relaying through our own server, where the payload is already
 * double-encrypted, is preferable to routing it through a third party.
 */

import type { Signal } from './signal.js';

export interface IceServerConfig {
  urls: string | string[];
  username?: string;
  credential?: string;
}

type SignalPayload =
  | { kind: 'sdp'; sdp: RTCSessionDescriptionInit }
  | { kind: 'ice'; candidate: RTCIceCandidateInit | null };

const CHANNEL_LABEL = 'qsft';

export interface DirectConnection {
  channel: RTCDataChannel;
  pc: RTCPeerConnection;
  /** e.g. "host" (same LAN), "srflx" (through NAT) - shown in the UI. */
  candidateType: string;
}

/**
 * Attempt a direct connection. Resolves null on timeout or failure - never
 * throws for an ordinary "it just didn't work", because the fallback is normal.
 */
export async function tryDirectConnection(
  signal: Signal,
  role: 'offerer' | 'answerer',
  iceServers: IceServerConfig[],
  timeoutMs = 12_000,
): Promise<DirectConnection | null> {
  if (typeof RTCPeerConnection !== 'function') return null;

  let pc: RTCPeerConnection;
  try {
    pc = new RTCPeerConnection({ iceServers: iceServers as RTCIceServer[] });
  } catch {
    return null;
  }

  return new Promise<DirectConnection | null>((resolve) => {
    let settled = false;
    const pendingRemoteCandidates: RTCIceCandidateInit[] = [];
    let remoteDescriptionSet = false;

    const finish = (result: DirectConnection | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (!result) { try { pc.close(); } catch { /* already closed */ } }
      resolve(result);
    };

    const timer = setTimeout(() => finish(null), timeoutMs);

    const onOpen = async (channel: RTCDataChannel) => {
      channel.binaryType = 'arraybuffer';
      let candidateType = 'unknown';
      try {
        const stats = await pc.getStats();
        stats.forEach((report: any) => {
          if (report.type === 'candidate-pair' && report.state === 'succeeded' && report.localCandidateId) {
            const local = stats.get(report.localCandidateId) as any;
            if (local?.candidateType) candidateType = local.candidateType;
          }
        });
      } catch { /* stats are advisory only */ }
      finish({ channel, pc, candidateType });
    };

    pc.onicecandidate = (ev) => {
      signal.sendSignal({ kind: 'ice', candidate: ev.candidate ? ev.candidate.toJSON() : null } satisfies SignalPayload);
    };
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'failed' || pc.connectionState === 'closed') finish(null);
    };

    signal.onSignal(async (raw) => {
      const payload = raw as SignalPayload;
      try {
        if (payload?.kind === 'sdp') {
          await pc.setRemoteDescription(payload.sdp);
          remoteDescriptionSet = true;
          for (const c of pendingRemoteCandidates.splice(0)) {
            await pc.addIceCandidate(c).catch(() => {});
          }
          if (payload.sdp.type === 'offer') {
            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);
            signal.sendSignal({ kind: 'sdp', sdp: answer } satisfies SignalPayload);
          }
        } else if (payload?.kind === 'ice') {
          if (!payload.candidate) return;
          // Candidates can arrive before the description they belong to.
          if (!remoteDescriptionSet) pendingRemoteCandidates.push(payload.candidate);
          else await pc.addIceCandidate(payload.candidate).catch(() => {});
        }
      } catch {
        finish(null);
      }
    });

    if (role === 'offerer') {
      const channel = pc.createDataChannel(CHANNEL_LABEL, { ordered: true });
      channel.binaryType = 'arraybuffer';
      channel.onopen = () => void onOpen(channel);
      channel.onerror = () => finish(null);
      void (async () => {
        try {
          const offer = await pc.createOffer();
          await pc.setLocalDescription(offer);
          signal.sendSignal({ kind: 'sdp', sdp: offer } satisfies SignalPayload);
        } catch {
          finish(null);
        }
      })();
    } else {
      pc.ondatachannel = (ev) => {
        const channel = ev.channel;
        channel.binaryType = 'arraybuffer';
        if (channel.readyState === 'open') void onOpen(channel);
        else channel.onopen = () => void onOpen(channel);
        channel.onerror = () => finish(null);
      };
    }
  });
}
