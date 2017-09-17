'use strict';

/* eslint-disable camelcase */

const querystring = require('querystring');

const bs58check = require('bs58check');

const minitok = {};

const roles = ['moderator', 'publisher', 'subscriber'];
const sessionPrefixes = ['1_', '2_'];

const tokenByteLength = 68;
const sessionByteLength = 27;

const getSessionBytes = sessionId => {
  const bytes = Buffer.alloc(sessionByteLength);

  const prefixType = sessionPrefixes.indexOf(sessionId.slice(0, 2));
  bytes.writeUInt8(prefixType, 0);

  const pieces = Buffer.from(sessionId.slice(2), 'base64')
    .toString('latin1')
    .split('~');

  // create_dt
  bytes.writeDoubleBE(Number(pieces[3]), 1);

  // nonce
  Buffer.from(pieces[4], 'base64').copy(bytes, 9);

  return bytes;
};

minitok.minify = token => {
  if (token.slice(0, 4) !== 'T1==') {
    throw new TypeError(`Not an opentok token: ${token}`);
  }

  const topPieces = querystring.parse(Buffer.from(token.slice(4), 'base64').toString('latin1'));

  const sigPieces = topPieces.sig.split(':');
  topPieces.sig = sigPieces[0];
  topPieces.session_id = sigPieces[1].slice('session_id='.length);

  const bytes = Buffer.alloc(tokenByteLength);
  let pos = 0; // eslint-disable-line no-unused-vars

  // partner id
  pos = bytes.writeUInt32BE(Number(topPieces.partner_id), pos);

  // sig
  pos += Buffer.from(topPieces.sig, 'hex').copy(bytes, pos);

  // session id
  pos += getSessionBytes(topPieces.session_id).copy(bytes, pos);

  // create_time
  pos = bytes.writeUInt32BE(Number(topPieces.create_time), pos);

  // nonce
  pos = bytes.writeDoubleBE(Number(topPieces.nonce), pos);

  // role
  pos = bytes.writeUInt8(roles.indexOf(topPieces.role), pos);

  // expire_time
  pos = bytes.writeUInt32BE(Number(topPieces.expire_time), pos);

  return bs58check.encode(bytes);
};

const getSessionId = (partnerId, sessionBytes) => {
  const prefix = sessionPrefixes[sessionBytes.readUInt8(0)];

  const create_dt = sessionBytes.readDoubleBE(1);

  const nonceBytes = Buffer.alloc(18);
  sessionBytes.copy(nonceBytes, 0, 9, 9 + 18);
  const nonce = nonceBytes.toString('base64');

  const sessionBeforeBase64 = ['1', partnerId, '', create_dt, nonce, '', ''].join('~');

  return `${prefix}${Buffer.from(sessionBeforeBase64)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/=*$/, '')}`;
};

minitok.expand = miniToken => {
  const bytes = bs58check.decode(miniToken);

  let pos = 0;

  const topPieces = {};

  topPieces.partner_id = String(bytes.readUInt32BE(pos));
  pos += 4;

  const sigBytes = Buffer.alloc(20);
  bytes.copy(sigBytes, 0, pos);
  pos += 20;
  topPieces.sig = sigBytes.toString('hex');

  const sessionBytes = Buffer.alloc(sessionByteLength);
  bytes.copy(sessionBytes, 0, pos, pos + sessionByteLength);
  pos += sessionByteLength;
  topPieces.session_id = getSessionId(topPieces.partner_id, sessionBytes);

  topPieces.create_time = String(bytes.readUInt32BE(pos));
  pos += 4;

  topPieces.nonce = String(bytes.readDoubleBE(pos));
  pos += 8;

  topPieces.role = roles[bytes.readUInt8(pos)];
  pos += 1;

  topPieces.expire_time = String(bytes.readUInt32BE(pos));
  pos += 4;

  const stringified = querystring
    .stringify(topPieces, '&', '=', {
      encodeURIComponent: str => str,
    })
    .replace('&session_id', ':session_id');

  return `T1==${Buffer.from(stringified).toString('base64')}`;
};

module.exports = minitok;
