'use strict';

/* eslint-disable camelcase */

const querystring = require('querystring');

const bs58check = require('bs58check');

const minitok = {};

const roles = ['moderator', 'publisher', 'subscriber'];
const sessionPrefixes = ['1_', '2_'];

const tokenByteLength = 68;
const sessionByteLength = 27;

const bufferReadWriteFormats = {
  Int8: 1,
  Int16BE: 2,
  Int16LE: 2,
  Int32BE: 4,
  Int32LE: 4,
  UInt8: 1,
  UInt16BE: 2,
  UInt16LE: 2,
  UInt32BE: 4,
  UInt32LE: 4,
  DoubleBE: 8,
  DoubleLE: 8,
  FloatBE: 4,
  FloatLE: 4,
};

const writeBufferSequence = (buf, seq, offsetParam = 0) => {
  let offset = offsetParam;

  seq.forEach(([value, format]) => {
    if (format in bufferReadWriteFormats) {
      offset = buf[`write${format}`](value, offset);
    } else if (format === 'buffer') {
      offset += value.copy(buf, offset);
    } else {
      throw new Error(`Unexpected format: ${format}`);
    }
  });

  return offset;
};

const readBufferSequence = (buf, seq, offsetParam = 0) => {
  let offset = offsetParam;
  const results = [];

  seq.forEach(([format, len]) => {
    if (format in bufferReadWriteFormats) {
      results.push(buf[`read${format}`](offset));
      offset += bufferReadWriteFormats[format];
    } else if (format === 'buffer') {
      const bytes = Buffer.alloc(len);
      buf.copy(bytes, 0, offset, offset + len);
      offset += len;
      results.push(bytes);
    } else {
      throw new Error(`Unexpected format: ${format}`);
    }
  });

  return results;
};

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

  writeBufferSequence(bytes, [
    [topPieces.partner_id, 'UInt32BE'],
    [Buffer.from(topPieces.sig, 'hex'), 'buffer'],
    [getSessionBytes(topPieces.session_id), 'buffer'],
    [topPieces.create_time, 'UInt32BE'],
    [topPieces.nonce, 'DoubleBE'],
    [roles.indexOf(topPieces.role), 'UInt8'],
    [topPieces.expire_time, 'UInt32BE'],
  ]);

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

  const [
    partner_id,
    sigBytes,
    sessionBytes,
    create_time,
    nonce,
    roleIndex,
    expire_time,
  ] = readBufferSequence(bytes, [
    ['UInt32BE'],
    ['buffer', 20],
    ['buffer', sessionByteLength],
    ['UInt32BE'],
    ['DoubleBE'],
    ['UInt8'],
    ['UInt32BE'],
  ]);

  const sig = sigBytes.toString('hex');
  const session_id = getSessionId(partner_id, sessionBytes);
  const role = roles[roleIndex];

  const topPieces = {
    partner_id,
    sig,
    session_id,
    create_time,
    nonce,
    role,
    expire_time,
  };

  const stringified = querystring
    .stringify(topPieces, '&', '=', {
      encodeURIComponent: str => str,
    })
    .replace('&session_id', ':session_id');

  return `T1==${Buffer.from(stringified).toString('base64')}`;
};

module.exports = minitok;
