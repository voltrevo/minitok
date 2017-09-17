'use strict';

const querystring = require('querystring');

const bs58check = require('bs58check');

const otMini = {};

const roles = ['moderator', 'publisher', 'subscriber'];

const getSessionBytes = sessionId => {
  const pieces = Buffer.from(sessionId.slice(2), 'base64')
    .toString('latin1')
    .split('~');

  const bytes = new Buffer(26);

  // create_dt
  bytes.writeDoubleBE(Number(pieces[3]), 0);

  // nonce
  Buffer.from(pieces[4], 'base64').copy(bytes, 8);

  return bytes;
};

otMini.minify = token => {
  if (token.slice(0, 4) !== 'T1==') {
    throw new TypeError(`Not an opentok token: ${token}`);
  }

  const topPieces = querystring.parse(Buffer.from(token.slice(4), 'base64').toString('latin1'));

  const sigPieces = topPieces.sig.split(':');
  topPieces.sig = sigPieces[0];
  topPieces.session_id = sigPieces[1].slice('session_id='.length);

  const bytes = new Buffer(67);
  let pos = 0;

  // partner id
  pos = bytes.writeUInt32BE(Number(topPieces.partner_id), pos);

  // sig
  pos += new Buffer(topPieces.sig, 'hex').copy(bytes, pos);

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
  const create_dt = sessionBytes.readDoubleBE(0);

  const nonceBytes = new Buffer(18);
  sessionBytes.copy(nonceBytes, 0, 8, 8 + 18);
  const nonce = nonceBytes.toString('base64');

  const sessionBeforeBase64 = ['1', partnerId, '', create_dt, nonce, '', ''].join('~');

  // TODO: Encode 1_ vs 2_
  return `2_${Buffer.from(sessionBeforeBase64)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/=*$/, '')}`;
};

otMini.expand = miniToken => {
  const bytes = bs58check.decode(miniToken);

  let pos = 0;

  const topPieces = {};

  topPieces.partner_id = String(bytes.readUInt32BE(pos));
  pos += 4;

  const sigBytes = new Buffer(20);
  bytes.copy(sigBytes, 0, pos);
  pos += 20;
  topPieces.sig = sigBytes.toString('hex');

  const sessionBytes = new Buffer(26);
  bytes.copy(sessionBytes, 0, pos, pos + 26);
  pos += 26;
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

const token =
  'T1==cGFydG5lcl9pZD00NTY5MTc3MSZzaWc9M2Y3ZjNmNTdlZGY5ZTY3OGU1NmY4NjljNWIzNzczZjJjYzgxMmQ2ZDpzZXNzaW9uX2lkPTJfTVg0ME5UWTVNVGMzTVg1LU1UVXdOVFEzTnpFd01Ua3dPSDV6YVN0MFMxTnZjVVl6V1ZKT1F6SmpiR05rWTBsS1NWQi1mZyZjcmVhdGVfdGltZT0xNTA1NDc3MTAyJm5vbmNlPTAuMjkzMjk2ODE0NzIxMTYzMiZyb2xlPW1vZGVyYXRvciZleHBpcmVfdGltZT0xNTA1NTYzNTAy';
const miniToken = otMini.minify(token);
console.log('before: ', token);
console.log('after:  ', miniToken);

const backToToken = otMini.expand(miniToken);
console.log('back:   ', backToToken);

console.log(token === backToToken ? 'matches' : 'does not match');

console.log((token.length / miniToken.length).toFixed(1));

module.exports = otMini;
