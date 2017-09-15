'use strict';

const querystring = require('querystring');

const bs58check = require('bs58check');

const otMini = {};

const roles = ['moderator', 'publisher', 'subscriber'];

const getSessionBytes = (sessionId) => {
  const pieces = Buffer.from(sessionId.slice(2), 'base64').toString('latin1').split('~');

  const bytes = new Buffer(26);
  bytes.writeDoubleBE(Number(pieces[3]), 0);

  Buffer.from(pieces[4], 'base64').copy(bytes, 8);

  return bytes;
};

otMini.minify = (token) => {
  if (token.slice(0, 4) !== 'T1==') {
    throw new TypeError('Not an opentok token: ' + token);
  }

  const topPieces = querystring.parse(
    Buffer.from(token.slice(4), 'base64').toString('latin1')
  );

  const sigPieces = topPieces.sig.split(':');
  topPieces.sig = sigPieces[0];
  topPieces.session_id = sigPieces[1].slice('session_id='.length);

  let bytes = new Buffer(67);
  let pos = 0;

  // partner id
  pos = bytes.writeInt32BE(Number(topPieces.partner_id), pos);
  console.log('partner_id', pos);

  // sig
  pos += (new Buffer(topPieces.sig, 'hex')).copy(bytes, pos);
  console.log('sig', pos);

  // session id
  pos += getSessionBytes(topPieces.session_id).copy(bytes, pos);
  console.log('session_id', pos);

  // create_time
  pos = bytes.writeInt32BE(Number(topPieces.create_time), pos);
  console.log('create_time', pos);

  // nonce
  pos = bytes.writeDoubleBE(Number(topPieces.nonce), pos);

  // role
  pos = bytes.writeInt8(roles.indexOf(topPieces.role), pos);

  // expire_time
  pos = bytes.writeInt32BE(Number(topPieces.expire_time), pos);

  return bs58check.encode(bytes);
};

const token = 'T1==cGFydG5lcl9pZD00NTY5MTc3MSZzaWc9M2Y3ZjNmNTdlZGY5ZTY3OGU1NmY4NjljNWIzNzczZjJjYzgxMmQ2ZDpzZXNzaW9uX2lkPTJfTVg0ME5UWTVNVGMzTVg1LU1UVXdOVFEzTnpFd01Ua3dPSDV6YVN0MFMxTnZjVVl6V1ZKT1F6SmpiR05rWTBsS1NWQi1mZyZjcmVhdGVfdGltZT0xNTA1NDc3MTAyJm5vbmNlPTAuMjkzMjk2ODE0NzIxMTYzMiZyb2xlPW1vZGVyYXRvciZleHBpcmVfdGltZT0xNTA1NTYzNTAy';
const miniToken = otMini.minify(token);
console.log('before: ', token);
console.log('after:  ', miniToken);

console.log((token.length / miniToken.length).toFixed(1))

module.exports = otMini;
