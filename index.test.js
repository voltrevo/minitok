'use strict';

/* eslint-env jest/globals */

const minitok = require('./index.js');

test('minify and expand recovers original token', () => {
  const token =
    'T1==cGFydG5lcl9pZD00NTY5MTc3MSZzaWc9M2Y3ZjNmNTdlZGY5ZTY3OGU1NmY4NjljNWIzNzczZjJjYzgxMmQ2ZDpzZXNzaW9uX2lkPTJfTVg0ME5UWTVNVGMzTVg1LU1UVXdOVFEzTnpFd01Ua3dPSDV6YVN0MFMxTnZjVVl6V1ZKT1F6SmpiR05rWTBsS1NWQi1mZyZjcmVhdGVfdGltZT0xNTA1NDc3MTAyJm5vbmNlPTAuMjkzMjk2ODE0NzIxMTYzMiZyb2xlPW1vZGVyYXRvciZleHBpcmVfdGltZT0xNTA1NTYzNTAy';
  const miniToken = minitok.minify(token);
  const backToToken = minitok.expand(miniToken);

  expect(backToToken).toEqual(token);
});
