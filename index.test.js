'use strict';

/* eslint-env jest/globals */

const minitok = require('./index.js');

test('minify and expand recovers original token', () => {
  {
    // Initial token sample
    const token =
      'T1==cGFydG5lcl9pZD00NTY5MTc3MSZzaWc9M2Y3ZjNmNTdlZGY5ZTY3OGU1NmY4NjljNWIzNzczZjJjYzgxMmQ2ZDpzZXNzaW9uX2lkPTJfTVg0ME5UWTVNVGMzTVg1LU1UVXdOVFEzTnpFd01Ua3dPSDV6YVN0MFMxTnZjVVl6V1ZKT1F6SmpiR05rWTBsS1NWQi1mZyZjcmVhdGVfdGltZT0xNTA1NDc3MTAyJm5vbmNlPTAuMjkzMjk2ODE0NzIxMTYzMiZyb2xlPW1vZGVyYXRvciZleHBpcmVfdGltZT0xNTA1NTYzNTAy';
    const miniToken = minitok.minify(token);
    const backToToken = minitok.expand(miniToken);

    expect(backToToken).toEqual(token);
  }

  {
    // Token with sessionId starting with 1_
    const token =
      'T1==cGFydG5lcl9pZD00NTY5MTc3MSZzaWc9YWQ3MDYwYmM4ZTIwOWExYmQxYTc3NzNhZGM3YjU4YThiMjAyOTQ4MzpzZXNzaW9uX2lkPTFfTVg0ME5UWTVNVGMzTVg1LU1UVXdOVFl5TXprek9ETTBNSDVtYm5kaU5VNUdhWFJsUW5kdVFVWTNkSG81UzJkeU9ERi1mZyZjcmVhdGVfdGltZT0xNTA1NjIzOTM5Jm5vbmNlPTAuOTgzODM5OTE0MzA4MjczOSZyb2xlPW1vZGVyYXRvciZleHBpcmVfdGltZT0xNTA1NzEwMzM5';
    const miniToken = minitok.minify(token);
    const backToToken = minitok.expand(miniToken);

    expect(backToToken).toEqual(token);
  }
});
