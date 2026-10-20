// Regression: the admin gate and target card pass epoch numbers, not Dates.
// `formatDate` used to forward a bare number straight to `toLocaleDateString`,
// which threw and left the Admin route blank.
import test from 'node:test';
import assert from 'node:assert/strict';

import { formatDate, formatTime, timeAgo } from '../src/lib/utils.js';

const sample = new Date(2026, 9, 20, 15, 4, 5); // local time, timezone-safe

test('formatDate accepts a Date', () => {
  assert.equal(formatDate(sample), 'Oct 20, 2026');
});

test('formatDate accepts an ISO string', () => {
  assert.equal(formatDate(sample.toISOString()), 'Oct 20, 2026');
});

test('formatDate accepts epoch milliseconds', () => {
  // The admin probe and policy acknowledgement both store Date.now().
  assert.equal(formatDate(sample.getTime()), 'Oct 20, 2026');
});

test('formatDate accepts unix seconds', () => {
  assert.equal(formatDate(Math.floor(sample.getTime() / 1000)), 'Oct 20, 2026');
});

test('formatDate keeps the empty placeholder', () => {
  assert.equal(formatDate(null), '\u2014');
  assert.equal(formatDate(undefined), '\u2014');
});

test('formatTime accepts numbers and strings', () => {
  assert.equal(formatTime(sample.getTime()), '15:04:05');
  assert.equal(formatTime(sample.toISOString()), '15:04:05');
});

test('timeAgo accepts epoch milliseconds', () => {
  assert.equal(timeAgo(Date.now() - 90_000), '1m ago');
});
