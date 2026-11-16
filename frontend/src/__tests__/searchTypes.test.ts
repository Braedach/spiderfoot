import { describe, expect, it } from 'vitest';
import { detectSearchType, SEARCH_LABELS, type SearchKey } from '../lib/searchTypes';

const cases: [string, SearchKey | null][] = [
  // domains and hostnames
  ['example.com', 'domain'], ['sub.example.co.uk', 'domain'], ['  EXAMPLE.org  ', 'domain'],
  ['https://www.example.com/path?x=1', 'domain'], ['example.com:8443', 'domain'],
  // IP addresses
  ['203.0.113.10', 'ip'], ['203.0.113.0/24', 'ip'], ['2001:db8::1', 'ip'], ['::1', 'ip'], ['2001:db8::/32', 'ip'],
  // email
  ['name@example.com', 'email'], ['first.last+tag@sub.example.org', 'email'],
  // phone
  ['+61400000000', 'phone'], ['+1 (415) 555-2671', 'phone'], ['0400 000 000', 'phone'], ['0400000000', 'phone'],
  ['02 9374 4000', 'phone'], ['+44 20 7946 0958', 'phone'],
  // ASN
  ['AS64496', 'asn'], ['as13335', 'asn'], ['64496', 'asn'], ['15169', 'asn'], ['12', 'asn'],
  // names and usernames, with or without quote marks
  ['Pat Example', 'name'], ['"Pat Example"', 'name'], ["'Pat Marcus Example'", 'name'], ['“Pat Example”', 'name'],
  ['someuser', 'name'], ['Zoë Müller', 'name'],
  // nothing to classify
  ['', null], ['   ', null], ['""', null], ['!!!', null], ['--', null],
];

describe('detectSearchType', () => {
  it.each(cases)('%j is %s', (input, expected) => {
    expect(detectSearchType(input)).toBe(expected);
  });

  it('has a label for every search', () => {
    expect(Object.keys(SEARCH_LABELS).sort()).toEqual(['asn', 'domain', 'email', 'ip', 'name', 'phone']);
  });

  it('does not mistake an IPv4 address for a phone number or an ASN', () => {
    expect(detectSearchType('101.185.137.187')).toBe('ip');
  });

  it('does not mistake an email address for a domain', () => {
    expect(detectSearchType('name@example.com')).toBe('email');
  });
});

import { countryFromTarget } from '../lib/searchTypes';

describe('countryFromTarget', () => {
  it.each([
    ['+61400000000', 'Australia'], ['+61 8 9234 5678', 'Australia'], ['+64211234567', 'New Zealand'],
    ['+353 1 234 5678', 'Ireland'], ['+442079460958', 'United Kingdom'], ['+14155552671', 'United States / Canada'],
    ['pat@example.com.au', 'Australia'], ['pat@example.au', 'Australia'], ['pat@example.co.uk', 'United Kingdom'], ['pat@example.de', 'Germany'],
    ['pat@example.com', null], ['Pat Example', null], ['0400000000', null], ['', null], ['+999123', null],
  ])('%j gives %s', (input, expected) => {
    expect(countryFromTarget(input)).toBe(expected);
  });
});
